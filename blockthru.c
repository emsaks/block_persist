#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/part_stat.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/kprobes.h>

#include "regs.h"

#ifdef MAKE_VER
#define BT_VER MAKE_VER
#else
#define BT_VER ""
#endif

#define pw(fmt, ...) pr_warn("[%s] "fmt, bt->disk->disk_name, ## __VA_ARGS__)

#define D(code) pr_warn("Entering code @%i: "#code"\n", __LINE__); code ; pr_warn("Exiting code: "#code"\n");
/*
#define spin_lock(mut) pr_warn("Pre lock in %i\n", __LINE__); (spin_lock)(mut); pr_warn("Post lock in %i\n", __LINE__);
#define spin_unlock(mut) pr_warn("Pre unlock in %i\n", __LINE__); (spin_unlock)(mut); pr_warn("Post unlock in %i\n", __LINE__);
#define spin_trylock(mut) (pr_warn("Pre trylock in %i\n", __LINE__), spin_trylock(mut))
*/

static int bt_major;
static int bt_minors = 0;
static char * holder = "blockthru"BT_VER "held disk.";

struct bt_dev;

struct disk {
	struct bt_dev * bt;
	struct block_device * bd;
	struct kref inflight;
	unsigned long jiffies_when_added;
};

struct bio_stash {
	struct list_head entry;
	struct disk * disk;
	void * bi_private;
	bio_end_io_t * bi_end_io;
	int tries_remaining;
};

struct bt_dev {
	struct list_head entry;

	//struct mutex lock;
	spinlock_t lock;
	struct gendisk * disk;

	int suspend;
	struct completion resume;

	struct disk * backing;
	bool await_backing;

	int exiting;
	struct completion exit;
	/*  we can't delete ourself from within a our attribute code, 
		because the delete code hangs waiting for all attributes
		to return, so we need a worker for that */
	struct work_struct delete;

	int tries;
	struct list_head free;

	struct kretprobe add_probe, del_probe;

	char *	persist_pattern;
	int 	addtl_depth;
	unsigned long persist_timeout;
	unsigned long jiffies_when_removed;

	uint swapped_count;
	
	struct kref refcount;
};

// ll of devices
DEFINE_SPINLOCK(bt_lock);
static LIST_HEAD(bt_devs);

#define dev_to_bt(dev) ((struct bt_dev *)dev_to_disk(dev)->private_data)

void release_dev(struct kref *ref)
{
	struct bt_dev * bt = container_of(ref, struct bt_dev, refcount);
	D(complete(&bt->exit);)
}

struct disk * backing_get(struct bt_dev * bt)
{
	struct disk * disk = kzalloc(sizeof(struct disk), GFP_KERNEL);

	if (!disk)
		return NULL;
	
	if(!kref_get_unless_zero(&bt->refcount))
		return NULL;

	kref_init(&disk->inflight);
	disk->bt = bt;
	disk->jiffies_when_added = jiffies;
	
	return disk;
}

void backing_put(struct kref *ref)
{
    struct disk *disk = container_of(ref, struct disk, inflight);
	struct bt_dev * bt = disk->bt;
	unsigned long uptime = jiffies - disk->jiffies_when_added;

	blkdev_put(disk->bd, FMODE_READ);

	pw("Putting disk [%s]; Uptime: %lum%lus\n",
				disk->bd->bd_disk->disk_name,
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

    kfree(disk);
	kref_put(&bt->refcount, release_dev);
}

static struct bio_stash * stash_get(struct bt_dev * bt)
{
	struct bio_stash * stash = NULL;
	spin_lock(&bt->lock);
		if ((stash = list_first_entry_or_null(&bt->free, struct bio_stash, entry)))
			list_del(&stash->entry);
	spin_unlock(&bt->lock);

	if (!stash) {
		stash = kzalloc(sizeof(struct bio_stash), GFP_KERNEL);
		if (!stash) return NULL;
	}

	return stash;
}

static void stash_put(struct bt_dev * bt, struct bio_stash * stash)
{
	spin_lock(&bt->lock);
		stash->disk = NULL; // probably unnecessary
		list_add(&stash->entry, &bt->free);
	spin_unlock(&bt->lock);
}

int should_block(struct bt_dev * bt) 
{
	return bt->suspend || (bt->await_backing && (!bt->backing || test_bit(GD_DEAD, &bt->backing->bd->bd_disk->state)));
}

static void bt_bio_final(struct bt_dev * bt, struct bio * bio)
{
	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;

	if (stash->disk)
		kref_put(&stash->disk->inflight, backing_put);

	bio_set_dev(bio, bt->disk->part0);
	bio->bi_private = stash->bi_private;
	bio->bi_end_io = stash->bi_end_io;
	bio_endio(bio);

	stash_put(bt, stash);
}

// assume bio is already pointing to *our* endio and has stash in bi_private
static void bt_submit_internal(struct bt_dev * bt, struct bio * bio)
{
	int block;
	struct bio_stash * stash = (struct bio_stash *)bio->bi_private;

	--stash->tries_remaining;

retry:	
	spin_lock(&bt->lock);
	if ((block = should_block(bt))) {
		reinit_completion(&bt->resume);
		stash->disk = NULL;
	} else {
		// !note: REQUIRES that !bt->backing or swapping under lock, before calling any backing_put()
		if (bt->backing && !kref_get_unless_zero(&bt->backing->inflight))
			stash->disk = NULL;
		else stash->disk = bt->backing; // this must be set under lock so the bd won't be swapped, free'd underneath us
	}
	spin_unlock(&bt->lock);

	if (block) {
		wait_for_completion(&bt->resume); // todo: use interruptable/killable
		goto retry;
	} else if (stash->disk == NULL) {
		pw("Setting STS_OFFLINE because there's no backing\n");
		bio->bi_status = BLK_STS_OFFLINE;
		bt_bio_final(bt, bio);
	} else {
		bio_set_dev(bio, stash->disk->bd);
		submit_bio_noacct(bio);
	}
}

static void bt_io_end(struct bio * bio)
{
	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;

	if (bio->bi_status == BLK_STS_OFFLINE && stash->disk /* otherwise the disk was dead on submit: preserve the STS_OFFLINE */) {
		if (stash->tries_remaining > 0) {
			bio->bi_status = BLK_STS_OK;
			bt_submit_internal(stash->disk->bt, bio);
			return;
		} else {
			struct bt_dev * bt = stash->disk->bt; // so the pw() macro will work
			pw("Switching STS_OFFLINE to STS_IO error.\n");
			bio->bi_status = BLK_STS_IOERR;
		}
	}

	bt_bio_final(stash->disk->bt, bio);
}

/// @brief Suspend this block device
/// @param bt 
/// @param timeout jiffies to wait for backing device to finish; negative to block indefinitely
/// @return 
static int bt_suspend(struct bt_dev * bt, unsigned long timeout)
{
	static DECLARE_WAIT_QUEUE_HEAD(wq);
	struct disk * disk = NULL;
	unsigned long ret;

	if (bt->exiting) {
		return -EBUSY;
	} else {
		spin_lock(&bt->lock);
			bt->suspend = 1;
			if (timeout && bt->backing) {
				disk = bt->backing;
				kref_get(&disk->inflight);
			}
		spin_unlock(&bt->lock);

		if (!disk) 
			return 0;

		if (timeout > 0) {
			ret = wait_event_killable_timeout(wq, kref_read(&disk->inflight) <= 2, timeout);
			if (!ret) ret = -ETIMEDOUT;
		} else {
			ret = wait_event_killable(wq, kref_read(&disk->inflight) <= 2);
		}
		
		kref_put(&disk->inflight, backing_put);
		return ret;
	}
}

static void bt_resume(struct bt_dev * bt)
{
	spin_lock(&bt->lock);
		bt->suspend = 0;
		if (!should_block(bt)) complete_all(&bt->resume);
	spin_unlock(&bt->lock);
}

static void backing_release(struct disk * disk)
{
	unsigned long uptime;
	struct bt_dev * bt = disk->bt;

	uptime = jiffies - disk->jiffies_when_added;
	pw("Releasing disk [%s]; Uptime: %lum%lus\n",
		disk->bd->bd_disk->disk_name,
		uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

	kref_put(&disk->inflight, backing_put);
}

/**
 * @brief Drop current backing device. Close if not inflight.
 * 
 * @param bt 
 * @param disk Optional. Guarantee that the backing being released is a child of <disk>
 */
static void bt_backing_release(struct bt_dev *bt, struct gendisk * gendisk)
{
	struct disk * disk;

	if (!bt->backing)
		return;

	spin_lock(&bt->lock);
	if (!gendisk || bt->backing->bd->bd_disk == gendisk) {
		bt->jiffies_when_removed = jiffies;
		disk = bt->backing;
		bt->backing = NULL;
	}
	spin_unlock(&bt->lock);

	backing_release(disk); 
}

static int test_path(struct kobject * kobj, const char * pattern, int rewind);

// TAKE LOCK BEFORE!
static int bt_backing_swap(struct bt_dev * bt, struct block_device * bd)
{
	if (bt->backing) {
		if (bt->backing->bd == bd) {
			pw("Ignoring swap request. Already in use.\n");
			return 0;
		}

		backing_release(bt->backing);
	}

	bt->backing = backing_get(bt);
	if (!bt->backing)
		return -ENOMEM;

	bt->backing->bd = bd;

	pw("Swapping backing to %s\n", bd->bd_disk->disk_name);

	if (!set_capacity_and_notify(bt->disk, bdev_nr_sectors(bd)))
		kobject_uevent(&disk_to_dev(bt->disk)->kobj, KOBJ_CHANGE);
	if (!should_block(bt)) complete_all(&bt->resume);

	return 0;
}

static int bt_backing_swap_path(struct bt_dev *bt, const char * path, size_t count)
{
	int err = 0;
	struct block_device * bd;

	bd = blkdev_get_by_path(path, FMODE_READ, holder);
	if (IS_ERR(bd))
		return PTR_ERR(bd);
	if (!bd)
		return -ENODEV;

	spin_lock(&bt->lock);
		if (bt->persist_pattern) {
			if (!bd->bd_device.parent || test_path(&bd->bd_device.parent->kobj, bt->persist_pattern, bt->addtl_depth)) {
				pw("New disk [%s] is not on path: %s; clearing persist settings.\n", bd->bd_disk->disk_name, bt->persist_pattern);
				if (bt->add_probe.handler) {
					unregister_kretprobe(&bt->add_probe);
					bt->add_probe.handler = NULL;
				}
				kfree(bt->persist_pattern);
				bt->persist_pattern = NULL;
			}
		}
		err = bt_backing_swap(bt, bd);
	spin_unlock(&bt->lock);

	return err;
}

#pragma region persist

struct add_data {
	struct gendisk * disk;
	int old_flags;
};

static const char * normalize_path(const char * path) // allow paths retrieved from sysfs
{
	if (!strncmp(path, "/sys/", 5)) return path + 4;
	if (path[0] == '.' && path[1] == '/') path += 1;
	if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
	while (!strncmp(path, "/../", 4)) path += 3;

	return path;
}

static int test_path(struct kobject * kobj, const char * pattern, int rewind)
{
	const char * part, * pp, * kp;

	if (!kobj) return 1;
	while (rewind--) if (!(kobj = kobj->parent)) { return 1; }

	part = pattern + strlen(pattern); 
	do {
		part -= strlen(kobj->name) + 1;
		if (part < pattern || *part != '/')
			{ return 1; }

		for (kp = kobj->name, pp = part+1; *kp; ++kp, ++pp)
			if ((*kp != *pp) && (*pp != '?'))
				{ return 1; }
	} while ((kobj = kobj->parent));

	return part != pattern;
}

/*
int try_script(struct persist_c *pc) {
	int ret;
	char * envp[] = { "HOME=/", NULL };
	char * argv[] = { "/bin/bash", pc->opts.script_on_added, pc->name, pc->blkdev->bd_disk->disk_name, NULL };

	if (!pc->opts.script_on_added)
		return 0;

	pw("Calling user script %s\n", pc->opts.script_on_added);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (ret) 
		pw("Script failed with error code %i\n", ret);

	return ret;
}
*/

static int add_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (void*)regs->ARG2;
	struct add_data * d = (void*)ri->data;
	struct bt_dev * bt = container_of(get_kretprobe(ri), struct bt_dev, add_probe);
	struct kobject * parent;

	d->disk = NULL;

	if (!disk) {
		pw("add_disk: Disk argument is NULL!\n");
		return 0;
	}

	// we must use parent because the block/sd* parts may not yet have been set
    parent = &(((struct device *)(regs->ARG1))->kobj);

	if (!parent) {
		pw("add_disk: Disk [%s] has no parent device! Skipping\n", disk->disk_name);
		return 0;
	}

	d->old_flags = disk->flags;

	// we must use a retry, so we don't wait on the lock while something tries to rip the probe
retry:
	if(spin_trylock(&bt->lock)) {
		if (!bt->persist_pattern) // may be in process of wiping pattern
			return 0;

		if (test_path(parent, bt->persist_pattern, bt->addtl_depth)) {
			pw("bt->addtl_depth = %i\n", bt->addtl_depth);
			pw("Added disk [%s] is not on path: %s. Ignoring.\n", disk->disk_name, bt->persist_pattern);
		} else if (get_capacity(disk) != get_capacity(bt->disk)) {
			pw("New disk [%s] capacity doesn't match! Ignoring.\n", disk->disk_name);
		} else {
			pw("Matched new disk [%s]\n", disk->disk_name);
			disk->flags |= (bt->disk->flags & GD_SUPPRESS_PART_SCAN);
			d->disk = disk;

			if ((d->old_flags ^ disk->flags) & GD_SUPPRESS_PART_SCAN)
				pw("Suppressed partscan on disk %s\n", disk->disk_name);
		}
		spin_unlock(&bt->lock);
	} else {
		if (bt->persist_pattern)
			goto retry;
	 	pw("Ignoring new disk after persistence pattern has been cleared.\n");
	}

	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct bt_dev * bt = container_of(get_kretprobe(ri), struct bt_dev, add_probe);
	struct add_data * d = (void*)ri->data;
	struct block_device * bd;

	D(if (!d->disk) return 0;)

	// todo: restore flags?

	if (regs_return_value(regs))
		return 0;

	if (bt->backing) {
		pw("New disk found before old one was deleted; Ignoring.\n");
		return 0;
	}

	if (bt->persist_timeout && (bt->jiffies_when_removed + bt->persist_timeout < jiffies)) {
		pw("Not loading new disk after timeout.\n");
		return 0;
	}

	// try_script(pc);

	// we must use a retry, so we don't wait on the lock while something tries to rip the probe
retry:
	pw("Pre trylock\n");
	if(spin_trylock(&bt->lock)) {
		pw("In trylock\n");
		// pattern may have been switched beneath us
		if (!d->disk->part0->bd_device.parent || test_path(&d->disk->part0->bd_device.parent->kobj, bt->persist_pattern, bt->addtl_depth)) {
			pw("Added disk [%s] is not on new path: %s. Ignoring.\n", d->disk->disk_name, bt->persist_pattern);
		} else {
			bd = blkdev_get_by_dev(d->disk->part0->bd_dev, FMODE_READ, holder);
			if (IS_ERR(bd)) {
				pw("Failed to open disk [%s] with error: %li\n", d->disk->disk_name, PTR_ERR(bd));
			} else
				bt_backing_swap(bt, bd);
		}
		spin_unlock(&bt->lock);
	} else {
		if (bt->persist_pattern)
			goto retry;
		pw("Not swapping disk after persistence pattern has been cleared.\n");
	}
	
	return 0;
}

static int del_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (struct gendisk *)regs->ARG1;
	struct bt_dev * bt = container_of(get_kretprobe(ri), struct bt_dev, del_probe);

	if (IS_ERR_OR_NULL(disk))
		return 0;

	bt_backing_release(bt, disk);

	return 0;
}

static int del_ret(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static int plant_probe(struct kretprobe * probe, kretprobe_handler_t entry, kretprobe_handler_t ret, char * symbol_name, size_t data_size)
{
	int e;

	if (probe->handler) {
		D(return -EBUSY;)
	}

	memset(probe, 0, sizeof(*probe));
	probe->handler        = ret,
	probe->entry_handler  = entry,
	probe->maxactive      = 20,
	probe->data_size	  = data_size;
	probe->kp.symbol_name = symbol_name;

	D(e = register_kretprobe(probe);)
	if (e < 0) {
		pr_warn("register_kretprobe for %s failed, returned %d\n", symbol_name, e);
		probe->handler = NULL; // this will flag that the probe has not been set
		return e;
	}

	return 0;
}

static void rip_probes(struct kretprobe * add_probe, struct kretprobe * del_probe)
{
	if (add_probe->handler) unregister_kretprobe(add_probe);
	if (del_probe->handler) unregister_kretprobe(del_probe);
}

static int set_pattern(struct bt_dev * bt, const char * pattern, size_t count)
{
	int ret = 0;
	char * devpath, *kp, *kt;
	const char *pp;

	if (count < 5) // normalize_path() minimum
		return -EINVAL;

	spin_lock(&bt->lock);
	if (bt->backing) {
		D(devpath = kobject_get_path(&(disk_to_dev(bt->backing->bd->bd_disk)->parent->kobj), GFP_KERNEL);)
		pattern = normalize_path(pattern);

		for (kp = devpath, pp = pattern; *kp; ++kp, ++pp) {
			if (*kp != *pp) {
				if (*pp != '?' || *kp == '/') break;
				*kp = '?'; // '?' is a wildcard
			}
		}

		if (*pp || (*kp && *kp != '/')) { // this will exclude trailing '/' in pattern
			pw("Device is not on path: [%.*s]%s != %s\n", (int)(kp - devpath), devpath, kp, pp);
			D(ret = -EINVAL;)
			kfree(devpath);
		} else {
			kt = kp;
			while (*kp) if (*kp++ == '/') bt->addtl_depth++;
			*kt = '\0';

			D(if (bt->persist_pattern) kfree(bt->persist_pattern);)
			if (!bt->add_probe.handler) {
				D(ret = plant_probe(&bt->add_probe, add_entry, add_ret, "device_add_disk", sizeof(struct add_data));)
			}
			if (ret) {
				D(kfree(devpath);)
				bt->persist_pattern = NULL;
			} else {
				D(bt->persist_pattern = devpath;)
			}
		}
	} else {
		pw("Can't update persistence pattern when no backing device is set\n");
		D(ret = -ENODEV;)
	}
	spin_unlock(&bt->lock);

	D(return ret;)
}

#pragma endregion persist

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%i\n",dev_to_bt(dev)->suspend);
}

static ssize_t suspend_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	long v;

	err = kstrtol(buf, 10, &v);
	if (err || v > INT_MAX)
		return -EINVAL;

	if (v != 0) {
		err = bt_suspend(dev_to_bt(dev), v);
	} else {
		bt_resume(dev_to_bt(dev));
	}
	
	return err < 0 ? err : count;
}
static DEVICE_ATTR_RW(suspend);

static ssize_t backing_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct bt_dev * bt = dev_to_bt(dev);
	struct block_device *bd = bt->backing->bd;
	if (bd) {
		strcpy(buf, bd->bd_disk->disk_name);
		return strlen(buf);
	} else
		return 0;
}

static ssize_t backing_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;

	if (count <= 0 || buf[0] == '\0') {
		bt_backing_release(dev_to_bt(dev), NULL);
		return count;
	}

	err = bt_backing_swap_path(dev_to_bt(dev), buf, count);
	return err < 0 ? err : count;
}
static DEVICE_ATTR_RW(backing);

static ssize_t persist_timeout_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%li", dev_to_bt(dev)->persist_timeout);
}

static ssize_t persist_timeout_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned long v;

	err = kstrtoul(buf, 10, &v);
	if (err || v > UINT_MAX)
		return -EINVAL;

	dev_to_bt(dev)->persist_timeout = v;

	return count;
}
static DEVICE_ATTR_RW(persist_timeout);

static ssize_t persist_pattern_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", dev_to_bt(dev)->persist_pattern);
}

static ssize_t persist_pattern_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	ssize_t ret;

	if (count <= 0) {
		spin_lock(&bt->lock);
			if (bt->persist_pattern) {
				kfree(bt->persist_pattern);
				bt->persist_pattern = NULL;
				if (bt->add_probe.handler) {
					unregister_kretprobe(&bt->add_probe);
					bt->add_probe.handler = NULL;
				}
			}
		spin_unlock(&bt->lock);
		return count;
	} else {
		ret = set_pattern(bt, buf, count);
		return ret < 0 ? ret : count;
	}
}
static DEVICE_ATTR_RW(persist_pattern);

static ssize_t tries_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%i", dev_to_bt(dev)->tries);
}

static ssize_t tries_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned long v;

	err = kstrtoul(buf, 10, &v);
	if (err || v > UINT_MAX)
		return -EINVAL;

	dev_to_bt(dev)->tries = v;

	return count;
}
static DEVICE_ATTR_RW(tries);

static ssize_t await_backing_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%i", dev_to_bt(dev)->tries);
}

static ssize_t await_backing_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	if (count > 0) {
		if (buf[0] == '1') bt->await_backing = 1;
		else if (buf[0] == '0') {
			spin_lock(&bt->lock);
				bt->await_backing = 0;
				if (!should_block(bt)) complete_all(&bt->resume);
			spin_unlock(&bt->lock);
		} else return -EINVAL;
	}

	return count;
}
static DEVICE_ATTR_RW(await_backing);

void bt_remove_worker(struct work_struct *work);
static ssize_t delete_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	int already_exiting = 0;

	spin_lock(&bt->lock);
	if (bt->exiting)
		already_exiting = 1;
	else if (!bt->suspend)
		bt->exiting = 1;
	spin_unlock(&bt->lock);
	if (!bt->exiting || already_exiting)
		return -EBUSY;

	INIT_WORK(&bt->delete, bt_remove_worker);
	schedule_work(&bt->delete);
	return count;
}
static DEVICE_ATTR_WO(delete);

static ssize_t partscan_show(struct device *dev, struct device_attribute *attr, char *buf)
{

	return sysfs_emit(buf, "%i", !(dev_to_bt(dev)->disk->flags & GD_SUPPRESS_PART_SCAN));
}

static ssize_t partscan_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	if (count > 0) {
		if (buf[0] == '1') {
			spin_lock(&bt->lock);
				bt->disk->flags &= ~GD_SUPPRESS_PART_SCAN;
			spin_unlock(&bt->lock);
		} else if (buf[0] == '0') {
			spin_lock(&bt->lock);
				bt->disk->flags |= GD_SUPPRESS_PART_SCAN;
			spin_unlock(&bt->lock);
		} else return -EINVAL;
	}

	return count;
}
static DEVICE_ATTR_RW(partscan);

static struct attribute *bt_attrs[] = {
	&dev_attr_delete.attr,
	&dev_attr_backing.attr,
	&dev_attr_suspend.attr,
	&dev_attr_persist_timeout.attr,
	&dev_attr_persist_pattern.attr,
	&dev_attr_tries.attr,
	&dev_attr_await_backing.attr,
	&dev_attr_partscan.attr,
	NULL,
};

static struct attribute_group bt_attribute_group = {
	.name	= "blockthru",
	.attrs	= bt_attrs,
};


static void bt_submit_bio(struct bio *bio)
{
	struct bt_dev * bt = bio->bi_bdev->bd_disk->private_data;
	struct bio_stash * stash = stash_get(bt);

	if (!stash) { // we are currently exiting or malloc fail
		bio->bi_status = BLK_STS_RESOURCE;
		bio_endio(bio);
		return;
	}

	stash->bi_private = bio->bi_private;
	stash->bi_end_io = bio->bi_end_io;
	stash->tries_remaining = bt->tries;
	bio->bi_private = stash;
	bio->bi_end_io = bt_io_end;

	bt_submit_internal(bt, bio);
}

static const struct block_device_operations bt_fops = {
	.owner		=	THIS_MODULE,
	.submit_bio	=	bt_submit_bio,
};

static int bt_alloc(const char * name)
{
	struct bt_dev *bt;
	struct gendisk *disk;
	char buf[DISK_NAME_LEN];
	int err = -ENOMEM;

	bt = kzalloc(sizeof(*bt), GFP_KERNEL);
	if (!bt)
		return -ENOMEM;
	
	spin_lock_init(&bt->lock);
	kref_init(&bt->refcount);
	init_completion(&bt->resume);
	init_completion(&bt->exit);

	INIT_LIST_HEAD(&bt->free);

	bt->tries = 1;
	bt->await_backing = 1;

	// todo: check name available
	snprintf(buf, DISK_NAME_LEN, name);
	
	disk = bt->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk)
		goto out_free_dev;

	set_bit(GD_SUPPRESS_PART_SCAN, &disk->state);

	disk->major			= bt_major;
	disk->first_minor	= bt_minors++; // todo: use a lock!
	disk->minors		= 1;
	disk->fops			= &bt_fops;
	disk->private_data	= bt;

	// todo: sector size; do we need it?

	strlcpy(disk->disk_name, buf, DISK_NAME_LEN);
	set_disk_ro(disk, true);
	set_capacity(disk, 0);

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, disk->queue);

	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	disk->bdi->ra_pages = 0; // must be after add_disk

	err = sysfs_create_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	if (err) {
		pw("sysfs init failed with code %i", err);
		goto out_del_disk;
	}

	plant_probe(&bt->del_probe, del_entry, del_ret, "del_gendisk", 0);

	if(!try_module_get(THIS_MODULE))
		goto out_rip_probe;

	spin_lock(&bt_lock);
		list_add(&bt->entry, &bt_devs);
	spin_unlock(&bt_lock);

	return 0;

out_rip_probe:
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	unregister_kretprobe(&bt->del_probe);
out_del_disk:
	del_gendisk(disk);
out_cleanup_disk:
	put_disk(disk); // todo: cleanup disk?
out_free_dev:
	list_del(&bt->entry); // todo: lock!
	kfree (bt);
	return err;
}

static void bt_del(struct bt_dev *bt)
{
	struct bio_stash * stash, * n;
	
	// these block until all runing code completes, so they're safe
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	rip_probes(&bt->add_probe, &bt->del_probe);

	bt_backing_release(bt, NULL);
	// todo: if we have inflight, should we just hang until await_backing is changed (BEFORE sysfs_remove)
	// or alternatively, for resume on suspend also...?
	bt->await_backing = 0;
	complete_all(&bt->resume);
	
	kref_put(&bt->refcount, release_dev);
	wait_for_completion(&bt->exit);
	
	del_gendisk(bt->disk);
	blk_cleanup_disk(bt->disk); // newer kernels just use put_disk

	list_for_each_entry_safe(stash, n, &bt->free, entry)
		kfree(stash);

	if (bt->persist_pattern) kfree(bt->persist_pattern);
}

static void bt_put(struct bt_dev * bt)
{
	kfree (bt);
	module_put(THIS_MODULE);
}

static void bt_remove(struct bt_dev *bt)
{
	bt_del(bt);

	spin_lock(&bt_lock);
		list_del(&bt->entry);
	spin_unlock(&bt_lock);

	bt_put(bt);
}

void bt_remove_worker(struct work_struct *work)
{
	struct bt_dev * bt = container_of(work, struct bt_dev, delete);
	bt_remove(bt);
}

static int create_set(const char *val, const struct kernel_param *kp)
{
	return bt_alloc(val);
}

struct kernel_param_ops create_ops = { 
	.set = create_set,
};
module_param_cb(create, &create_ops, NULL, 0664);
MODULE_PARM_DESC(create, "Create new named passthru device");

static void bt_cleanup(void)
{
	
} 

static int __init bt_init(void)
{
	bt_major = register_blkdev(0, "bt"BT_VER);
	if (bt_major < 0) {
		pr_info("blockthru"BT_VER": module NOT loaded !\n");
		return -EIO;
	}

	pr_info("blockthru"BT_VER": module loaded\n");
	return 0;
}

static void __exit bt_exit(void)
{
	bt_cleanup();
	unregister_blkdev(bt_major, "bt"BT_VER);
	
	pr_info("blockthru"BT_VER": module unloaded\n");
}

module_init(bt_init);
module_exit(bt_exit);
MODULE_LICENSE("GPL");
