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

#define BT_VER "6"

#define pw(fmt, ...) pr_warn("[%s] "fmt, bt->disk->disk_name, ## __VA_ARGS__)

static int bt_major;
static int bt_minors = 0;
static char * holder = "blockthru"BT_VER "held disk.";

struct bt_dev;

struct bio_stash {
	struct list_head entry;
	struct bt_dev * bt;
	struct block_device * backing;
	void * bi_private;
	bio_end_io_t * bi_end_io;
	int tries_remaining;
};

struct bt_dev {
	struct list_head entry;

	struct mutex lock;
	struct gendisk * disk;

	int suspend;
	struct completion resume;

	struct block_device * backing;
	char backing_path[PATH_MAX];
	bool block_if_no_backing;

	int exiting;
	struct completion exit;
	/*  we can't delete ourself from within a our attribute code, 
		because the delete code hangs waiting for all attributes
		to return, so we need a worker for that */
	struct work_struct delete;

	int tries;
	struct list_head free;
	struct list_head inflight;

	struct kretprobe add_probe, del_probe;

	char *	path_pattern;
	int 	addtl_depth;

	uint swapped_count;
	unsigned long jiffies_when_removed, jiffies_when_added;
};

// ll of devices
DEFINE_MUTEX(bt_lock);
static LIST_HEAD(bt_devs);

#define dev_to_bt(dev) ((struct bt_dev *)dev_to_disk(dev)->private_data)

static struct bio_stash * bt_get_stash(struct bt_dev * bt)
{
	struct bio_stash * stash = NULL;
	mutex_lock(&bt->lock);
		stash = list_first_entry_or_null(&bt->free, struct bio_stash, entry);
		if (stash) {
			list_move(&stash->entry, &bt->inflight);
		} else {
			stash = kzalloc(sizeof(struct bio_stash), GFP_KERNEL);
			if (!stash) return NULL;
			stash->bt = bt;
			list_add(&stash->entry, &bt->inflight);
		}
	mutex_unlock(&bt->lock);

	return stash;
}

/* return device if it should be released; USE LOCK! 
	ENSURE CALLER cleared its stash->backing, 
	otherwise it's stash will prevent free'ing */
static struct block_device * bt_put_dev(struct bt_dev * bt, struct block_device *bd)
{
	struct bio_stash * s;

	list_for_each_entry(s, &bt->inflight, entry) {
		if (s->backing == bd)
			return NULL;
	}

	return bd;	
}

static void bt_put_stash(struct bio_stash * stash)
{
	struct bt_dev * bt = stash->bt;
	struct block_device *putdev = NULL;
	int exit = 0;

	mutex_lock(&bt->lock);
	list_move(&stash->entry, &bt->free); // we can safely call bt_put_dev now
	if (bt->backing != stash->backing)
		putdev = bt_put_dev(bt, stash->backing);
	stash->backing = NULL;
	exit = bt->exiting && list_empty(&bt->inflight);
	mutex_unlock(&bt->lock);
	
	if (putdev) blkdev_put(putdev, FMODE_READ);
	if (exit) complete(&bt->exit);
}

// assume bio is already pointing to *our* endio and has stash in bi_private
static void bt_submit_internal(struct bio * bio)
{
	int suspend;
	struct bio_stash * stash = (struct bio_stash *)bio->bi_private;
	struct bt_dev * bt = stash->bt;

	--stash->tries_remaining;

retry:	
	mutex_lock(&bt->lock);
	suspend = bt->suspend || (bt->block_if_no_backing && (!bt->backing || test_bit(GD_DEAD, &bt->backing->bd_disk->state)));
	if (!suspend && bt->backing != NULL)
		stash->backing = bt->backing; // this must be set under lock so the bd won't be swapped, free'd underneath us
	else stash->backing = NULL;
	mutex_unlock(&bt->lock);

	if (suspend) {
		wait_for_completion(&bt->resume); // todo: use interruptable/killable
		goto retry;
	} else if (stash->backing == NULL) {
		pr_warn("Setting STS_OFFLINE because there's no backing\n");
		bio_set_dev(bio, bt->disk->part0); // in case we are a retry that backed a different dev; perhaps unneccessary.
		bio->bi_status = BLK_STS_OFFLINE;
		stash->tries_remaining = 0;
		bio_endio(bio);
	} else {
		bio_set_dev(bio, stash->backing);
		submit_bio_noacct(bio);
	}
}

static void bt_io_end(struct bio * bio)
{
	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;
	struct block_device * putdev = NULL;
 
	if (bio->bi_status == BLK_STS_OFFLINE && stash->backing /* otherwise the disk was dead on submit: preserve the STS_OFFLINE */) {
		if (stash->tries_remaining > 0) {
			bio->bi_status = BLK_STS_OK;
			putdev = stash->backing;
			// put the device ourself (because we are not calling put_stash)
			mutex_lock(&stash->bt->lock);
			stash->backing = NULL; // so bt_put_dev will work properly
			if (stash->bt->backing != putdev)
				putdev = bt_put_dev(stash->bt, putdev);
			mutex_unlock(&stash->bt->lock);
			if (putdev) blkdev_put(putdev, FMODE_READ);

			bt_submit_internal(bio);
			return;
		} else {
			pr_warn("Switching STS_OFFLINE to STS_IO error.\n");
			bio_io_error(bio);
		}
	}

	bio->bi_private = stash->bi_private;
	bio->bi_end_io = stash->bi_end_io;
	bt_put_stash(stash);
	bio_endio(bio);
}

static int bt_suspend(struct bt_dev * bt)
{
	int err = 0;
	mutex_lock(&bt->lock);
		if (bt->exiting)
			err = -EBUSY;
		else {
			reinit_completion(&bt->resume);
			bt->suspend = 1;
		}
	mutex_unlock(&bt->lock);
	return err;
}

static int bt_resume(struct bt_dev * bt)
{
	mutex_lock(&bt->lock);
		bt->suspend = 0;
		complete_all(&bt->resume);
	mutex_unlock(&bt->lock);
	
	return 0;
}

/**
 * @brief Drop current backing device. Close if not inflight.
 * 
 * @param bt 
 * @param bd Optional. Guarantee that the backing being released == bd 
 */
static void bt_backing_release(struct bt_dev *bt, struct gendisk * disk)
{
	struct block_device * putdev;
	unsigned long uptime = jiffies - bt->jiffies_when_added;

	if (!bt->backing)
		return;

	mutex_lock(&bt->lock);
	if (!disk || bt->backing->bd_disk == disk) {
		pw("Releasing disk [%s]; Uptime: %lum%lus\n",
				bt->backing_path,
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);
		bt->jiffies_when_removed = jiffies;
		putdev = bt_put_dev(bt, bt->backing);
		bt->backing = NULL;
		reinit_completion(&bt->resume); // so block_on_no_backing will have what to wait on
	}
	mutex_unlock(&bt->lock); 
	if (putdev) blkdev_put(putdev, FMODE_READ);
}

static int bt_backing_swap(struct bt_dev *bt, const char * path, size_t count)
{
	struct block_device * bd, *putdev;
	int resume = 0;
	unsigned long uptime;

	bd = blkdev_get_by_path(path, FMODE_READ, holder);
	if (IS_ERR(bd))
		return PTR_ERR(bd);
	if (!bd)
		return -ENODEV;

	if (bt->backing) {
		uptime = jiffies - bt->jiffies_when_added;
		pw("Releasing disk [%s]; Uptime: %lum%lus\n",
			bt->backing_path,
			uptime / (HZ*60), (uptime % (HZ*60)) / HZ);
	}

	pr_warn("Swapping backing to %s\n", path);

	mutex_lock(&bt->lock);
		bt->jiffies_when_added = jiffies;
		putdev = bt_put_dev(bt, bt->backing);
		bt->backing = bd;
		strncpy((char*)bt->backing_path, path, count);
		resume = !bt->suspend; // in case we previously had a dead backing and block_on_no_backing was set
		if (!set_capacity_and_notify(bt->disk, bdev_nr_sectors(bd)))
			kobject_uevent(&disk_to_dev(bt->disk)->kobj, KOBJ_CHANGE);
	mutex_unlock(&bt->lock);

	if (resume) complete_all(&bt->resume);
	if (putdev) blkdev_put(putdev, FMODE_READ);

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

	memset(probe, 0, sizeof(*probe));
	probe->handler        = ret,
    probe->entry_handler  = entry,
    probe->maxactive      = 20,
	probe->data_size	  = data_size;
	probe->kp.symbol_name = symbol_name;

	e = register_kretprobe(probe);
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

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",dev_to_bt(dev)->suspend ? "1" : "0");
}

static ssize_t suspend_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	if (count <= 0)
		return count;
	if (buf[0] == '1') {
		err = bt_suspend(dev_to_bt(dev));
	} else if (buf[0] == '0') {
		err = bt_resume(dev_to_bt(dev));
	}
	return err < 0 ? err : count;
}
static DEVICE_ATTR_RW(suspend);

static ssize_t backing_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	strncpy(buf, dev_to_bt(dev)->backing_path, sizeof(dev_to_bt(dev)->backing_path));
	return strlen(buf);
}

static ssize_t backing_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;

	if (count > 0 && buf[0] == '\0') {
		bt_backing_release(dev_to_bt(dev), NULL);
		return count;
	}

    err = bt_backing_swap(dev_to_bt(dev), buf, count);
	return err < 0 ? err : count;
}
static DEVICE_ATTR_RW(backing);

static ssize_t port_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t port_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return count;
}
static DEVICE_ATTR_RW(port);

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

static ssize_t block_if_no_backing_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%i", dev_to_bt(dev)->tries);
}

static ssize_t block_if_no_backing_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	if (count > 0) {
		if (buf[0] == '1') bt->block_if_no_backing = 1;
		else if (buf[0] == '0') bt->block_if_no_backing = 0;
		else return -EINVAL;
	}

    return count;
}
static DEVICE_ATTR_RW(block_if_no_backing);

void bt_remove_worker(struct work_struct *work);
static ssize_t delete_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	INIT_WORK(&bt->delete, bt_remove_worker);
	schedule_work(&bt->delete);
    return count;
}
static DEVICE_ATTR_WO(delete);

static struct attribute *bt_attrs[] = {
	&dev_attr_delete.attr,
	&dev_attr_backing.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
	&dev_attr_tries.attr,
	&dev_attr_block_if_no_backing.attr,
	NULL,
};

static struct attribute_group bt_attribute_group = {
	.name = "blockthru",
	.attrs= bt_attrs,
};


static void bt_submit_bio(struct bio *bio)
{
	struct bt_dev * bt= bio->bi_bdev->bd_disk->private_data;
	struct bio_stash * stash = bt_get_stash(bt);

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

	bt_submit_internal(bio);
}

static const struct block_device_operations bt_fops = {
	.owner      =	THIS_MODULE,
	.submit_bio =	bt_submit_bio,
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
	
	mutex_init(&bt->lock);
	init_completion(&bt->resume);
	init_completion(&bt->exit);

	INIT_LIST_HEAD(&bt->inflight);
	INIT_LIST_HEAD(&bt->free);

	bt->tries = 1;

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

	err = plant_probe(&bt->del_probe, del_entry, del_ret, "del_gendisk", 0);
	if (err) {
		
	}
	}
	err = plant_probes(&bt->add_probe, &bt->del_probe);
	if (err)
		
	

	if(!try_module_get(THIS_MODULE))
		goto out_del_disk;

	mutex_lock(&bt_lock);
		list_add(&bt->entry, &bt_devs);
	mutex_unlock(&bt_lock);

	return 0;

out_del_disk:
	del_gendisk(disk);
out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	list_del(&bt->entry); // lock!
	kfree (bt);
	return err;
}

#define d(code) pr_warn("Entering code: "#code"\n"); code ; pr_warn("Exiting code: "#code"\n");
static int bt_del(struct bt_dev *bt)
{
	struct bio_stash * stash, * n;
	int has_inflight = 0;
	int already_exiting = 0;
	mutex_lock(&bt->lock);
	if (bt->exiting)
		already_exiting = 1;
	else if (!bt->suspend)
		bt->exiting = 1;
	mutex_unlock(&bt->lock);
	if (!bt->exiting || already_exiting)
		return -EBUSY;
	
	rip_probes(&bt->add_probe, &bt->del_probe);
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	del_gendisk(bt->disk);
	put_disk(bt->disk);
	
	mutex_lock(&bt->lock);
		has_inflight = !list_empty(&bt->inflight);
	mutex_unlock(&bt->lock);
	if (has_inflight)
		wait_for_completion(&bt->exit);
	
	if (bt->backing) blkdev_put(bt->backing, FMODE_READ);

	blk_cleanup_disk(bt->disk);

	list_for_each_entry_safe(stash, n, &bt->free, entry)
		kfree(stash);
	
	return 0;
}

static void bt_put(struct bt_dev * bt)
{
	kfree (bt);
	module_put(THIS_MODULE);
}

static int bt_remove(struct bt_dev *bt)
{
	int err = bt_del(bt);
	if (err) 
		return err;

	mutex_lock(&bt_lock);
		list_del(&bt->entry);
	mutex_unlock(&bt_lock);

	bt_put(bt);
	return 0;
}

void bt_remove_worker(struct work_struct *work)
{
	struct bt_dev * bt = container_of(work, struct bt_dev, delete);
	int err = bt_remove(bt);
	if (err) 
		pr_warn("Failed to delete blockthru disk: %s with error code %i\n", bt->disk->disk_name, err);
}

static int delete_set(const char *val, const struct kernel_param *kp)
{
	struct bt_dev * bt, * n;
	mutex_lock(&bt_lock);
	list_for_each_entry_safe(bt, n, &bt_devs, entry) {
		if (!strncmp(val, bt->disk->disk_name, sizeof(bt->disk->disk_name)))
			break;
	}
	mutex_unlock(&bt_lock);

	if list_entry_is_head(bt, &bt_devs, entry)
		return -ENODEV;

	return bt_remove(bt);
}

struct kernel_param_ops delete_ops = { 
    .set = delete_set,
};
module_param_cb(delete, &delete_ops, NULL, 0664);
MODULE_PARM_DESC(delete, "Delete named passthru device");

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
