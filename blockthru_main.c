#include <linux/module.h>
#include <linux/moduleparam.h>

#include "blockthru.h"
#include "compat.h"
#include "regs.h"

static int bt_major;
static atomic_t bt_minors = ATOMIC_INIT(0);
char * holder = "blockthru"BT_VER "held disk.";

// ll of devices
DEFINE_SPINLOCK(btlock);
static LIST_HEAD(bt_devs);

void release_dev(struct kref *ref)
{
	struct bt_dev * bt = container_of(ref, struct bt_dev, refcount);
	complete(&bt->exit);
}

struct backing * backing_get(struct bt_dev * bt)
{
	struct backing * disk = kzalloc(sizeof(struct backing), GFP_KERNEL);

	if (!disk)
		return NULL;
	
	if(!kref_get_unless_zero(&bt->refcount))
		return NULL;

	kref_init(&disk->inflight);
	disk->bt = bt;
	disk->jiffies_when_added = jiffies;
	
	return disk;
}

void backing_put_worker(struct work_struct * work)
{
	struct backing * backing = container_of(work, struct backing, put);
	struct bt_dev * bt = backing->bt;
	unsigned long uptime = jiffies - backing->jiffies_when_added;

	pw("Putting disk [%s]; Uptime: %lum%lus\n",
				backing->bd->bd_disk->disk_name,
				uptime / (HZ*60), (uptime % (HZ*60)) / HZ);

	bdev_release(backing->bdev_handle);

	kfree(backing);
	kref_put(&bt->refcount, release_dev);
}

void backing_put(struct kref *ref)
{
	struct backing *backing = container_of(ref, struct backing, inflight);
	// avoids "Voluntary context switch within RCU read-side critical section!" via blkdev_put->schedule()
	INIT_WORK(&backing->put, backing_put_worker);
	schedule_work(&backing->put);
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
	if (!spin_trylock(&bt->lock)) {
		stash->disk = NULL;
		pw("Missed spinlock in bt_submit_internal\n");
		bio->bi_status = BLK_STS_RESOURCE;
		bt_bio_final(bt, bio);
		return;
	}
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
	} else if (bio->bi_status == BLK_STS_IOERR && op_is_write(bio->bi_opf)) {
		salvage_bio(bio);
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
	struct backing * disk = NULL;
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

static void backing_release(struct backing * disk)
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
	struct backing * backing = NULL;

	if (!bt->backing)
		return;

	spin_lock(&bt->lock);
	if (!gendisk || bt->backing->bd->bd_disk == gendisk) {
		bt->jiffies_when_removed = jiffies;
		backing = bt->backing;
		bt->backing = NULL;
	}
	spin_unlock(&bt->lock);

	if (backing)
		backing_release(backing); 
}

// TAKE LOCK BEFORE!
int bt_backing_swap(struct bt_dev * bt, struct bdev_handle *handle)
{
	struct block_device *bd = handle->bdev;

	if (bt->backing) {
		if (bt->backing->bd == handle->bdev) {
			pw("Ignoring swap request. Already in use.\n");
			return 0;
		}

		backing_release(bt->backing);
	}

	bt->backing = backing_get(bt);
	if (!bt->backing)
		return -ENOMEM;

	bt->backing->bdev_handle = handle;
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
	struct bdev_handle *bdev_handle;

	bdev_handle = bdev_open_by_path(path, BLK_OPEN_READ, holder, NULL);
	if (IS_ERR_OR_NULL(bdev_handle))
		return PTR_ERR(bdev_handle);

	bd = bdev_handle->bdev;
	if (IS_ERR(bd))
		return PTR_ERR(bd);
	if (!bd)
		return -ENODEV;

	spin_lock(&bt->lock);
		persist_new_dev(bt, bd);
		err = bt_backing_swap(bt, bdev_handle);
	spin_unlock(&bt->lock);

	return err;
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

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%i\n",dev_to_bt(dev)->suspend);
}

// follows bt_suspend semantics; on 0, resume
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
	struct block_device *bd;
	spin_lock(&bt->lock);
	if (bt->backing && bt->backing->bd) {
		bd = bt->backing->bd;
		strcpy(buf, bd->bd_disk->disk_name);
	}
	spin_unlock(&bt->lock);

	return (bd) ? strlen(buf) : 0;
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

extern struct device_attribute dev_attr_persist_timeout;
extern struct device_attribute dev_attr_persist_pattern;

static struct attribute *bt_attrs[] = {
	&dev_attr_delete.attr,
	&dev_attr_backing.attr,
	&dev_attr_suspend.attr,
	&dev_attr_persist_timeout.attr,
	&dev_attr_persist_pattern.attr,
	&dev_attr_tries.attr,
	&dev_attr_await_backing.attr,
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

	prep_bio(bio);
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
	ssize_t namelen;

	namelen = strscpy(buf, name, DISK_NAME_LEN);
	if (namelen == -E2BIG || !namelen)
		return -ENOTNAM;
	
	if (buf[namelen-1] == '\n') {
		if (namelen == 1)
			return -ENOTNAM;
		buf[namelen-1] = '\0';
	}

	bt = kzalloc(sizeof(*bt), GFP_KERNEL);
	if (!bt)
		return -ENOMEM;

	// todo: check name available
	
	spin_lock_init(&bt->lock);
	kref_init(&bt->refcount);
	init_completion(&bt->resume);
	init_completion(&bt->exit);

	INIT_LIST_HEAD(&bt->free);

	bt->tries = 1;
	bt->await_backing = 1;

	disk = bt->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk)
		goto out_free_dev;

	disk->major			= bt_major;
	disk->first_minor	= atomic_inc_return(&bt_minors);
	disk->minors		= 1;
	disk->fops			= &bt_fops;
	disk->private_data	= bt;

	// todo: sector size; do we need it?

	strscpy(disk->disk_name, buf, DISK_NAME_LEN);
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

	// block module unload until this bt is deleted
	// an alternative is, upon unload:
	//	block any new creation
	//	flush_scheduled_work to flush scheduled deletes
	//	manually delete any remaining/or return busy
	if(!try_module_get(THIS_MODULE))
		goto out_rip_probe;

	spin_lock(&btlock);
		list_add(&bt->entry, &bt_devs);
	spin_unlock(&btlock);

	return 0;

out_rip_probe:
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	rip_probe(&bt->del_probe);
out_del_disk:
	del_gendisk(disk);
out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	kfree (bt);
	return err;
}

static void bt_del(struct bt_dev *bt)
{
	struct bio_stash * stash, * n;
	
	// these block until all runing code completes, so they're safe
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	persist_cleanup(bt);

	rip_probe(&bt->del_probe);

	bt_backing_release(bt, NULL);
	// todo: if we have inflight, should we just hang until await_backing is changed (BEFORE sysfs_remove)
	// or alternatively, for resume on suspend also...?
	bt->await_backing = 0;
	complete_all(&bt->resume);
	
	kref_put(&bt->refcount, release_dev);
	wait_for_completion(&bt->exit);
	
	del_gendisk(bt->disk);
	put_disk(bt->disk);

	list_for_each_entry_safe(stash, n, &bt->free, entry)
		kfree(stash);
}

static void bt_put(struct bt_dev * bt)
{
	kfree (bt);
	module_put(THIS_MODULE);
}

static void bt_remove(struct bt_dev *bt)
{
	bt_del(bt);

	spin_lock(&btlock);
		list_del(&bt->entry);
	spin_unlock(&btlock);

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
	block_partscan_cleanup();

	unregister_blkdev(bt_major, "bt"BT_VER);
	
	pr_info("blockthru"BT_VER": module unloaded\n");
}

module_init(bt_init);
module_exit(bt_exit);
MODULE_LICENSE("GPL");
