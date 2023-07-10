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

#define BT_VER "6"
static int bt_major;
static int bt_minors = 0;
static char * holder = "blockthru"BT_VER "held disk.";

struct bt_dev;

struct bio_stash {
	struct list_head entry;
	struct bt_dev * bt;
	struct block_device * target;
	void * bi_private;
	bio_end_io_t * bi_end_io;
	int tries_remaining;
};

struct bt_dev {
	struct list_head entry;
	struct device dev;
	int suspend;
	struct completion resume;

	char target_path[PATH_MAX];
	struct mutex lock;
	struct gendisk * disk;
	struct block_device * target;

	int exiting;
	struct completion exit;

	int tries;
	struct list_head free;
	struct list_head inflight;
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

// return device if it should be released; USE LOCK! ENSURE CALLER cleared its stash device
static struct block_device * bt_put_dev(struct bt_dev * bt, struct block_device *bd)
{
	struct bio_stash * s;

	list_for_each_entry(s, &bt->inflight, entry) {
		if (s->target == bd)
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
	if (bt->target != stash->target)
		putdev = bt_put_dev(bt, stash->target);
	stash->target = NULL;
	exit = bt->exiting && list_empty(&bt->inflight);
	mutex_unlock(&bt->lock);
	
	if (putdev) blkdev_put(putdev, FMODE_READ);
	if (exit) complete(&bt->exit);
}

// assume bio is already pointing to *our* endio and has stash in bi_private
static void bt_submit_internal(struct bio * bio)
{
	int suspended;
	struct bio_stash * stash = (struct bio_stash *)bio->bi_private;
	struct bt_dev * bt = stash->bt;

	--stash->tries_remaining;

retry:	
	mutex_lock(&bt->lock);
	if (!(suspended = bt->suspend) && bt->target != NULL)
			stash->target = bt->target; // this must be set under lock so the bd won't be swapped, free'd underneath us
	mutex_unlock(&bt->lock);

	if (suspended) {
		wait_for_completion(&bt->resume); // todo: use interruptable/killable
		goto retry;
	} else if (stash->target == NULL) {
		// todo: follow rule for block_on_empty // will we force suspend on NULL or keep a separate flag?
		// if exiting, do not block_on_empty!
		pr_warn("Setting error on no target\n");
		bio_set_dev(bio, bt->disk->part0); // in case we are a retry that targets as different dev; perhaps unneccessary.
		bio->bi_status = BLK_STS_MEDIUM;
		stash->tries_remaining = 0;
		bio_endio(bio);
	} else {
		bio_set_dev(bio, stash->target);
		submit_bio_noacct(bio);
	}
}

static void bt_io_end(struct bio * bio)
{
	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;
	struct block_device * putdev = NULL;

	// if retrying, put the device ourself (because we are not calling put_stash)
	// if no target, preserve the error code and don't bother retrying
	if (bio->bi_status == BLK_STS_MEDIUM && stash->target) {
		if (stash->tries_remaining > 0) {
			bio->bi_status = BLK_STS_OK;
			putdev = stash->target;
			mutex_lock(&stash->bt->lock);
			stash->target = NULL;
			if (stash->bt->target != putdev)
				putdev = bt_put_dev(stash->bt, putdev);
			mutex_unlock(&stash->bt->lock);
			if (putdev) blkdev_put(putdev, FMODE_READ);

			bt_submit_internal(bio);
			return;
		} else {
			pr_warn("Setting error on target MEDIUM fail\n");
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

static int bt_target_swap(struct bt_dev *bt, const char * path, size_t count)
{
	struct block_device * bd, *putdev;
	
	if (path[0] == '\0') {
		mutex_lock(&bt->lock);
		putdev = bt_put_dev(bt, bt->target);
		bt->target = NULL;
		mutex_unlock(&bt->lock);
		if (putdev) blkdev_put(putdev, FMODE_READ);
		return 0;
	}

	bd = blkdev_get_by_path(path, FMODE_READ, holder);
	if (IS_ERR(bd))
		return PTR_ERR(bd);
	if (!bd)
		return -ENODEV;

	pr_warn("Swapping target on %s to %s\n", bt->disk->disk_name, path);

	mutex_lock(&bt->lock);
		putdev = bt_put_dev(bt, bt->target);
		bt->target = bd;
		strncpy((char*)bt->target_path, path, count);

		if (!set_capacity_and_notify(bt->disk, bdev_nr_sectors(bd)))
			kobject_uevent(&disk_to_dev(bt->disk)->kobj, KOBJ_CHANGE);
	mutex_unlock(&bt->lock);

	if (putdev) blkdev_put(putdev, FMODE_READ);

	return 0;
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

static ssize_t target_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	strncpy(buf, dev_to_bt(dev)->target_path, sizeof(dev_to_bt(dev)->target_path));
	return strlen(buf);
}

static ssize_t target_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    int err = bt_target_swap(dev_to_bt(dev), buf, count);
	return err < 0 ? err : count;
}
static DEVICE_ATTR_RW(target);

static ssize_t port_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t port_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return count;
}
static DEVICE_ATTR_RW(port);

/* // this is unsafe/cause a lockup
static ssize_t delete_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	bt_delete(dev_to_bt(dev));
    return count;
}
static DEVICE_ATTR_WO(delete);
*/

static struct attribute *bt_attrs[] = {
	//&dev_attr_delete.attr,
	&dev_attr_target.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
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

#define d(code) pr_warn("Entering code: "#code"\n"); code ; pr_warn("Exiting code: "#code"\n");
static int bt_delete(struct bt_dev *bt)
{
	struct bio_stash * stash, * n;
	int has_inflight = 0;

	mutex_lock(&bt->lock);
	if (!bt->suspend)
		bt->exiting = 1;
	mutex_unlock(&bt->lock);
	if (!bt->exiting)
		return -EBUSY;
	
	sysfs_remove_group(&disk_to_dev(bt->disk)->kobj, &bt_attribute_group);
	del_gendisk(bt->disk);
	put_disk(bt->disk);
	
	mutex_lock(&bt->lock);
		has_inflight = !list_empty(&bt->inflight);
	mutex_unlock(&bt->lock);
	if (has_inflight)
		wait_for_completion(&bt->exit);
	
	if (bt->target) blkdev_put(bt->target, FMODE_READ);

	blk_cleanup_disk(bt->disk);

	list_for_each_entry_safe(stash, n, &bt->free, entry)
		kfree(stash);
	
	kfree (bt);

	module_put(THIS_MODULE);

	return 0;
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
		pr_warn("sysfs init failed with code %i", err);
		goto out_del_disk;
	}

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


static int delete_set(const char *val, const struct kernel_param *kp)
{
	int err = 0;
	struct bt_dev * bt, * n;
	mutex_lock(&bt_lock);
	list_for_each_entry_safe(bt, n, &bt_devs, entry) {
		if (!strncmp(val, bt->disk->disk_name, sizeof(bt->disk->disk_name))) {
			list_del(&bt->entry);
			break;
		}
	}
	mutex_unlock(&bt_lock);

	if list_entry_is_head(bt, &bt_devs, entry)
		return -ENODEV;

	err = bt_delete(bt);
	if (!err)
		return 0;

	mutex_lock(&bt_lock);
	list_add(&bt->entry, &bt_devs);
	mutex_unlock(&bt_lock);

	return err;
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
	struct list_head * l, * n;
	mutex_lock(&bt_lock);
		list_for_each_safe(l, n, &bt_devs) {
			bt_delete((struct bt_dev *)l);
		}
	mutex_unlock(&bt_lock);
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
