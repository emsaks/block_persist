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
#include <linux/semaphore.h>

#define BT_VER "3"
static int bt_major;
static int bt_minors = 0;
static char * holder = "blockthru"BT_VER "held disk.";

struct bt_dev;

struct bio_stash {
	struct list_head entry;
	struct bt_dev * bt;
	struct block_device * target;
	void * bi_private;
	bio_end_io_t * bi_endio;
	int tries_remaining;
};

struct bt_dev {
	struct list_head bt_list;
	struct device dev;
	int suspend;
	struct completion resume;

	char target_path[PATH_MAX];
	struct mutex lock;
	struct gendisk * disk;
	struct block_device * target;
	int sysfs_inited;

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
	struct bio_stash * stash;
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

static void bt_put_stash(struct bio_stash * stash)
{
	struct bt_dev * bt = stash->bt;
	struct block_device *putdev = NULL;
	struct bio_stash * s;

	mutex_lock(&bt->lock);
	list_move(&stash->entry, &bt->free);
	if (stash->target != bt->target) {
		putdev = stash->target;
		list_for_each_entry(s, &bt->inflight, entry) {
			if (s->target == stash->target) {
				putdev = NULL;
				break;
			}
		}
	}
	stash->target = NULL;
	mutex_unlock(&bt->lock);
	
	if (putdev) blkdev_put(putdev, FMODE_READ);
}

static void bt_submit_internal(struct bio * bio)
{
	int suspended;
	struct bio_stash * stash = (struct bio_stash *)bio->bi_private;
	struct bt_dev * bt = stash->bt;

	stash->tries_remaining--;

retry:	
	mutex_lock(&bt->lock);
	if (!(suspended = bt->suspend)) {
		if (bt->target != NULL) {
			stash->target = bt->target;
		} else bio_set_dev(bio, bt->disk->part0);
	}
	mutex_unlock(&bt->lock);

	if (suspended) {
		wait_for_completion(&bt->resume); // todo: use interruptable/killable
		goto retry;
	} else if (bio->bi_bdev == bt->disk->part0) {
		// todo: follow rule for block_on_empty
		bio->bi_status = BLK_STS_MEDIUM;
		// todo: set tries to 0?
		bio_endio(bio);
	} else {
		bio_set_dev(bio, stash->target);
		submit_bio_noacct(bio);
	}
}

static void bt_bio_end(struct bio * bio)
{
	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;
	
	if (bio->bi_status == BLK_STS_MEDIUM) {
		if (stash->tries_remaining > 0) {
			bio->bi_status = BLK_STS_OK;
			bt_submit_internal(bio);
			return;
		} else {
			bio_io_error(bio);
		}
	}
	
	bio->bi_private = stash->bi_private;
	bio->bi_end_io = stash->bi_endio;

	bt_put_stash(stash);
	bio_endio(bio);
}

static int bt_suspend(struct bt_dev * bt)
{
	mutex_lock(&bt->lock);
		bt->suspend = 1;
	mutex_unlock(&bt->lock);
	return 0;
}

static int bt_resume(struct bt_dev * bt)
{
	mutex_lock(&bt->lock);
		bt->suspend = 0;
	mutex_unlock(&bt->lock);
	complete(&bt->resume);
	return 0;
}

static int bt_target_release_locked(struct bt_dev * bt)
{
	if (!bt->target)
		return 0;
	
	memset(bt->target_path, sizeof(bt->target_path), 0);

	blkdev_put(bt->target, FMODE_READ);
	bt->target = NULL;
	return 0;
}

static int bt_target_release(struct bt_dev * bt)
{
	mutex_lock(&bt->lock);
		bt_target_release_locked (bt);
	mutex_unlock(&bt->lock);
	return 0;
}

static int bt_target_swap(struct bt_dev *bt, const char * path, size_t count)
{
	struct block_device * bd;

	if (path[0] == '\0') {
		bt_target_release (bt);
		return 0;
	}

	bd = blkdev_get_by_path(path, FMODE_READ, holder);
	if (IS_ERR(bd)) {
		return PTR_ERR(bd);
	}
	if (!bd) {
		return 1;
	}

	pr_warn("Swapping target on %s to %s\n", bt->disk->disk_name, path);

	mutex_lock(&bt->lock);
		bt_target_release_locked (bt);
		bt->target = bd;
		strncpy((char*)bt->target_path, path, count);

		if (!set_capacity_and_notify(bt->disk, get_capacity(bd->bd_disk)))
			kobject_uevent(&disk_to_dev(bt->disk)->kobj, KOBJ_CHANGE);
	mutex_unlock(&bt->lock);

	return 0;
}

static void bt_sysfs_exit(struct bt_dev *bt);

static int bt_delete(struct bt_dev *bt)
{
	// todo: flag cleanup so no more swapping etc.
	
	mutex_lock(&bt->lock);
		bt->suspend = 1; // think through nested  locking etc
		bt_target_release_locked(bt);
	mutex_unlock(&bt->lock);
	bt_sysfs_exit(bt);
	del_gendisk(bt->disk); 
	blk_cleanup_disk(bt->disk);
	kfree (bt);

	return 0;
}

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct bt_dev * bt = dev_to_bt(dev);
	return sysfs_emit(buf, "%s\n", bt->suspend ? "1" : "0");
}

static ssize_t suspend_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count <= 0)
		return count;
	if (buf[0] == '1') {
		bt_suspend(dev_to_bt(dev));
	} else if (buf[0] == '0') {
		bt_resume(dev_to_bt(dev));
	}
	return count;
}
static DEVICE_ATTR_RW(suspend);

static ssize_t target_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	strncpy(buf, dev_to_bt(dev)->target_path, sizeof(dev_to_bt(dev)->target_path));
	return strlen(buf);
}

static ssize_t target_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    bt_target_swap(dev_to_bt(dev), buf, count);
	return count;
}
static DEVICE_ATTR_RW(target);

static ssize_t port_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t port_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return 0;
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

static ssize_t release_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	if (count <= 0)
		return count;
    bt_target_release(dev_to_bt(dev));
	return count;
}
static DEVICE_ATTR_WO(release);

static struct attribute *bt_attrs[] = {
	//&dev_attr_delete.attr,
	&dev_attr_target.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
	&dev_attr_release.attr,
	NULL,
};

static struct attribute_group bt_attribute_group = {
	.name = "blockthru",
	.attrs= bt_attrs,
};

static void bt_sysfs_init(struct bt_dev *bt)
{
	int ret = sysfs_create_group(&disk_to_dev(bt->disk)->kobj,
						&bt_attribute_group);
	if (ret)
		pr_warn("sysfs init failed with code %i", ret);

	bt->sysfs_inited = !ret;
}

static void bt_sysfs_exit(struct bt_dev *bt)
{
	if (bt->sysfs_inited)
		sysfs_remove_group(&disk_to_dev(bt->disk)->kobj,
				   &bt_attribute_group);
}

static void bt_submit_bio(struct bio *bio)
{
	/*
		todo: get stash, save, set tries remaining, call submit internal
	
	*/
	int suspended;
	struct bt_dev * bt= bio->bi_bdev->bd_disk->private_data;

	//pr_warn("submit bio");
retry:	
	mutex_lock(&bt->lock);
	if (!(suspended = bt->suspend)) {
		if (IS_ERR_OR_NULL(bt->target)) {
			bio_io_error(bio); // TODO: ensure this is the appropriate status (maybe use BLK_STS_TARGET/MEDIUM)
			bio_endio(bio);	// TODO: check if bio->bi_dev is accessed after this
		} else {
			bio_set_dev(bio, bt->target);
			/*
			 *	When this returns, I *think* the bio device field 
			 *  will not be used again, so it is safe to release the
			 *  device handle.
			 */
			submit_bio_noacct(bio);
		}
	}
	mutex_unlock(&bt->lock);

	if (suspended) {
		wait_for_completion(&bt->resume); // todo: use interruptable/killable
		goto retry;
	}
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
	
	// TODO: all inits here
	mutex_init(&bt->lock);
	init_completion(&bt->resume);
	INIT_LIST_HEAD(&bt->inflight);
	INIT_LIST_HEAD(&bt->free);
	for (int i = 0; i < 4; i++) {
		struct bio_stash * stash = kzalloc(sizeof(struct bio_stash), GFP_KERNEL);
		if (!stash) break;
		stash->bt = bt;
		list_add(&stash->entry, &bt->free);
	}

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

	bt_sysfs_init (bt);

	mutex_lock(&bt_lock);
		list_add(&bt->bt_list, &bt_devs);
	mutex_unlock(&bt_lock);

	return 0;

out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	list_del(&bt->bt_list); // lock!
	kfree (bt);
	return err;
}


static int delete_set(const char *val, const struct kernel_param *kp)
{
	struct bt_dev * bt, * n;

	mutex_lock(&bt_lock);
	list_for_each_entry_safe(bt, n, &bt_devs, bt_list) {
		if (!strncmp(val, bt->disk->disk_name, sizeof(bt->disk->disk_name))) {
				list_del(&bt->bt_list);
				break;
		}
	}
	mutex_unlock(&bt_lock);

	return list_entry_is_head(bt, &bt_devs, bt_list) ? -ENODEV : bt_delete(bt);
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
	struct list_head * l;
	mutex_lock(&bt_lock);
		list_for_each(l, &bt_devs) {
			bt_delete((struct bt_dev *)l);
		}
	mutex_unlock(&bt_lock);
} 


static int __init bt_init(void)
{
	int err;

	bt_major = register_blkdev(0, "bt"BT_VER);
    if (bt_major < 0) {
		err = -EIO;
        goto out_free;
	}

	pr_info("blockthru"BT_VER": module loaded\n");
	return 0;

out_unreg_blkdev:
	unregister_blkdev(bt_major, "bt"BT_VER);
out_free:
	bt_cleanup();

	pr_info("blockthru"BT_VER": module NOT loaded !\n");
	return err;
}

static void __exit bt_exit(void)
{
	unregister_blkdev(bt_major, "bt"BT_VER);
	bt_cleanup();

	pr_info("blockthru"BT_VER": module unloaded\n");
}

module_init(bt_init);
module_exit(bt_exit);
MODULE_LICENSE("GPL");
