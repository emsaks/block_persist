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

struct bp_dev {
	struct device dev;
	struct list_head bpd_list;
	int timeout;
	int suspend;
	int disabled;
	char blockdev[PATH_MAX];
	struct mutex lock;
	struct gendisk * disk;
	int sysfs_inited;
};
// ll of devices

#define dev_to_bp(dev) ((struct bp_device *)dev_to_disk(dev)->private_data)

static LIST_HEAD(bp_devices);

static ssize_t disabled_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct bp_dev * bpd = dev_to_bp(dev);
	return sysfs_emit(buf, "%s\n", bpd->disabled ? "1" : "0");
}

static ssize_t disabled_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	return 0;
}
static DEVICE_ATTR_RW(disabled);

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct bp_dev * bpd = dev_to_bp(dev);
	return sysfs_emit(buf, "%s\n", bpd->suspend ? "1" : "0");
}

static ssize_t suspend_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	return 0;
}
static DEVICE_ATTR_RW(suspend);

static ssize_t blockdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t blockdev_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return 0;
}
static DEVICE_ATTR_RW(blockdev);

static ssize_t port_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t port_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return 0;
}
static DEVICE_ATTR_RW(port);

static ssize_t timeout_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct bp_dev * bpd = dev_to_bp(dev);
	return sysfs_emit(buf, "%d\n", bpd->timeout);
}

static ssize_t timeout_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return 0;
}
static DEVICE_ATTR_RW(timeout);

static ssize_t delete_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return 0;
}
static DEVICE_ATTR_WO(delete);

static struct attribute *bp_attrs[] = {
	&dev_attr_disabled.attr,
	&dev_attr_delete.attr,
	&dev_attr_blockdev.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
	&dev_attr_timeout.attr,
	NULL,
};

static struct attribute_group bp_attribute_group = {
	.name = "persist",
	.attrs= bp_attrs,
};

static void bp_sysfs_init(struct bp_device *bp)
{
	bp->sysfs_inited = !sysfs_create_group(&disk_to_dev(bp->disk)->kobj,
						&bp_attribute_group);
}

static void bp_sysfs_exit(struct bp_device *bp)
{
	if (lo->sysfs_inited)
		sysfs_remove_group(&disk_to_dev(bp->bp_disk)->kobj,
				   &bp_attribute_group);
}

static int bp_alloc(const char * name)
{
	struct bp_device *bpd;
	struct gendisk *disk;
	char buf[DISK_NAME_LEN];
	int err = -ENOMEM;

	bpd = kzalloc(sizeof(*bpd), GFP_KERNEL);
	if (!bpd)
		return -ENOMEM;

	list_add_tail(&bpd->bpd_list, &bp_devices); // todo: use a lock

	mutex_init(&bpd->lock);

	// todo: check name available
	snprintf(buf, DISK_NAME_LEN, name);
	
	disk = bpd->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk)
		goto out_free_dev;

	set_bit(GD_SUPPRESS_PART_SCAN, &disk->state);

	disk->major			= bp_major;
	disk->first_minor	= i * max_part; // todo: get free minor; use a lock
	disk->minors		= 1;
	disk->fops			= &bp_fops;
	disk->private_data	= bpd;

	strlcpy(disk->disk_name, buf, DISK_NAME_LEN);
	set_capacity(disk, 0);
	

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, disk->queue);

	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	return 0;

out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	list_del(&bpd->bpd_list); // lock!
	kfree(bpd);
	return err;
}

static int create_set(const char *val, const struct kernel_param *kp)
{
    return bp_alloc(val);
}

static const struct block_device_operations bp_fops = {
	.owner      =	THIS_MODULE,
	.submit_bio =	bp_submit_bio,
};

struct kernel_param_ops create_ops { 
    .set = create_set,
}
module_param_cb(create, create_ops, NULL, 0664)
MODULE_PARM_DESC(create, "Create new named persistent device");

static void bp_cleanup(void)
{
    // remove devices/disks
} 

static int bp_major;
static int __init bp_init(void)
{
	int err;

	bp_major = register_blkdev(0, "bp");
    if (bp_major < 0)
		err = -EIO;
        goto out_free;
	}

	
	
	pr_info("block_persist: module loaded\n");
	return 0;

out_unreg_blkdev:
	unregister_blkdev(bp_major, "bp");
out_free:
	bp_cleanup();

	pr_info("block_persist: module NOT loaded !\n");
	return err;
}

static void __exit bp_exit(void)
{
	unregister_blkdev(bp_major, "bp");
	bp_cleanup();

	pr_info("brd: module unloaded\n");
}

module_init(bp_init);
module_exit(bp_exit);
MODULE_LICENSE("GPL");
