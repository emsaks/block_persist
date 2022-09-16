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
};
// ll of devices

#define dev_to_bp(dev) (container_of(dev, sturct bp_dev, dev))

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

static struct attribute *bp_dev_attrs[] = {
	&dev_attr_disabled.attr,
	&dev_attr_delete.attr,
	&dev_attr_blockdev.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
	&dev_attr_timeout.attr,
	NULL,
};

ATTRIBUTE_GROUPS(bp_dev);

static int brd_alloc(const char * name)
{
	struct bp_device *bpd;
	struct gendisk *disk;
	char buf[DISK_NAME_LEN];
	int err = -ENOMEM;


	bpd = kzalloc(sizeof(*bpd), GFP_KERNEL);
	if (!bpd)
		return -ENOMEM;

	list_add_tail(&bpd->bpd_list, &bp_devices);

	mutex_init(&bpd->lock);

	// todo: check available
	snprintf(buf, DISK_NAME_LEN, name);
	
	disk = bpd->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk)
		goto out_free_dev;

	disk->major			= bp_major;
	disk->first_minor	= i * max_part; // todo
	disk->minors		= 1;
	disk->fops			= &bp_fops;
	disk->private_data	= bpd;

	strlcpy(disk->disk_name, buf, DISK_NAME_LEN);
	set_capacity(disk, 0);
	

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, disk->queue);

	bpd->dev.groups = bp_dev_group;


	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	return 0;

out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	list_del(&bpd->bpd_list);
	kfree(bpd);
	return err;
}

static int bp_create(const char * name)
{
    struct bp_dev * dev;
    
}

static int create_set(const char *val, const struct kernel_param *kp)
{
    return bp_create(val);
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
    // remove devices
} 

static struct platform_driver bp_driver = {
	.driver = {
		   .name = "block_persist",
	},
};

static int bp_major;
static int __init bp_init(void)
{
	int err;

	bp_major = register_blkdev(0, "block_persist");
    if (bp_major < 0)
		err = -EIO;
        goto out_free;
	}

	err = platform_driver_register(&bp_driver);
	if (err)
		goto out_unreg_blkdev;
	
	pr_info("block_persist: module loaded\n");
	return 0;

out_unreg_blkdev:
	unregister_blkdev(bp_major, "block_persist");
out_free:
	bp_cleanup();

	pr_info("block_persist: module NOT loaded !\n");
	return err;
}

static void __exit bp_exit(void)
{
	unregister_blkdev(bp_major, "block_persist");
	bp_cleanup();

	pr_info("brd: module unloaded\n");
}

module_init(bp_init);
module_exit(bp_exit);
MODULE_LICENSE("GPL");
