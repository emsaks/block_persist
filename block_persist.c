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

// ll of devices

static ssize_t suspend_show(struct device *dev, struct device_attribute *attr, char *buf)
{

}

static ssize_t suspend_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{

}
static DEVICE_ATTR_RW(suspend);

static ssize_t blockdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{

}

static ssize_t blockdev_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    
}
static DEVICE_ATTR_RW(blockdev);

static ssize_t port_show(struct device *dev, struct device_attribute *attr, char *buf)
{

}

static ssize_t port_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    
}
static DEVICE_ATTR_RW(port);

static ssize_t timeout_show(struct device *dev, struct device_attribute *attr, char *buf)
{

}

static ssize_t timeout_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    
}
static DEVICE_ATTR_RW(timeout);

static ssize_t delete_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    
}
static DEVICE_ATTR_WO(delete);

static struct attribute *bp_dev_attrs[] = {
	&dev_attr_delete.attr,
	&dev_attr_blockdev.attr,
	&dev_attr_suspend.attr,
	&dev_attr_port.attr,
	&dev_attr_timeout.attr,
	NULL,
};

static const struct attribute_group bp_dev_attr_grp = {
	.attrs = bp_dev_attrs,
};

static const struct attribute_group *bp_dev_group[] = {
	&bp_dev_attr_grp,
	NULL,
};

static int bp_create(const char * name)
{

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

static int bp_major;
static int __init bp_init(void)
{
	int err;

	bp_major = register_blkdev(0, "block_persist");
    if (bp_major < 0)
		err = -EIO;
        goto out_free;
	}

	pr_info("block_persist: module loaded\n");
	return 0;

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
