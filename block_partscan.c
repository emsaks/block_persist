#include <linux/module.h>
#include <linux/moduleparam.h>

long partscan_timeout = 0;

static int block_partscan_get(char *buffer, const struct kernel_param *kp);
{
	long now = jiffies;
	return sysfs_emit(buf, "%i\n", (now > partscan_timeout) ? now - partscan_timeout, 0);
}

static int block_partscan_set(const char *val, const struct kernel_param *kp)
{
	int err;
	long v;

	err = kstrtol(buf, 10, &v);
	if (err || v > INT_MAX)
		return -EINVAL;

	if (v <= 0) {
		partscan_timeout = v;
	} else if ((jiffies + v) > partscan_timeout) {
		partscan_timeout = jiffies + v;
	}
	
	return count;
}

struct kernel_param_ops block_partscan_ops = { 
	.set = block_partscan_set,
	.get = block_partscan_get,
};
module_param_cb(block_partscan, &block_partscan_ops, NULL, 0664);
MODULE_PARM_DESC(block_partscan, "Block partition scanning permanenty (-1) or for (>0) jiffies");