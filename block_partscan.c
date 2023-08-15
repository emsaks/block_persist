#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>

static unsigned long partscan_timeout = 0;

static enum block_modes {
	block_never,
	block_once,
	block_once_timeout,
	block_all,
	block_all_timeout,
} block_mode;

struct kprobe partscan_probe;

static int block_partscan_get(char *buffer, const struct kernel_param *kp);
{
	int ret;
	unsigned long now = jiffies;
	if (block_mode == block_never)
		ret = 0;
	else if (block_mode == block_once)
		ret = -1;
	else if (block_mode == block_all)
		ret = 1;
	else if (now > partscan_timeout)
		ret = 0;
	else {
		ret = now - partscan_timeout;
		if (ret == 1) ret = 0;
	}

	return sysfs_emit(buf, "%i\n", ret);
}

static int block_partscan_set(const char *val, const struct kernel_param *kp)
{
	long v;
	unsigned long new_timeout;

	err = kstrtol(buf, 10, &v);
	if (err || v > INT_MAX)
		return -EINVAL;

	if (v < -1) {
		block_mode = block_once_timeout;
		partscan_timeout = jiffies + -v;
	} else if (v == -1) {
		block_mode = block_once;
	} else if (v == 0) {
		block_mode = block_never;
	} else if (v == 1) {
		block_mode = block_all;
	} else {
		block_mode = block_all_timeout;
		new_timeout = jiffies + v;
		if (new_timeout > partscan_timeout)
			partscan_timeout = new_timeout;
	}
	
	if (block_mode != block_never && !partscan_probe.handler) {
		// try to set probe
	}
	
	return 0;
}

struct kernel_param_ops block_partscan_ops = { 
	.set = block_partscan_set,
	.get = block_partscan_get,
};
module_param_cb(block_partscan, &block_partscan_ops, NULL, 0664);
MODULE_PARM_DESC(block_partscan, "Block partition scanning permanently (1) / jiffies (>1) / once (-1) / once upto jiffies (<-1)");