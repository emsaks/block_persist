#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>

#include "regs.h"
#include "compat.h"

DEFINE_SPINLOCK(partscan_lock);

static unsigned long block_all_timeout = 0, block_once_timeout = 0;

struct instance_data {
    struct gendisk *disk;
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct instance_data *data;
    struct gendisk *disk;

    data = (struct instance_data *)ri->data;
    disk = (struct gendisk *)(regs->ARG2);

	data->disk = NULL;
	
	if (!disk)
		return 0;

	spin_lock(&partscan_lock);
	if (jiffies <= block_all_timeout || jiffies <= block_once_timeout)
		data->disk = disk;
	spin_unlock(&partscan_lock);

	if (data->disk) {
		pr_warn("Intercepted partition read for disk: %s.\n", disk->disk_name);
		suppress_part_scan(disk);
		//set_bit(GD_SUPPRESS_PART_SCAN, &disk->state);
        data->disk = disk; // store this so we can remove the NO_PARTSCAN flag on function return
		block_once_timeout = 0;
	}

    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct gendisk *disk;

    disk = ((struct instance_data *)ri->data)->disk;
	if (disk) enable_part_scan(disk);
    //if (disk) clear_bit(GD_SUPPRESS_PART_SCAN, &disk->state);
    return 0;
}

static struct kretprobe partscan_probe = {
    .handler        = ret_handler,
    .entry_handler  = entry_handler,
    .data_size      = sizeof(struct instance_data),
    .maxactive      = 20,
	.kp.symbol_name	= "device_add_disk",
};

// best effort to return useful information; might be improvable
static int block_partscan_get(char *buf, const struct kernel_param *kp)
{
	int ret;
	unsigned long now;
	
	spin_lock(&partscan_lock);
	if (block_all_timeout == ULONG_MAX)
		ret = 1;
	else if (block_once_timeout == ULONG_MAX)
		ret = -1;
	else {
		now = jiffies;
		if (now <= block_all_timeout)
			ret = block_all_timeout - now;
		else if (now <= block_once_timeout)
			ret = -(block_once_timeout - now);
		else
			ret = 0;
	}
	spin_unlock(&partscan_lock);
	
	return sysfs_emit(buf, "%i\n", ret);
}

static int block_partscan_set(const char *val, const struct kernel_param *kp)
{
	int err;
	long v;
	unsigned long new_timeout;

	err = kstrtol(val, 10, &v);
	if (err || v > INT_MAX)
		return -EINVAL;

	spin_lock(&partscan_lock);
	if (v < -1) {
		if (block_once_timeout < ULONG_MAX) {
			new_timeout = jiffies + -v;
			if (new_timeout > block_once_timeout)
				block_once_timeout = new_timeout;
		}
	} else if (v == -1) {
		block_once_timeout = ULONG_MAX;
	} else if (v == 0) {
		block_all_timeout = 0;
		block_once_timeout = 0;
	} else if (v == 1) {
		block_all_timeout = ULONG_MAX;
	} else if (block_all_timeout < ULONG_MAX){
		new_timeout = jiffies + v;
		if (new_timeout > block_all_timeout)
			block_all_timeout = new_timeout;
	}
	
	if ((block_all_timeout || block_once_timeout) && !partscan_probe.kp.addr) {
		err = register_kretprobe(&partscan_probe);
		if (err) {
			pr_warn("register_kretprobe for %s failed, returned %d\n", partscan_probe.kp.symbol_name, err);
			memset(&partscan_probe.kp, 0, sizeof(partscan_probe.kp));
		}
	}
	spin_unlock(&partscan_lock);

	return 0;
}

void block_partscan_cleanup(void)
{
	if (partscan_probe.kp.addr) {
		unregister_kretprobe(&partscan_probe);
		memset(&partscan_probe.kp, 0, sizeof(partscan_probe.kp));
	}
}

struct kernel_param_ops block_partscan_ops = { 
	.set = block_partscan_set,
	.get = block_partscan_get,
};
module_param_cb(block_partscan, &block_partscan_ops, NULL, 0664);
MODULE_PARM_DESC(block_partscan, "Block partition scan (1) or for (2+) jiffies; negate for one-time block");