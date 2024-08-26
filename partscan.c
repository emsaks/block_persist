#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>
#include <scsi/scsi_device.h>

#include "blockthru.h"
#include "regs.h"
#include "compat.h"

DEFINE_SPINLOCK(partscan_lock);

static unsigned long block_all_timeout = 0, block_once_timeout = 0;
static struct device * previous_scsi_target = NULL;
static struct gendisk * previous_revalidate_gendisk = NULL;
static unsigned long jiffies_at_block = 0;
struct instance_data {
    struct gendisk *disk;
};
bool read_before_ms = 0;

static int should_block(void)
{
	int block;
	spin_lock(&partscan_lock);
	block = jiffies <= block_all_timeout || jiffies <= block_once_timeout;
	spin_unlock(&partscan_lock);
	return block;
}

static int device_add_disk_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct instance_data *data;
	struct gendisk *disk;
	struct device * dev; 
	
	data = (struct instance_data *)ri->data;
	dev  = (struct device *)(regs->ARG1);
	disk = (struct gendisk *)(regs->ARG2);

	data->disk = NULL;
	
	if (!disk)
		return 0;

	/*	If this disk was seen first in sd_revalidate
	 *	assume the timeout expired in the meantime
	 *	and block anyway */
	if (should_block() || previous_revalidate_gendisk == disk)
		data->disk = disk;

	previous_revalidate_gendisk = NULL;

	// intercept partition scan for any disk under the same scsi target
	// if they are added in quick succession (useful for card readers)
	// even if a one-time block was specified
	// todo: this should probably be moved into sd_revalidate_disk
	if (   !data->disk 
		&& previous_scsi_target
		&& dev
		&& scsi_is_sdev_device(dev) 
		&& scsi_is_target_device(dev->parent) 
		&& dev->parent == previous_scsi_target) {

		if (jiffies > jiffies_at_block && (jiffies - jiffies_at_block) < HZ) {
			data->disk = disk;
		} else {
			previous_scsi_target = NULL;
		}
	}	

	if (data->disk) {
		if (dev && scsi_is_sdev_device(dev) && scsi_is_target_device(dev->parent)) {
			jiffies_at_block = jiffies;
			previous_scsi_target = dev->parent;
		}

		if (disk->part0->bd_nr_sectors > 0) {
			pr_warn("[%s] Intercepted partition read\n", disk->disk_name);
			set_bit(GD_SUPPRESS_PART_SCAN, &disk->GD_PS_STATE);
			data->disk = disk; // store this so we can remove the NO_PARTSCAN flag on function return
		}

		block_once_timeout = 0;
	}

	return 0;
}

static int device_add_disk_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk *disk;

	disk = ((struct instance_data *)ri->data)->disk;
	if (disk) clear_bit(GD_SUPPRESS_PART_SCAN, &disk->GD_PS_STATE);
	return 0;
}

static struct kretprobe device_add_disk_probe;

static int sd_revalidate_disk_entry(struct kprobe *p, struct pt_regs *regs);

static struct kprobe sd_revalidate_disk_probe = {
	.pre_handler = sd_revalidate_disk_entry,
	.symbol_name = "sd_revalidate_disk.isra.0",
};

static int sd_revalidate_disk_entry(struct kprobe *p, struct pt_regs *regs)
{
	// this was usually cleared in device_add_disk
	// but in case it never made it that far 
	// ensure we don't keep a stale pointer
	previous_revalidate_gendisk = NULL;

	if (!should_block())
		return 0;

	struct gendisk * gd = (struct gendisk *)regs->ARG1;
	if (PTR_ERR_OR_ZERO(gd) || gd->disk_name[0] != 's' || gd->disk_name[1] != 'd' || gd->disk_name[3] != '\0') {
		pr_warn("Bug: Doesn't look like we got a gendisk in %s\n", sd_revalidate_disk_probe.symbol_name);
		return 0;
	}

	previous_revalidate_gendisk = gd;

	struct scsi_device *sdev = scsi_dev_from_gd(gd);
	if (!read_before_ms) {
		pr_warn("[%s] Disabling read_before_ms\n", gd->disk_name);
		sdev->read_before_ms = 0;
	}
	return 0;
}

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
	spin_unlock(&partscan_lock);

	return 0;
}
module_param_call(block_partscan, block_partscan_set, block_partscan_get, NULL, 0664);
MODULE_PARM_DESC(block_partscan, "Block partition scan (1) or for (2+) jiffies; negate for one-time block");

module_param(read_before_ms, bool, 0664);
MODULE_PARM_DESC(read_before_ms, "Allow a dummy read when initializing disk. Some disks require it.");

void block_partscan_init(void)
{
	plant_retprobe(&device_add_disk_probe, device_add_disk, sizeof(struct instance_data));

	int err = register_kprobe(&sd_revalidate_disk_probe);
	if (err) {
		pr_warn("register_kprobe for %s failed, returned %d\n", sd_revalidate_disk_probe.symbol_name, err);
		memset(&sd_revalidate_disk_probe, 0, sizeof(sd_revalidate_disk_probe));
	}
}

void block_partscan_cleanup(void)
{
	rip_probe(&device_add_disk_probe);

	if (sd_revalidate_disk_probe.addr) 
		unregister_kprobe(&sd_revalidate_disk_probe);
}