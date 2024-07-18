#include <linux/module.h>
#include <linux/moduleparam.h>

#include "blockthru.h"
#include "compat.h"
#include "regs.h"

struct add_data {
	struct gendisk * disk;
	int old_state;
};

static const char * normalize_path(const char * path) // allow paths retrieved from sysfs
{
	if (!strncmp(path, "/sys/", 5)) return path + 4;
	if (path[0] == '.' && path[1] == '/') path += 1;
	if (path[0] == '.' && path[1] == '.' && path[2] == '/') path += 2;
	while (!strncmp(path, "/../", 4)) path += 3;

	return path;
}

static int test_path(struct kobject * kobj, const char * pattern, int rewind)
{
	const char * part, * pp, * kp;

	if (!kobj) return 1;
	while (rewind--) if (!(kobj = kobj->parent)) { return 1; }

	part = pattern + strlen(pattern); 
	do {
		part -= strlen(kobj->name) + 1;
		if (part < pattern || *part != '/')
			{ return 1; }

		for (kp = kobj->name, pp = part+1; *kp; ++kp, ++pp)
			if ((*kp != *pp) && (*pp != '?'))
				{ return 1; }
	} while ((kobj = kobj->parent));

	return part != pattern;
}

/*
int try_script(struct persist_c *pc) {
	int ret;
	char * envp[] = { "HOME=/", NULL };
	char * argv[] = { "/bin/bash", pc->opts.script_on_added, pc->name, pc->blkdev->bd_disk->disk_name, NULL };

	if (!pc->opts.script_on_added)
		return 0;

	pw("Calling user script %s\n", pc->opts.script_on_added);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (ret) 
		pw("Script failed with error code %i\n", ret);

	return ret;
}
*/

static int add_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gendisk * disk = (void*)regs->ARG2;
	struct add_data * d = (void*)ri->data;
	struct bt_dev * bt = container_of(get_kretprobe(ri), struct bt_dev, add_probe);
	struct kobject * parent;

	d->disk = NULL;

	if (!disk) {
		pw("add_disk: Disk argument is NULL!\n");
		return 0;
	}

	// we must use parent because the block/sd* parts may not yet have been set
    parent = &(((struct device *)(regs->ARG1))->kobj);

	if (!parent) {
		pw("add_disk: Disk [%s] has no parent device! Skipping\n", disk->disk_name);
		return 0;
	}

	d->old_state = disk->state;

	// we must use a retry, so we don't wait on the lock while something tries to rip the probe
retry:
	if(spin_trylock(&bt->lock)) {
		if (!bt->persist_pattern) // may be in process of wiping pattern
			return 0;

		if (test_path(parent, bt->persist_pattern, bt->addtl_depth)) {
			pw("bt->addtl_depth = %i\n", bt->addtl_depth);
			pw("Added disk [%s] is not on path: %s. Ignoring.\n", disk->disk_name, bt->persist_pattern);
		} else if (get_capacity(disk) != get_capacity(bt->disk)) {
			pw("New disk [%s] capacity doesn't match! Ignoring.\n", disk->disk_name);
		} else {
			pw("Matched new disk [%s]\n", disk->disk_name);
			d->disk = disk;

			if (!test_bit(GD_SUPPRESS_PART_SCAN, &disk->GD_PS_STATE)) {
				pw("Suppressed partscan on disk %s\n", disk->disk_name);
				set_bit(GD_SUPPRESS_PART_SCAN, &disk->GD_PS_STATE);
			}
		}
		spin_unlock(&bt->lock);
	} else {
		if (bt->persist_pattern)
			goto retry;
	 	pw("Ignoring new disk after persistence pattern has been cleared.\n");
	}

	return 0;
}

static int add_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct bt_dev * bt = container_of(get_kretprobe(ri), struct bt_dev, add_probe);
	struct add_data * d = (void*)ri->data;
	struct block_device * bd = NULL;

	if (!d->disk) return 0;

	if (regs_return_value(regs))
		return 0;

	if (bt->backing) {
		pw("New disk found before old one was deleted; Ignoring.\n");
		return 0;
	}

	if (bt->persist_timeout && (bt->jiffies_when_removed + bt->persist_timeout < jiffies)) {
		pw("Not loading new disk after timeout.\n");
		return 0;
	}

	// try_script(pc);

	// we must use a retry, so we don't wait on the lock while something tries to rip the probe
retry:
	if(spin_trylock(&bt->lock)) {
		// pattern may have been switched beneath us
		if (!d->disk->part0->bd_device.parent || test_path(&d->disk->part0->bd_device.parent->kobj, bt->persist_pattern, bt->addtl_depth)) {
			pw("Added disk [%s] is not on new path: %s. Ignoring.\n", d->disk->disk_name, bt->persist_pattern);
		} else {
			struct bdev_handle *h = bdev_open_by_dev(d->disk->part0->bd_dev, BLK_OPEN_READ, holder, NULL);
			if (!IS_ERR_OR_NULL(h))
				bd = h->bdev;
			if (IS_ERR_OR_NULL(bd)) {
				pw("Failed to open disk [%s] with error: %li\n", d->disk->disk_name, PTR_ERR(bd));
			} else
				bt_backing_swap(bt, h);
		}
		spin_unlock(&bt->lock);
	} else {
		if (bt->persist_pattern)
			goto retry;
		pw("Not swapping disk after persistence pattern has been cleared.\n");
	}
	
	return 0;
}

static int set_pattern(struct bt_dev * bt, const char * pattern, size_t count)
{
	int ret = 0;
	char * devpath, *kp, *kt;
	const char *pp;

	if (count < 5) // normalize_path() minimum
		return -EINVAL;

	spin_lock(&bt->lock);
	if (bt->backing) {
		devpath = kobject_get_path(&(disk_to_dev(bt->backing->bd->bd_disk)->parent->kobj), GFP_KERNEL);
		pattern = normalize_path(pattern);

		for (kp = devpath, pp = pattern; *kp; ++kp, ++pp) {
			if (*kp != *pp) {
				if (*pp != '?' || *kp == '/') break;
				*kp = '?'; // '?' is a wildcard
			}
		}

		if (*pp || (*kp && *kp != '/')) { // this will exclude trailing '/' in pattern
			pw("Device is not on path: [%.*s]%s != %s\n", (int)(kp - devpath), devpath, kp, pp);
			ret = -EINVAL;
			kfree(devpath);
		} else {
			kt = kp;
			while (*kp) if (*kp++ == '/') bt->addtl_depth++;
			*kt = '\0';

			if (bt->persist_pattern) kfree(bt->persist_pattern);
			if (!bt->add_probe.handler) {
				ret = plant_probe(&bt->add_probe, add_entry, add_ret, "device_add_disk", sizeof(struct add_data));
			}
			if (ret) {
				kfree(devpath);
				bt->persist_pattern = NULL;
			} else {
				bt->persist_pattern = devpath;
			}
		}
	} else {
		pw("Can't update persistence pattern when no backing device is set\n");
		ret = -ENODEV;
	}
	spin_unlock(&bt->lock);

	return ret;
}


static ssize_t persist_timeout_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%li", dev_to_bt(dev)->persist_timeout);
}

static ssize_t persist_timeout_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned long v;

	err = kstrtoul(buf, 10, &v);
	if (err || v > UINT_MAX)
		return -EINVAL;

	dev_to_bt(dev)->persist_timeout = v;

	return count;
}
DEVICE_ATTR_RW(persist_timeout);

static ssize_t persist_pattern_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", dev_to_bt(dev)->persist_pattern);
}

static ssize_t persist_pattern_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct bt_dev * bt = dev_to_bt(dev);
	ssize_t ret;

	if (count <= 0) {
		spin_lock(&bt->lock);
			if (bt->persist_pattern) {
				kfree(bt->persist_pattern);
				bt->persist_pattern = NULL;
				rip_probe(&bt->add_probe);
			}
		spin_unlock(&bt->lock);
		return count;
	} else {
		ret = set_pattern(bt, buf, count);
		return ret < 0 ? ret : count;
	}
}
DEVICE_ATTR_RW(persist_pattern);

void persist_new_dev(struct bt_dev * bt, struct block_device * bd)
{
	if (bt->persist_pattern) {
		if (!bd->bd_device.parent || test_path(&bd->bd_device.parent->kobj, bt->persist_pattern, bt->addtl_depth)) {
			pw("New disk [%s] is not on path: %s; clearing persist settings.\n", bd->bd_disk->disk_name, bt->persist_pattern);
			rip_probe(&bt->add_probe);
			kfree(bt->persist_pattern);
			bt->persist_pattern = NULL;
		}
	}
}

void persist_cleanup(struct bt_dev * bt)
{
	rip_probe(&bt->add_probe);
	if (bt->persist_pattern) kfree(bt->persist_pattern);
}