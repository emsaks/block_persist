#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/part_stat.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/kprobes.h>
#include <linux/string.h>

#include "debug.h"

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#ifndef BT_VER
#define BT_VER ""
#endif
#define BT_VER_STR STRINGIFY(BT_VER)

#define dev_to_bt(dev) ((struct bt_dev *)dev_to_disk(dev)->private_data)

#define pw(fmt, ...) pr_warn("[%s] "fmt, bt->disk->disk_name, ## __VA_ARGS__)

struct bt_dev;

struct backing {
	struct bt_dev * bt;
	struct block_device * bd;
	struct bdev_handle * bdev_handle;
	struct kref inflight;
	unsigned long timestamp;
	struct work_struct put;
};

struct bio_stash {
	struct list_head entry;
	struct backing * disk;
	void * bi_private;
	bio_end_io_t * bi_end_io;
	int tries_remaining;
};

struct bt_dev {
	struct list_head entry;

	//struct mutex lock;
	spinlock_t lock;
	struct gendisk * disk;

	int suspend;
	struct completion resume;

	struct backing * backing;
	bool await_backing;

	int exiting;
	struct completion exit;
	/*  we can't delete ourself from within a our attribute code, 
		because the delete code hangs waiting for all attributes
		to return, so we need a worker for that */
	struct work_struct delete;

	unsigned long tries;
	struct list_head free;

	struct kretprobe add_probe, del_probe;

	char *	persist_pattern;
	int 	addtl_depth;
	unsigned long persist_timeout;

	long salvaged_bytes;

	unsigned long jiffies_when_removed;

	uint swapped_count;
	
	struct kref refcount;
};

static inline int plant_probe(struct kretprobe * probe, kretprobe_handler_t entry, kretprobe_handler_t ret, char * symbol_name, size_t data_size)
{
	int e;

	if (probe->handler) {
		return -EBUSY;
	}

	memset(probe, 0, sizeof(*probe));
	probe->handler        = ret,
	probe->entry_handler  = entry,
	probe->maxactive      = 20,
	probe->data_size	  = data_size;
	probe->kp.symbol_name = symbol_name;

	e = register_kretprobe(probe);
	if (e < 0) {
		pr_warn("register_kretprobe for %s failed, returned %d\n", symbol_name, e);
		probe->handler = NULL; // this will flag that the probe has not been set
		return e;
	}

	return 0;
}

static inline void rip_probe(struct kretprobe * probe)
{
	if (probe->handler) {
		unregister_kretprobe(probe);
		probe->handler = NULL;
	}
}

extern char * holder;
int bt_backing_swap(struct bt_dev * bt, struct bdev_handle * handle);

void persist_new_dev(struct bt_dev * bt, struct block_device * bd);
void persist_cleanup(struct bt_dev * bt);

void block_partscan_init(void);
void block_partscan_cleanup(void);

extern struct device_attribute dev_attr_persist_timeout;
extern struct device_attribute dev_attr_persist_pattern;

#ifdef SALVAGE
void prep_bio(struct bio * bio);
size_t salvage_bio(struct bio * bio);
extern struct device_attribute dev_attr_salvaged_bytes;
#endif

#define DEVICE_ATTR_FUNCS_ACC(name, accessor_via_dev, kstrfunc, fmt) 						\
static ssize_t name ## _show(struct device *dev, struct device_attribute *attr, char *buf)	\
{																							\
	return sysfs_emit(buf, "%" #fmt "\n", accessor_via_dev);								\
}																							\
static ssize_t name ## _store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	\
{																												\
	int err;																									\
	long v;																										\
																												\
	err = kstrfunc(buf, 10, &v);																				\
	if (err)																									\
		return -EINVAL;																							\
																												\
	(accessor_via_dev) = v;																						\
	return count;																								\
}

#define DEVICE_ATTR_LONG_FUNCS_ACC(name, accessor_via_dev) DEVICE_ATTR_FUNCS_ACC(name, accessor_via_dev, kstrtol, li)

#define DEVICE_ATTR_LONG_FUNCS(name, dev_to_parent) DEVICE_ATTR_LONG_FUNCS_ACC(name, (dev_to_parent)->name)

#define DEVICE_ATTR_ULONG_FUNCS_ACC(name, accessor_via_dev)	DEVICE_ATTR_FUNCS_ACC(name, accessor_via_dev, kstrtoul, lu)								\

#define DEVICE_ATTR_ULONG_FUNCS(name, dev_to_parent) DEVICE_ATTR_ULONG_FUNCS_ACC(name, (dev_to_parent)->name)
