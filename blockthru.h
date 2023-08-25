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

#ifdef MAKE_VER
#define BT_VER MAKE_VER
#else
#define BT_VER ""
#endif

#define dev_to_bt(dev) ((struct bt_dev *)dev_to_disk(dev)->private_data)

#define pw(fmt, ...) pr_warn("[%s] "fmt, bt->disk->disk_name, ## __VA_ARGS__)

#define D(code) pr_warn("Entering code @%i: "#code"\n", __LINE__); code ; pr_warn("Exiting code: "#code"\n");

static inline int debug_spin_trylock(spinlock_t * lock, char * name, char * file, int line) {
	int ret;
	pr_warn("Pre trylock (%s) in %s @%i\n", name, file, line);
	ret = (spin_trylock)(lock);
	pr_warn("Trylock (%s) in %s @%i returned %i\n", name, file, line, ret);
	return ret;
}

#define spin_lock(mut) pr_warn("Pre lock (%s) in %s, @%i\n", #mut, __FILE__, __LINE__); (spin_lock)(mut); pr_warn("Post lock @%i\n", __LINE__);
#define spin_unlock(mut) pr_warn("Pre unlock (%s) in %s @%i\n", #mut, __FILE__, __LINE__); (spin_unlock)(mut); pr_warn("Post unlock @%i\n", __LINE__);
#define spin_trylock(mut) (debug_spin_trylock(mut, #mut, __FILE__, __LINE__))


struct bt_dev;

struct disk {
	struct bt_dev * bt;
	struct block_device * bd;
	struct kref inflight;
	unsigned long jiffies_when_added;
};

struct bio_stash {
	struct list_head entry;
	struct disk * disk;
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

	struct disk * backing;
	bool await_backing;

	int exiting;
	struct completion exit;
	/*  we can't delete ourself from within a our attribute code, 
		because the delete code hangs waiting for all attributes
		to return, so we need a worker for that */
	struct work_struct delete;

	int tries;
	struct list_head free;

	struct kretprobe add_probe, del_probe;

	char *	persist_pattern;
	int 	addtl_depth;
	unsigned long persist_timeout;
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
int bt_backing_swap(struct bt_dev * bt, struct block_device * bd);

void persist_new_dev(struct bt_dev * bt, struct block_device * bd);
void persist_cleanup(struct bt_dev * bt);

void block_partscan_cleanup(void);