#include <linux/version.h> 
#include <linux/blkdev.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define put_disk(disk) blk_cleanup_disk(disk)
#endif

#ifndef BLK_OPEN_READ
#define BLK_OPEN_READ BLK_OPEN_READ
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 23) //(6, 8, 0)
struct bdev_handle {
	struct block_device *bdev;
	void *holder;
	// blk_mode_t mode; // not in earlier versions...
};

inline struct bdev_handle *bdev_open_by_path(const char *path, blk_mode_t mode,
		void *holder, const struct blk_holder_ops *hops) {
	struct bdev_handle *h;
	
	h = kzalloc(sizeof(struct bdev_handle), GFP_KERNEL);
	if (!h) return NULL;
	h->bdev = blkdev_get_by_path(path, mode, holder);
	h->holder = holder;
	return h;
}

inline struct bdev_handle *bdev_open_by_dev(dev_t dev, blk_mode_t mode, void *holder,
				     const struct blk_holder_ops *hops) {
	struct bdev_handle *h;

	h = kzalloc(sizeof(struct bdev_handle), GFP_KERNEL);
	if (!h) return NULL;
	h->bdev = blkdev_get_by_dev(path, mode, holder);
	h->holder = holder;
	return h;
}

inline void bdev_release(struct bdev_handle *handle) {
	#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	blkdev_put(handle->bd, BLK_OPEN_READ);
	#else
	blkdev_put(handle->bd, handle->holder);
	#endif
	kfree(handle);
}
#endif

#ifdef GD_SUPPRESS_PART_SCAN
#define GD_PS_STATE state
#else
#define GD_SUPPRESS_PART_SCAN GENHD_FL_NO_PART_SCAN
#define GD_PS_STATE flags
#define set_bit(flag, addr) (*(addr) |= (flag))
#define clear_bit(flag, addr) (*(addr) &= ~(flag))
#define test_bit(flag, addr) (*(addr) & (flag))
#endif

#ifndef BLK_STS_OFFLINE
#define BLK_STS_OFFLINE BLK_STS_TARGET
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#define bt_submit_bio(bioarg)							\
	bt_submit_bio_compat(bioarg);						\
	static blk_qc_t (bt_submit_bio)(struct bio * bio)	\
	{													\
		bt_submit_bio_compat(bio);						\
		return BLK_QC_T_NONE;							\
	}													\
	static void bt_submit_bio_compat(bioarg)
#endif