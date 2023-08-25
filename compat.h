#include <linux/version.h> 
#include <linux/blkdev.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define put_disk(disk) blk_cleanup_disk(disk)
#endif

#ifdef GD_SUPPRESS_PART_SCAN
#define GD_PS_STATE state
#else
#define GD_SUPPRESS_PART_SCAN GENHD_FL_NO_PART_SCAN
#define GD_PS_STATE flags
#define set_bit(flag, addr) *(addr) |= (flag)
#define clear_bit(flag, addr) *(addr) &= ~(flag)
#define test_bit(flag, addr) (*(addr) & (flag))
#endif

#ifndef BLK_STS_OFFLINE
#define BLK_STS_OFFLINE BLK_STS_TARGET
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#define bt_submit_bio(bioarg) bt_submit_bio_compat(bioarg)
static void bt_submit_bio_compat(struct bio * bio);
static inline blk_qc_t (bt_submit_bio)(struct bio * bio)
{
	bt_submit_bio_compat(bio);
	return BLK_QC_T_NONE;
} 
#endif