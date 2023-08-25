#include <linux/version.h> 
#include <linux/genhd.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define put_disk(disk) blk_cleanup_disk(disk)
#endif

#ifdef GD_SUPPRESS_PART_SCAN
#define GD_PS_STATE state
#else
#define GD_SUPPRESS_PART_SCAN GENHD_FL_NO_PART_SCAN
#define GD_PS_STATE flags
#endif

#ifndef BLK_STS_OFFLINE
#define BLK_STS_OFFLINE BLK_STS_TARGET
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#define bt_bio_submit(bioarg) bt_bio_submit_compat(bioarg)
static inline blkqc_t bt_submit_bio(struct bio * bio)
{
	bt_bio_submit_compat(bio);
	return BLK_QC_T_NONE;
} 
#endif