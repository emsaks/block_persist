#include <linux/version.h> 
#include <linux/genhd.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define put_disk(disk) blk_cleanup_disk(disk)
#endif

#ifdef GD_SUPPRESS_PART_SCAN
static inline void suppress_part_scan(struct gendisk * gd) { set_bit(GD_SUPPRESS_PART_SCAN, &gd->state); }
static inline void enable_part_scan(struct gendisk * gd) { clear_bit(GD_SUPPRESS_PART_SCAN, &gd->state); }
static inline int  test_no_part_scan(struct gendisk * gd) { return test_bit(GD_SUPPRESS_PART_SCAN, &gd->state); }
#else
static inline void suppress_part_scan(struct gendisk * gd) { gd->flags |= GENHD_FL_NO_PART_SCAN; }
static inline void enable_part_scan(struct gendisk * gd) { gd->flags &= ~GENHD_FL_NO_PART_SCAN; }
static inline int  test_no_part_scan(struct gendisk * gd) { return gd->flags & GENHD_FL_NO_PART_SCAN; }
#endif

#ifndef BLK_STS_OFFLINE
#define BLK_STS_OFFLINE BLK_STS_TARGET
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#define SUBMIT_BIO_TYPE blk_qc_t
#define SUBMIT_BIO_RET BLK_QC_T_NONE
#else
#define SUBMIT_BIO_TYPE void
#define SUBMIT_BIO_RET
#endif