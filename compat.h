#include <linux/version.h> 

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define put_disk(disk) blk_cleanup_disk(disk)
#endif