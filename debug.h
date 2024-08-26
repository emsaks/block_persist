#include <linux/spinlock.h>
#include <linux/printk.h>

#define CHECKPOINT pr_warn("Reached line %i in file %s\n", __LINE__, __FILE__)

#ifdef DEBUG
#define D(code) pr_warn("Entering code @%i: "#code"\n", __LINE__); code ; pr_warn("Exiting code: "#code"\n");

static inline int debug_spin_trylock(spinlock_t * lock, char * name, char * file, int line) {
	int ret;
	pr_warn("Pre trylock (%s) in %s @%i\n", name, file, line);
	ret = (spin_trylock)(lock);
	pr_warn("Trylock (%s) in %s @%i returned %i\n", name, file, line, ret);
	return ret;
}

#define spin_lock(lock) pr_warn("Pre lock (%s) in %s, @%i\n", #lock, __FILE__, __LINE__); (spin_lock)(lock); pr_warn("Post lock @%i\n", __LINE__);
#define spin_unlock(lock) pr_warn("Pre unlock (%s) in %s @%i\n", #lock, __FILE__, __LINE__); (spin_unlock)(lock); pr_warn("Post unlock @%i\n", __LINE__);
#define spin_trylock(lock) (debug_spin_trylock(lock, #lock, __FILE__, __LINE__))

#define mutex_lock(lock) pr_warn("Pre lock (%s) in %s, @%i\n", #lock, __FILE__, __LINE__); (mutex_lock)(lock); pr_warn("Post lock @%i\n", __LINE__);
#define mutex_unlock(lock) pr_warn("Pre unlock (%s) in %s @%i\n", #lock, __FILE__, __LINE__); (mutex_unlock)(lock); pr_warn("Post unlock @%i\n", __LINE__);
#define mutex_trylock(lock) (debug_mutex_trylock(lock, #lock, __FILE__, __LINE__))
#endif