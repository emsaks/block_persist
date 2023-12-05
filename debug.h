#include <linux/spinlock.h>
#include <linux/printk.h>

#ifdef DEBUG
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
#endif