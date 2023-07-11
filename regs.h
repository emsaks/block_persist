#ifdef CONFIG_X86_32
#define ARG1 ax
#define ARG2 bx
#elif defined CONFIG_X86_64
#define ARG1 di
#define ARG2 si
#elif defined CONFIG_ARM || CONFIG_ARM64
#define ARG1 regs[0]
#define ARG2 regs[1]
#endif