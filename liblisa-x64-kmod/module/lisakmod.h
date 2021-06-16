/* https://cirosantilli.com/linux-kernel-module-cheat#ioctl */

#ifndef LISA_KMOD
#define LISA_KMOD

#include <linux/ioctl.h>

typedef struct {
	uint64_t addr;
} cmd_munmap_t;

typedef struct {
	uint64_t addr;
	int32_t fd;
	uint8_t prot;
} cmd_mmap_t;

typedef struct {
	int status;
	int si_errno;
	int si_code;
	int si_signo;
	uint64_t optional_addr;
} lisa_observe_result_t;

/* Structs are the way to pass multiple arguments. */
typedef struct {
	int pid;
	size_t num_unmaps;
	size_t num_maps;
	int mapping_flags;
	cmd_munmap_t unmaps[32];
	cmd_mmap_t maps[32];
	void *regs;
	lisa_observe_result_t *result;
} lisa_ioctl_struct;

/* TODO some random number I can't understand how to choose. */
#define LKMC_IOCTL_MAGIC 0x33

/* I think those number do not *need* to be unique across, that is just to help debugging:
 * https://stackoverflow.com/questions/22496123/what-is-the-meaning-of-this-macro-iormy-macig-0-int
 *
 * However, the ioctl syscall highjacks several low values at do_vfs_ioctl, e.g.
 * This "forces" use to use the _IOx macros...
 * https://stackoverflow.com/questions/10071296/ioctl-is-not-called-if-cmd-2
 *
 * Some of those magic low values are used for fnctl, which can also be used on regular files:
 * e.g. FIOCLEX for close-on-exec:
 * https://stackoverflow.com/questions/6125068/what-does-the-fd-cloexec-fcntl-flag-do
 *
 * TODO are the W or R of _IOx and type functional, or only to help with uniqueness?
 *
 * Documentation/ioctl/ioctl-number.txt documents:
 *
 * ....
 * _IO    an ioctl with no parameters
 * _IOW   an ioctl with write parameters (copy_from_user)
 * _IOR   an ioctl with read parameters  (copy_to_user)
 * _IOWR  an ioctl with both write and read parameters.
 * ....
 */
/* Take an int, increment it. */
#define LKMC_IOCTL_PREPARE     _IOWR(LKMC_IOCTL_MAGIC, 0, int)
#define LKMC_IOCTL_OBSERVE     _IOWR(LKMC_IOCTL_MAGIC, 1, lisa_ioctl_struct)

#endif