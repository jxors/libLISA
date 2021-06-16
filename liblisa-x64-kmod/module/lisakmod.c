#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <linux/swap.h>
#include <linux/signal.h>
#include <linux/uio.h>
#include <linux/pid_namespace.h>
#include <linux/userfaultfd_k.h>
#include <linux/rbtree_augmented.h>
#include <linux/mempolicy.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <asm/switch_to.h>
#include <linux/kallsyms.h>
#include <linux/printk.h> /* printk */
#include <asm/uaccess.h> /* copy_from_user, copy_to_user */

/*
!!! WARNING: The code below is scary. It will probably break when you update the kernel version. It has only been tested on the 5.8.0-55-generic default ubuntu kernel. !!!

The code starts with ~700 lines copy-pasted from the kernel source code. Function calls that are not exported are accessed by 
guessing their addresses at runtime. The bash script genalladdrs.sh can be used to generate base addresses from a System.map file.

The actual code defines two ioclts: one to wipe all mapped memory from a process (it does have to be a child process, which should 
make it slightly harder for attackers to abuse. You probably still don't want to run this on a system that also runs untrusted code),
and one ioctl to do an 'observation', which consists of unmapping some memory, mapping new memory, setting registers, executing a single
step, checking the result (sigsegv? sigtrap? something else?), checking registers, and finally returning to the userspace code.

Since this one syscall combines 10+ syscalls that would otherwise have to be done over two different processes, it speeds up the 
observations.

I did not try to make this code look nice, nor did I try to fully understand how the kernel maps memory. I just copied things until
it worked. While you *can* use this code freely under the GPL, I'd strongly recommend that you *don't*. Besides general hackyness
of the code, it probably also contains security issues and bugs that you do not want on your system.
*/

#include "lisakmod.h"
static struct proc_dir_entry *lisa_file;

#define mmap_min_addr 0

// TODO: Including this because I have no idea which header I'd need to import for this
/* Nonzero if STATUS indicates the child is stopped.  */

/* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
#define	__WEXITSTATUS(status)	(((status) & 0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define	__WTERMSIG(status)	((status) & 0x7f)

/* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
#define	__WSTOPSIG(status)	__WEXITSTATUS(status)

/* Nonzero if STATUS indicates normal termination.  */
#define	__WIFEXITED(status)	(__WTERMSIG(status) == 0)

/* Nonzero if STATUS indicates termination by a signal.  */
#define __WIFSIGNALED(status) \
  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child is stopped.  */
#define	__WIFSTOPPED(status)	(((status) & 0xff) == 0x7f)

/* Nonzero if STATUS indicates the child continued after a stop.  We only
   define this if <bits/waitflags.h> provides the WCONTINUED flag bit.  */
#ifdef WCONTINUED
# define __WIFCONTINUED(status)	((status) == __W_CONTINUED)
#endif

/* Nonzero if STATUS indicates the child dumped core.  */
#define	__WCOREDUMP(status)	((status) & __WCOREFLAG)

/* Macros for constructing status values.  */
#define	__W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#define	__W_STOPCODE(sig)	((sig) << 8 | 0x7f)
#define __W_CONTINUED		0xffff
#define	__WCOREFLAG		0x80

# define WEXITSTATUS(status)	__WEXITSTATUS (status)
# define WTERMSIG(status)	__WTERMSIG (status)
# define WSTOPSIG(status)	__WSTOPSIG (status)
# define WIFEXITED(status)	__WIFEXITED (status)
# define WIFSIGNALED(status)	__WIFSIGNALED (status)
# define WIFSTOPPED(status)	__WIFSTOPPED (status)

struct waitid_info {
	pid_t pid;
	uid_t uid;
	int status;
	int cause;
};

struct wait_opts {
	enum pid_type		wo_type;
	int			wo_flags;
	struct pid		*wo_pid;

	struct waitid_info	*wo_info;
	int			wo_stat;
	struct rusage		*wo_rusage;

	wait_queue_entry_t		child_wait;
	int			notask_error;
};

#include "symbol_addrs.h"

static int (*invoke_do_munmap)(struct mm_struct *mm, unsigned long start, size_t len, struct list_head *uf);
static int (*invoke_shmem_zero_setup)(struct vm_area_struct *vma);
static void (*invoke_vma_link)(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent);
static void (*invoke_perf_event_mmap)(struct vm_area_struct *vma);
static void (*invoke_unmap_region)(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end);
static void (*invoke___audit_mmap_fd)(int fd, int flags);
static int (*invoke___mm_populate)(unsigned long addr, unsigned long len,
			 int ignore_errors);
static void (*invoke_userfaultfd_unmap_complete)(struct mm_struct *mm, struct list_head *uf);
static int (*invoke_security_mmap_file)(struct file *file, unsigned long prot,
			unsigned long flags);
static int (*invoke_locks_mandatory_locked)(struct file *file);
static void (*invoke_vm_area_free)(struct vm_area_struct *);
static struct vm_area_struct *(*invoke_get_gate_vma)(struct mm_struct *mm);
static struct vm_area_struct *(*invoke_vm_area_alloc)(struct mm_struct *);
static void (*invoke_vma_set_page_prot)(struct vm_area_struct *vma);
static int (*invoke_uprobe_mmap)(struct vm_area_struct *vma);
static void (*invoke_vm_stat_account)(struct mm_struct *, vm_flags_t, long npages);
static struct vm_area_struct *(*invoke_vma_merge)(struct mm_struct *,
	struct vm_area_struct *prev, unsigned long addr, unsigned long end,
	unsigned long vm_flags, struct anon_vma *, struct file *, pgoff_t,
	struct mempolicy *, struct vm_userfaultfd_ctx);
static int (*invoke_security_vm_enough_memory_mm)(struct mm_struct *mm, long pages);
static bool (*invoke_is_file_shm_hugepages)(struct file *file);
static bool (*invoke_may_expand_vm)(struct mm_struct *, vm_flags_t, unsigned long npages);
static void (*invoke_vm_unacct_memory)(long pages);
static int (*invoke_ptrace_check_attach)(struct task_struct *child, bool ignore_state);
static int (*invoke_ptrace_regset)(struct task_struct *task, int req, unsigned int type,
			 struct iovec *kiov);
static int (*invoke_ptrace_resume)(struct task_struct *child, long request,
			 unsigned long data);
static int (*invoke_ptrace_getsiginfo)(struct task_struct *child, kernel_siginfo_t *info);
static long (*invoke_do_wait)(struct wait_opts *wo);
static int (*invoke_wake_up_state)(struct task_struct *p, unsigned int state);


struct file_operations *ptr_hugetlbfs_file_operations;
int *ptr_sysctl_max_map_count;

static inline bool invoke_is_file_hugepages(struct file *file)
{
	if (file->f_op == ptr_hugetlbfs_file_operations)
		return true;

	return invoke_is_file_shm_hugepages(file);
}

static inline int invoke_locks_verify_locked(struct file *file)
{
	if (mandatory_lock(locks_inode(file)))
		return invoke_locks_mandatory_locked(file);
	return 0;
}

static inline void invoke_mm_populate(unsigned long addr, unsigned long len)
{
	/* Ignore errors */
	(void) invoke___mm_populate(addr, len, 1);
}

static inline void invoke_audit_mmap_fd(int fd, int flags)
{
	if (unlikely(!audit_dummy_context()))
		invoke___audit_mmap_fd(fd, flags);
}

static inline u64 file_mmap_size_max(struct file *file, struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISBLK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISSOCK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	/* Special "we do even unsigned file positions" case */
	if (file->f_mode & FMODE_UNSIGNED_OFFSET)
		return 0;

	/* Yes, random drivers might want more. But I'm tired of buggy drivers */
	return ULONG_MAX;
}

static inline int mlock_future_check(struct mm_struct *mm,
				     unsigned long flags,
				     unsigned long len)
{
	unsigned long locked, lock_limit;

	/*  mlock MCL_FUTURE? */
	if (flags & VM_LOCKED) {
		locked = len >> PAGE_SHIFT;
		locked += mm->locked_vm;
		lock_limit = rlimit(RLIMIT_MEMLOCK);
		lock_limit >>= PAGE_SHIFT;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}
	return 0;
}

static inline bool file_mmap_ok(struct file *file, struct inode *inode,
				unsigned long pgoff, unsigned long len)
{
	u64 maxsize = file_mmap_size_max(file, inode);

	if (maxsize && len > maxsize)
		return false;
	maxsize -= len;
	if (pgoff > maxsize >> PAGE_SHIFT)
		return false;
	return true;
}

static inline int execute_only_pkey(struct mm_struct *mm)
{
	// TODO: For now we just assume they are disabled
	return -1;
}

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < mmap_min_addr))
		return PAGE_ALIGN(mmap_min_addr);
	return hint;
}

/*
 * We account for memory if it's a private writeable mapping,
 * not hugepages and VM_NORESERVE wasn't set.
 */
static inline int accountable_mapping(struct file *file, vm_flags_t vm_flags)
{
	/*
	 * hugetlb has its own accounting separate from the core VM
	 * VM_HUGETLB may not be set yet so we cannot check for that flag.
	 */
	if (file && invoke_is_file_hugepages(file))
		return 0;

	return (vm_flags & (VM_NORESERVE | VM_SHARED | VM_WRITE)) == VM_WRITE;
}

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}

static unsigned long count_vma_pages_range(struct mm_struct *mm,
		unsigned long addr, unsigned long end)
{
	unsigned long nr_pages = 0;
	struct vm_area_struct *vma;

	/* Find first overlaping mapping */
	vma = find_vma_intersection(mm, addr, end);
	if (!vma)
		return 0;

	nr_pages = (min(end, vma->vm_end) -
		max(addr, vma->vm_start)) >> PAGE_SHIFT;

	/* Iterate over the rest of the overlaps */
	for (vma = vma->vm_next; vma; vma = vma->vm_next) {
		unsigned long overlap_len;

		if (vma->vm_start > end)
			break;

		overlap_len = min(end, vma->vm_end) - vma->vm_start;
		nr_pages += overlap_len >> PAGE_SHIFT;
	}

	return nr_pages;
}

unsigned long lisa_mmap_region(struct mm_struct *mm, struct file *file, unsigned long addr,
		unsigned long len, vm_flags_t vm_flags, unsigned long pgoff,
		struct list_head *uf)
{
	struct vm_area_struct *vma, *prev;
	int error;
	struct rb_node **rb_link, *rb_parent;
	unsigned long charged = 0;

	/* Check against address space limit. */
	if (!invoke_may_expand_vm(mm, vm_flags, len >> PAGE_SHIFT)) {
		unsigned long nr_pages;

		/*
		 * MAP_FIXED may remove pages of mappings that intersects with
		 * requested mapping. Account for the pages it would unmap.
		 */
		nr_pages = count_vma_pages_range(mm, addr, addr + len);

		if (!invoke_may_expand_vm(mm, vm_flags,
					(len >> PAGE_SHIFT) - nr_pages))
			return -ENOMEM;
	}

	/* Clear old maps */
	while (find_vma_links(mm, addr, addr + len, &prev, &rb_link,
			      &rb_parent)) {
		if (invoke_do_munmap(mm, addr, len, uf))
			return -ENOMEM;
	}

	/*
	 * Private writable mapping: check memory availability
	 */
	if (accountable_mapping(file, vm_flags)) {
		charged = len >> PAGE_SHIFT;
		if (invoke_security_vm_enough_memory_mm(mm, charged))
			return -ENOMEM;
		vm_flags |= VM_ACCOUNT;
	}

	/*
	 * Can we just expand an old mapping?
	 */
	vma = invoke_vma_merge(mm, prev, addr, addr + len, vm_flags,
			NULL, file, pgoff, NULL, NULL_VM_UFFD_CTX);
	if (vma)
		goto out;

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	vma = invoke_vm_area_alloc(mm);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	if (file) {
		if (vm_flags & VM_DENYWRITE) {
			error = deny_write_access(file);
			if (error)
				goto free_vma;
		}
		if (vm_flags & VM_SHARED) {
			error = mapping_map_writable(file->f_mapping);
			if (error)
				goto allow_write_and_free_vma;
		}

		/* ->mmap() can change vma->vm_file, but must guarantee that
		 * vma_link() below can deny write-access if VM_DENYWRITE is set
		 * and map writably if VM_SHARED is set. This usually means the
		 * new file must not have been exposed to user-space, yet.
		 */
		vma->vm_file = get_file(file);
		error = call_mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;

		/* Can addr have changed??
		 *
		 * Answer: Yes, several device drivers can do it in their
		 *         f_op->mmap method. -DaveM
		 * Bug: If addr is changed, prev, rb_link, rb_parent should
		 *      be updated for vma_link()
		 */
		WARN_ON_ONCE(addr != vma->vm_start);

		addr = vma->vm_start;
		vm_flags = vma->vm_flags;
	} else if (vm_flags & VM_SHARED) {
		error = invoke_shmem_zero_setup(vma);
		if (error)
			goto free_vma;
	} else {
		vma_set_anonymous(vma);
	}

	invoke_vma_link(mm, vma, prev, rb_link, rb_parent);
	/* Once vma denies write, undo our temporary denial count */
	if (file) {
		if (vm_flags & VM_SHARED)
			mapping_unmap_writable(file->f_mapping);
		if (vm_flags & VM_DENYWRITE)
			allow_write_access(file);
	}
	file = vma->vm_file;
out:
	invoke_perf_event_mmap(vma);

	invoke_vm_stat_account(mm, vm_flags, len >> PAGE_SHIFT);
	if (vm_flags & VM_LOCKED) {
		if ((vm_flags & VM_SPECIAL) || vma_is_dax(vma) ||
					is_vm_hugetlb_page(vma) ||
					vma == invoke_get_gate_vma(current->mm))
			vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
		else
			mm->locked_vm += (len >> PAGE_SHIFT);
	}

	if (file)
		invoke_uprobe_mmap(vma);

	/*
	 * New (or expanded) vma always get soft dirty status.
	 * Otherwise user-space soft-dirty page tracker won't
	 * be able to distinguish situation when vma area unmapped,
	 * then new mapped in-place (which must be aimed as
	 * a completely new data area).
	 */
	vma->vm_flags |= VM_SOFTDIRTY;

	invoke_vma_set_page_prot(vma);

	return addr;

unmap_and_free_vma:
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
	invoke_unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
	charged = 0;
	if (vm_flags & VM_SHARED)
		mapping_unmap_writable(file->f_mapping);
allow_write_and_free_vma:
	if (vm_flags & VM_DENYWRITE)
		allow_write_access(file);
free_vma:
	invoke_vm_area_free(vma);
unacct_error:
	if (charged)
		invoke_vm_unacct_memory(charged);
	return error;
}

unsigned long lisa_do_mmap(struct mm_struct *mm, struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vm_flags_t vm_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf)
{
	int pkey = 0;

	*populate = 0;

	if (!len)
		return -EINVAL;

	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we dont add PROT_EXEC.)
	 */
	// TODO: Incorrect use of current
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && path_noexec(&file->f_path)))
			prot |= PROT_EXEC;

	/* force arch specific MAP_FIXED handling in get_unmapped_area */
	if (flags & MAP_FIXED_NOREPLACE)
		flags |= MAP_FIXED;

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/* Too many mappings? */
	if (mm->map_count > *ptr_sysctl_max_map_count)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	// TODO: This uses current
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (flags & MAP_FIXED_NOREPLACE) {
		struct vm_area_struct *vma = find_vma(mm, addr);

		if (vma && vma->vm_start < addr + len)
			return -EEXIST;
	}

	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(mm);
		if (pkey < 0)
			pkey = 0;
	}

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags |= calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	if (flags & MAP_LOCKED)
		if (!can_do_mlock())
			return -EPERM;

	if (mlock_future_check(mm, vm_flags, len))
		return -EAGAIN;

	if (file) {
		struct inode *inode = file_inode(file);
		unsigned long flags_mask;

		if (!file_mmap_ok(file, inode, pgoff, len))
			return -EOVERFLOW;

		flags_mask = LEGACY_MAP_MASK | file->f_op->mmap_supported_flags;

		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			/*
			 * Force use of MAP_SHARED_VALIDATE with non-legacy
			 * flags. E.g. MAP_SYNC is dangerous to use with
			 * MAP_SHARED as you don't know which consistency model
			 * you will get. We silently ignore unsupported flags
			 * with MAP_SHARED to preserve backward compatibility.
			 */
			flags &= LEGACY_MAP_MASK;
			fallthrough;
		case MAP_SHARED_VALIDATE:
			if (flags & ~flags_mask)
				return -EOPNOTSUPP;
			if (prot & PROT_WRITE) {
				if (!(file->f_mode & FMODE_WRITE))
					return -EACCES;
				if (IS_SWAPFILE(file->f_mapping->host))
					return -ETXTBSY;
			}

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure there are no mandatory locks on the file.
			 */
			if (invoke_locks_verify_locked(file))
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);
			fallthrough;
		case MAP_PRIVATE:
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			if (path_noexec(&file->f_path)) {
				if (vm_flags & VM_EXEC)
					return -EPERM;
				vm_flags &= ~VM_MAYEXEC;
			}

			if (!file->f_op->mmap)
				return -ENODEV;
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
				return -EINVAL;
			break;

		default:
			return -EINVAL;
		}
	} else {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
				return -EINVAL;
			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
		case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	/*
	 * Set 'VM_NORESERVE' if we should not account for the
	 * memory use of this mapping.
	 */
	if (flags & MAP_NORESERVE) {
		// ! Don't care: MAP_NORESERVE
		return -EINVAL;
	}

	addr = lisa_mmap_region(mm, file, addr, len, vm_flags, pgoff, uf);
	if (!IS_ERR_VALUE(addr) &&
	    ((vm_flags & VM_LOCKED) ||
	     (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
		*populate = len;
	return addr;
}

static inline unsigned long
lisa_do_mmap_pgoff(struct mm_struct *mm, struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot, unsigned long flags,
	unsigned long pgoff, unsigned long *populate,
	struct list_head *uf)
{
	return lisa_do_mmap(mm, file, addr, len, prot, flags, 0, pgoff, populate, uf);
}

unsigned long lisa_vm_mmap_pgoff(struct mm_struct *mm, struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	unsigned long populate;
	LIST_HEAD(uf);

	ret = invoke_security_mmap_file(file, prot, flag);
	if (!ret) {
		if (mmap_write_lock_killable(mm))
			return -EINTR;
		ret = lisa_do_mmap_pgoff(mm, file, addr, len, prot, flag, pgoff,
				    &populate, &uf);
		mmap_write_unlock(mm);
		invoke_userfaultfd_unmap_complete(mm, &uf);
		if (populate)
			invoke_mm_populate(ret, populate);
	}
	return ret;
}

unsigned long lisa_mmap_pgoff(struct mm_struct *mm, unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd, unsigned long pgoff)
{
	struct file *file = NULL;
	unsigned long retval;

	if (!(flags & MAP_ANONYMOUS)) {
		invoke_audit_mmap_fd(fd, flags);
		file = fget(fd);
		if (!file)
			return -EBADF;
		if (invoke_is_file_hugepages(file)) {
			// ! Don't care: huge pages
			retval = -EINVAL;
			goto out_fput;
		}

		retval = -EINVAL;
		if (unlikely(flags & MAP_HUGETLB && !invoke_is_file_hugepages(file)))
			goto out_fput;
	} else if (flags & MAP_HUGETLB) {
		// ! Don't care: huge pages
		retval = -EINVAL;
		goto out_fput;
		// struct user_struct *user = NULL;
		// struct hstate *hs;

		// hs = hstate_sizelog((flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		// if (!hs)
		// 	return -EINVAL;

		// len = ALIGN(len, huge_page_size(hs));
		// /*
		//  * VM_NORESERVE is used because the reservations will be
		//  * taken when vm_ops->mmap() is called
		//  * A dummy user value is used because we are not locking
		//  * memory so no accounting is necessary
		//  */
		// file = hugetlb_file_setup(HUGETLB_ANON_FILE, len,
		// 		VM_NORESERVE,
		// 		&user, HUGETLB_ANONHUGE_INODE,
		// 		(flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		// if (IS_ERR(file))
		// 	return PTR_ERR(file);
	}

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

	retval = lisa_vm_mmap_pgoff(mm, file, addr, len, prot, flags, pgoff);
out_fput:
	if (file)
		fput(file);
	return retval;
}

int lisa_munmap(struct mm_struct *mm, unsigned long start, size_t len) {
	int ret = 0;
	LIST_HEAD(uf);
	if (mmap_write_lock_killable(mm))
		return -EINTR;
	
	ret = invoke_do_munmap(mm, start, len, &uf);

	/*
	 * Returning 1 indicates mmap_lock is downgraded.
	 * But 1 is not legal return value of vm_munmap() and munmap(), reset
	 * it to 0 before return.
	 */
	if (ret == 1) {
		mmap_read_unlock(mm);
		ret = 0;
	} else
		mmap_write_unlock(mm);

	return ret;
}

static long cmd_prepare(int pid) 
{
	long ret = 0;
	struct pid *pid_struct;
    struct task_struct *child;
	LIST_HEAD(uf);

	pr_info("Preparing pid = %d\n", pid);
	pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		pr_info("Preparation failed: could not find pid\n");
		ret = -ESRCH;
		goto out;
	}

	child = pid_task(pid_struct, PIDTYPE_PID);
	if (!child) {
		pr_info("Preparation failed: could not find task\n");
		ret = -ESRCH;
		goto out;
	}

	if (child->parent != current) {
		pr_info("Preparation failed: pid is not a child process\n");
		ret = -EPERM;
		goto out;
	}

	ret = lisa_munmap(child->mm, 0, 0x7fffff000000);

	if (ret != 0) {
		pr_info("Preparation failed: munmap returned an error: %ld\n", ret);
	} else {
		pr_info("Preparation OK\n");
	}

out:
	return ret;
}

static long ptrace_enter(struct pid *pid_struct, struct task_struct **child) {
	long ret = 0;
	*child = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!*child) {
		ret = -ESRCH;
		goto out;
	}

	if ((*child)->parent != current) {
		ret = -EPERM;
		goto out_put_task;
	}

	if ((ret = invoke_ptrace_check_attach(*child, false)) < 0) {
		goto out_put_task;
	}

	return ret;

out_put_task:
	put_task_struct(*child);

out:
	return ret;
}

static void ptrace_exit(struct task_struct **child) {
	struct task_struct *task = *child;
	if (task->state != __TASK_TRACED)
		return;

	WARN_ON(!task->ptrace || task->parent != current);

	/*
	 * PTRACE_LISTEN can allow ptrace_trap_notify to wake us up remotely.
	 * Recheck state under the lock to close this race.
	 */
	spin_lock_irq(&task->sighand->siglock);
	if (task->state == __TASK_TRACED) {
		if (__fatal_signal_pending(task))
			invoke_wake_up_state(task, __TASK_TRACED);
		else
			task->state = TASK_TRACED;
	}
	spin_unlock_irq(&task->sighand->siglock);

	put_task_struct(task);
	*child = NULL;
}

static long cmd_observe(lisa_ioctl_struct *data) 
{
	long ret = 0, waitret;
	struct pid *pid_struct;
    struct task_struct *child;
	struct wait_opts wo;
	lisa_observe_result_t lisa_result;
	enum pid_type type;
	size_t i;
	struct iovec iov;
	kernel_siginfo_t siginfo;
	LIST_HEAD(uf);

	// Make sure we don't accidentally return (potentially sensitive) data from the stack.
	lisa_result.optional_addr = 0;
	lisa_result.si_code = 0;
	lisa_result.si_errno = 0;
	lisa_result.si_signo = 0;

	// pr_info("Observing pid = %d\n", data->pid);
	pid_struct = find_get_pid(data->pid);
	if (!pid_struct) {
		ret = -ESRCH;
		goto out;
	}

	ptrace_enter(pid_struct, &child);
	if (ret != 0) {
		goto out;
	}

	// pr_info("Observe: ptrace attach to %d\n", data->pid);

	// unmap old memory
	for (i = 0; i < data->num_unmaps; i++) {
		ret = lisa_munmap(child->mm, data->unmaps[i].addr, PAGE_SIZE);

		if (ret != 0) {
			pr_warn("Observe: unmap at 0x%llx failed\n", data->unmaps[i].addr);
			goto out_unfreeze;
		}
	}

	// map new memory
	for (i = 0; i < data->num_maps; i++) {
		ret = lisa_mmap_pgoff(child->mm, data->maps[i].addr, PAGE_SIZE, data->maps[i].prot, data->mapping_flags, data->maps[i].fd, 0);

		if (ret < 0) {
			pr_warn("Observe: mmap at 0x%llx failed\n", data->maps[i].addr);
			goto out_unfreeze;
		}
	}

	// set basic registers
	iov.iov_base = data->regs;
	iov.iov_len = ELF_NGREG * sizeof(elf_greg_t);
	ret = invoke_ptrace_regset(child, PTRACE_SETREGSET, NT_PRSTATUS, &iov);
	if (ret != 0) {
		pr_warn("Observe: PTRACE_SETREGSET failed\n");
		goto out_unfreeze;
	}
	
	// optional: set debugging registers
	// future work: set XSTATE

	do {
		// Do a single step
		ret = invoke_ptrace_resume(child, PTRACE_SINGLESTEP, 0);
		if (ret != 0) {
			pr_warn("Observe: ptrace_resume returned %ld\n", ret);
			goto out_unfreeze;
		}

		ptrace_exit(&child);

		// waitpid()
		wo.wo_type	= type;
		wo.wo_pid	= pid_struct;
		wo.wo_flags	= WEXITED;
		wo.wo_info	= NULL;
		wo.wo_stat	= 0;
		wo.wo_rusage = NULL;
		waitret = invoke_do_wait(&wo);

		ret = ptrace_enter(pid_struct, &child);
		if (ret != 0) {
			pr_warn("Observe: could not re-enter for single step, ret = %ld\n", ret);
			goto out;
		}
	} while (waitret != -1 && waitret > 0 && WIFSTOPPED(wo.wo_stat) && (WSTOPSIG(wo.wo_stat) == SIGINT || WSTOPSIG(wo.wo_stat) == SIGWINCH));

	lisa_result.status = wo.wo_stat;
	if (waitret == -1) {
		// waitpid failed
		goto out;
	}

	if (waitret > 0) {
		if (WIFSTOPPED(wo.wo_stat) && WSTOPSIG(wo.wo_stat) == SIGTRAP) {
			// triggered after doing a single step
			// get basic registers
			// 			+ future work XSTATE
			iov.iov_base = data->regs;
			iov.iov_len = ELF_NGREG * sizeof(elf_greg_t);
			ret = invoke_ptrace_regset(child, PTRACE_GETREGSET, NT_PRSTATUS, &iov);

			if (ret != 0) {
				pr_warn("Observe: ptrace_getregset failed\n");
				goto out_unfreeze;
			}
		} else {
			// if signal, fetch signal info
			// pr_info("Observe: fetching signal info %d\n", data->pid);
			ret = invoke_ptrace_getsiginfo(child, (kernel_siginfo_t*)&siginfo);
			lisa_result.si_code = siginfo.si_code;
			lisa_result.si_errno = siginfo.si_errno;
			lisa_result.si_signo = siginfo.si_signo;
			lisa_result.optional_addr = (uint64_t)siginfo.si_addr;
			if (ret != 0) {
				goto out_unfreeze;
			}
		}
	}

	if (copy_to_user(data->result, &lisa_result, sizeof(lisa_observe_result_t))) {
		return -EFAULT;
	}

	// pr_info("Observe: completed successfully\n");
out_unfreeze:
	ptrace_exit(&child);

out:
	return ret;
}

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp)
{
	void __user *arg_user;
	union {
		int pid;
		lisa_ioctl_struct command_data;
	} arg_kernel;

	arg_user = (void __user *)argp;
	
	switch (cmd) {
		case LKMC_IOCTL_PREPARE:
			if (copy_from_user(&arg_kernel.pid, arg_user, sizeof(arg_kernel.pid))) {
				return -EFAULT;
			}

			return cmd_prepare(arg_kernel.pid);
		case LKMC_IOCTL_OBSERVE:
			if (copy_from_user(&arg_kernel.command_data, arg_user, sizeof(arg_kernel.command_data))) {
				return -EFAULT;
			}

			return cmd_observe(&arg_kernel.command_data);
		break;
		default:
			return -EINVAL;
		break;
	}

	return 0;
}

static const struct proc_ops fops = {
	// .owner = THIS_MODULE,
	.proc_ioctl = unlocked_ioctl
};

static int myinit(void)
{
	void *base_addr, *fn_addr_offset;
	/* ioctl permissions are not automatically restricted by rwx as for read / write,
	 * but we could of course implement that ourselves:
	 * https://stackoverflow.com/questions/29891803/user-permission-check-on-ioctl-command */
	lisa_file = proc_create("lisa", 0666, NULL, &fops);

	base_addr = (void*)&vm_munmap;
	fn_addr_offset = base_addr - VM_MUNMAP_ADDR;

	pr_info("Function pointer offset = %llx (%llx - %llx)\n", (uint64_t)fn_addr_offset, (uint64_t)base_addr, (uint64_t)VM_MUNMAP_ADDR);

	invoke_do_munmap = DO_MUNMAP_ADDR + fn_addr_offset;
	invoke_shmem_zero_setup = SHMEM_ZERO_SETUP_ADDR + fn_addr_offset;
	invoke_vma_link = VMA_LINK_ADDR + fn_addr_offset;
	invoke_perf_event_mmap = PERF_EVENT_MMAP_ADDR + fn_addr_offset;
	invoke_unmap_region = UNMAP_REGION_ADDR + fn_addr_offset;
	invoke___audit_mmap_fd = __AUDIT_MMAP_FD_ADDR + fn_addr_offset;
	invoke___mm_populate = __MM_POPULATE_ADDR + fn_addr_offset;
	invoke_userfaultfd_unmap_complete = USERFAULTFD_UNMAP_COMPLETE_ADDR + fn_addr_offset;
	invoke_security_mmap_file = SECURITY_MMAP_FILE_ADDR + fn_addr_offset;
	invoke_locks_mandatory_locked = LOCKS_MANDATORY_LOCKED_ADDR + fn_addr_offset;
	invoke_vm_area_free = VM_AREA_FREE_ADDR + fn_addr_offset;
	invoke_get_gate_vma = GET_GATE_VMA_ADDR + fn_addr_offset;
	invoke_vm_area_alloc = VM_AREA_ALLOC_ADDR + fn_addr_offset;
	invoke_vma_set_page_prot = VMA_SET_PAGE_PROT_ADDR + fn_addr_offset;
	invoke_uprobe_mmap = UPROBE_MMAP_ADDR + fn_addr_offset;
	invoke_vm_stat_account = VM_STAT_ACCOUNT_ADDR + fn_addr_offset;
	invoke_vma_merge = VMA_MERGE_ADDR + fn_addr_offset;
	invoke_security_vm_enough_memory_mm = SECURITY_VM_ENOUGH_MEMORY_MM_ADDR + fn_addr_offset;
	invoke_is_file_shm_hugepages = IS_FILE_SHM_HUGEPAGES_ADDR + fn_addr_offset;
	invoke_may_expand_vm = MAY_EXPAND_VM_ADDR + fn_addr_offset;
	invoke_vm_unacct_memory = VM_UNACCT_MEMORY_ADDR + fn_addr_offset;
	invoke_ptrace_check_attach = PTRACE_CHECK_ATTACH_ADDR + fn_addr_offset;
	invoke_ptrace_regset = PTRACE_REGSET_ADDR + fn_addr_offset;
	invoke_ptrace_resume = PTRACE_RESUME_ADDR + fn_addr_offset;
	invoke_ptrace_getsiginfo = PTRACE_GETSIGINFO_ADDR + fn_addr_offset;
	invoke_do_wait = DO_WAIT_ADDR + fn_addr_offset;
	invoke_wake_up_state = WAKE_UP_STATE_ADDR + fn_addr_offset;
	 
	ptr_hugetlbfs_file_operations = HUGETLBFS_FILE_OPERATIONS_ADDR + fn_addr_offset;
	ptr_sysctl_max_map_count = SYSCTL_MAX_MAP_COUNT_ADDR + fn_addr_offset;

	return 0;
}

static void myexit(void)
{
	proc_remove(lisa_file);
}

module_init(myinit)
module_exit(myexit)
MODULE_LICENSE("GPL");