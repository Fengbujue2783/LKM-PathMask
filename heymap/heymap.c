// heymap.ko - dedicated /proc/self/maps fd swapper for the heytea packer.
// Pure mainline kernel APIs: kretprobe on __x64_sys_openat, swap the fd of
// its own maps to a faker file for selected uids. No kallsyms recovery, no
// path-hiding, no KallRecon dependency.
#define pr_fmt(fmt) "heymap: " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/cred.h>

static char fake_path[256];
module_param_string(fake_path, fake_path, sizeof(fake_path), 0444);
MODULE_PARM_DESC(fake_path, "file served for maps opens");

static char maps_uids[512];
module_param_string(maps_uids, maps_uids, sizeof(maps_uids), 0444);
MODULE_PARM_DESC(maps_uids, "comma UIDs to redirect");

static char probe_only[8] = "0";
module_param_string(probe_only, probe_only, sizeof(probe_only), 0444);
MODULE_PARM_DESC(probe_only, "1 = log matches but do not swap (canary mode)");

#define MAX_UIDS 64
static uid_t uid_list[MAX_UIDS];
static unsigned int uid_count;
static atomic_t fired_once = ATOMIC_INIT(0);

struct hd {
	bool redirect;
	long bad;
};

static bool uid_ok(uid_t u)
{
	unsigned int i;
	for (i = 0; i < uid_count; i++)
		if (uid_list[i] == u)
			return true;
	return false;
}

static bool user_path_is_own_maps(const char __user *uptr)
{
	char buf[64];
	long n;
	char *end;
	unsigned long pid;

	n = strncpy_from_user(buf, uptr, sizeof(buf) - 1);
	if (n <= 0)
		return false;
	buf[n] = 0;

	if (strncmp(buf, "/proc/self/", 11) == 0)
		return strcmp(buf + 11, "maps") == 0;

	if (strncmp(buf, "/proc/", 6) == 0) {
		pid = simple_strtoul(buf + 6, &end, 10);
		if (end && *end == '/' && strcmp(end + 1, "maps") == 0)
			return pid == (unsigned long)task_tgid_nr(current);
	}
	return false;
}

static int hxp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hd *d = (struct hd *)ri->data;
	struct pt_regs *u = (struct pt_regs *)regs->di;

	d->redirect = false;
	d->bad = 0;

	if (!fake_path[0] || !uid_count)
		return 0;
	if (!uid_ok(__kuid_val(current_uid())))
		return 0;
	if (!u || !user_path_is_own_maps((const char __user *)(unsigned long)u->si))
		return 0;

	if (atomic_cmpxchg(&fired_once, 0, 1) == 0)
		pr_info("match: uid=%u maps open intercepted\n",
			__kuid_val(current_uid()));
	d->redirect = true;
	return 0;
}

static int hxp_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hd *d = (struct hd *)ri->data;
	long ret = (long)regs->ax;
	struct file *fk;
	int nfd;

	if (!d->redirect || ret < 0)
		return 0;

	if (probe_only[0] == '1') {
		pr_info("canary: maps open succ fd=%ld, NOT swapped\n", ret);
		return 0;
	}

	fk = filp_open(fake_path, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(fk)) {
		pr_warn_ratelimited("faker open failed %ld\n", PTR_ERR(fk));
		return 0;
	}

	nfd = get_unused_fd_flags(0);
	if (nfd < 0) {
		filp_close(fk, NULL);
		return 0;
	}

	/* release the descriptor the syscall allocated for real maps */
	close_fd((unsigned int)ret);
	fd_install(nfd, fk);
	regs->ax = (unsigned long)nfd;
	pr_info("swapped fd %ld -> %d (%s)\n", ret, nfd, fake_path);
	return 0;
}

static struct kretprobe kp = {
	.kp.symbol_name = "__x64_sys_openat",
	.entry_handler	= hxp_entry,
	.handler	= hxp_exit,
	.data_size	= sizeof(struct hd),
	.maxactive	= 32,
};

static int parse_uids(void)
{
	char *buf, *cur, *item;

	if (!maps_uids[0]) {
		pr_warn("no maps_uids given; module is a no-op\n");
		return 0;
	}

	buf = kstrdup(maps_uids, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cur = buf;
	while ((item = strsep(&cur, ",")) != NULL) {
		unsigned int v;
		int r;

		item = strim(item);
		if (!*item)
			continue;
		r = kstrtouint(item, 10, &v);
		if (r) {
			pr_warn("bad uid token '%s'\n", item);
			continue;
		}
		if (uid_count >= MAX_UIDS) {
			pr_warn("uid list full, drop %u\n", v);
			break;
		}
		uid_list[uid_count++] = (uid_t)v;
	}
	kfree(buf);

	pr_info("armed for %u uid(s), faker=%s, probe_only=%s\n",
		uid_count, fake_path, probe_only);
	return 0;
}

static int __init heymap_init(void)
{
	int ret;

	ret = parse_uids();
	if (ret)
		return ret;

	if (!fake_path[0]) {
		pr_err("fake_path required\n");
		return -EINVAL;
	}

	ret = register_kretprobe(&kp);
	if (ret) {
		pr_err("register_kretprobe failed: %d\n", ret);
		return ret;
	}

	pr_info("loaded: hook __x64_sys_openat, %u uid(s)\n", uid_count);
	return 0;
}

static void __exit heymap_exit(void)
{
	unregister_kretprobe(&kp);
	pr_info("unloaded\n");
}

module_init(heymap_init);
module_exit(heymap_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("heytea maps fd swapper");
MODULE_AUTHOR("local");
