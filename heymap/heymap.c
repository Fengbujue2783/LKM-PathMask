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
#include <linux/kobject.h>

static char fake_path[256];
module_param_string(fake_path, fake_path, sizeof(fake_path), 0644);
MODULE_PARM_DESC(fake_path, "file served for maps opens");

static char probe_only[8] = "1";
module_param_string(probe_only, probe_only, sizeof(probe_only), 0644);
MODULE_PARM_DESC(probe_only, "1 = log matches but do not swap (canary mode)");

#define MAX_UIDS 64
static uid_t uid_list[MAX_UIDS];
static unsigned int uid_count;
static atomic_t fired_once = ATOMIC_INIT(0);

static char maps_uids[512];

static void rebuild_uid_list(void)
{
	char *buf, *cur, *item;
	unsigned int n = 0;

	uid_count = 0;
	if (!maps_uids[0])
		return;

	buf = kstrdup(maps_uids, GFP_KERNEL);
	if (!buf)
		return;

	cur = buf;
	while ((item = strsep(&cur, ",")) != NULL && n < MAX_UIDS - 1) {
		unsigned int v;
		int r;

		item = strim(item);
		if (!*item)
			continue;
		r = kstrtouint(item, 10, &v);
		if (r)
			continue;
		uid_list[uid_count++] = (uid_t)v;
	}
	kfree(buf);
}

static int set_maps_uids(const char *val, const struct kernel_param *kp)
{
	(void)kp;
	if (!val)
		return -EINVAL;
	strscpy(maps_uids, val ? val : "", sizeof(maps_uids));
	rebuild_uid_list();
	pr_info("uids set via sysfs: '%s' -> %u uid(s)\n",
		maps_uids, uid_count);
	return 0;
}

static int get_maps_uids(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%s", maps_uids);
}

static const struct kernel_param_ops maps_uids_ops = {
	.set = set_maps_uids,
	.get = get_maps_uids,
};

module_param_cb(maps_uids, &maps_uids_ops, NULL, 0644);
MODULE_PARM_DESC(maps_uids, "comma UIDs to redirect (sysfs-writable)");

struct hd {
	bool redirect;
	bool is_exe;
	bool is_auxv;
	bool is_enoent;
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
	char buf[96];
	long n;
	char *end;
	unsigned long pid;

	n = strncpy_from_user(buf, uptr, sizeof(buf) - 1);
	if (n <= 0)
		return false;
	buf[n] = 0;

	if (strstr(buf, "libhoudini.so") || strstr(buf, "libhp15_x86_64.so") ||
	    strstr(buf, "javahelper/libs/x86_64") ||
	    strstr(buf, "libjavahelper.so") || strstr(buf, "mumu-configs")) {
		d->is_enoent = true;
		return true;
	}

	if (strncmp(buf, "/proc/self/", 11) == 0) {
		const char *f = buf + 11;

		if (strcmp(f, "maps") == 0 || strcmp(f, "exe") == 0 ||
		    strcmp(f, "auxv") == 0 || strcmp(f, "status") == 0 ||
		    strcmp(f, "mountinfo") == 0 || strcmp(f, "mounts") == 0)
			return true;
		if (strncmp(f, "net/", 4) == 0 &&
		    (strcmp(f + 4, "unix") == 0 || strcmp(f + 4, "tcp") == 0 ||
		     strcmp(f + 4, "tcp6") == 0))
			return true;
		return false;
	}

	if (strcmp(buf, "/proc/mounts") == 0 ||
	    strcmp(buf, "/proc/self/mounts") == 0)
		return true;

	if (strncmp(buf, "/proc/", 6) == 0) {
		pid = simple_strtoul(buf + 6, &end, 10);
		if (end && *end == '/') {
			const char *f = end + 1;

			if (pid != (unsigned long)task_tgid_nr(current))
				return false;
			if (strcmp(f, "maps") == 0 || strcmp(f, "status") == 0 ||
			    strcmp(f, "mountinfo") == 0 || strcmp(f, "exe") == 0)
				return true;
		}
	}
	return false;
}

#define AUDIT_SLOTS 128
#define AUDIT_PLEN 96
static char audit_buf[AUDIT_SLOTS][AUDIT_PLEN];
static unsigned int audit_pos;

static void audit_path(const char *buf)
{
    unsigned int i = audit_pos & (AUDIT_SLOTS - 1);
    int n;

    n = strscpy(audit_buf[i], buf, AUDIT_PLEN);
    if (n < 0)
        n = AUDIT_PLEN - 1;
    audit_buf[i][AUDIT_PLEN - 1] = 0;
    audit_pos++;
    if ((audit_pos & 15) == 1)
        pr_warn("AUDIT[%u] %s\n", audit_pos, buf);
}

static ssize_t audit_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
    ssize_t n = 0;
    unsigned int i, t = audit_pos;

    if (t > AUDIT_SLOTS)
        t = AUDIT_SLOTS;
    for (i = 0; i < t; i++) {
        unsigned int idx = (audit_pos - t + i) & (AUDIT_SLOTS - 1);
        n += scnprintf(b + n, PAGE_SIZE - n, "%u\t%s\n",
                       audit_pos - t + i, audit_buf[idx]);
        if (n >= PAGE_SIZE - AUDIT_PLEN)
            break;
    }
    return n;
}

static struct kobj_attribute audit_attr = __ATTR(heymap_audit, 0444, audit_show, NULL);

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
	if (!u)
		return 0;
	{
		char ab[AUDIT_PLEN];
		long an = strncpy_from_user(ab, (const char __user *)(unsigned long)u->si, AUDIT_PLEN - 1);

		if (an > 0) {
			ab[an] = 0;
			audit_path(ab);
			if (audit_pos - 1 < 0x1000000) { /* keep audit cheap */ }
			d->is_exe = strncmp(ab, "/proc/self/exe", 15) == 0;
			d->is_auxv = strncmp(ab, "/proc/self/auxv", 16) == 0;
			d->is_enoent = strstr(ab, "libhoudini.so") != NULL ||
				strstr(ab, "libhp15_x86_64.so") != NULL ||
				strstr(ab, "javahelper/libs/x86_64") != NULL ||
				strstr(ab, "mumu-configs") != NULL;
		}
	}
	if (!user_path_is_own_maps((const char __user *)(unsigned long)u->si))
		return 0;

	if (atomic_cmpxchg(&fired_once, 0, 1) == 0)
		pr_info("match: uid=%u proc open intercepted\n",
			__kuid_val(current_uid()));
	d->redirect = true;
	return 0;
}

static int hxp_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hd *d = (struct hd *)ri->data;
	long ret = (long)regs->ax;
	char fpath[320];
	char cpath[AUDIT_PLEN];
	long cn;
	struct file *fk;
	int nfd;

	if (!d->redirect || ret < 0)
		return 0;

	if (d->is_enoent) {
		if (pm_close_fd)
			pm_close_fd((unsigned int)ret);
		regs->ax = (unsigned long)-2; /* ENOENT: file does not exist */
		return 0;
	}

	cn = strncpy_from_user(cpath, (const char __user *)(unsigned long)((struct pt_regs *)regs->di)->si, AUDIT_PLEN - 1);
	if (cn <= 0) {
		cpath[0] = 0;
	} else {
		cpath[cn] = 0;
	}

	/* dispatch by requested path */
	if (strstr(cpath, "/exe"))
		strscpy(fpath, "/data/local/tmp/fakes/exe", sizeof(fpath));
	else if (strstr(cpath, "/auxv"))
		strscpy(fpath, "/data/local/tmp/fakes/auxv", sizeof(fpath));
	else if (strstr(cpath, "/status"))
		strscpy(fpath, "/data/local/tmp/fakes/status", sizeof(fpath));
	else if (strstr(cpath, "/net/unix"))
		strscpy(fpath, "/data/local/tmp/fakes/net_unix", sizeof(fpath));
	else if (strstr(cpath, "/net/tcp") && !strstr(cpath, "tcp6"))
		strscpy(fpath, "/data/local/tmp/fakes/net_unix", sizeof(fpath));
	else if (strstr(cpath, "/mounts") || strstr(cpath, "/mountinfo"))
		strscpy(fpath, "/data/local/tmp/fakes/mounts", sizeof(fpath));
	else
		strscpy(fpath, fake_path, sizeof(fpath));

	if (probe_only[0] == '1') {
		pr_info("canary: open succ fd=%ld -> %s NOT swapped\n", ret, fpath);
		return 0;
	}

	fk = filp_open(fpath, O_RDONLY | O_LARGEFILE, 0);
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
	pr_info("swapped fd %ld -> %d (%s)\n", ret, nfd, fpath);
	return 0;
}

static struct kretprobe kp = {
	.kp.symbol_name = "__x64_sys_openat",
	.entry_handler	= hxp_entry,
	.handler	= hxp_exit,
	.data_size	= sizeof(struct hd),
	.maxactive	= 32,
};

static int __init heymap_init(void)
{
	int ret;

	rebuild_uid_list();

	if (!fake_path[0]) {
		pr_err("fake_path required\n");
		return -EINVAL;
	}

	ret = register_kretprobe(&kp);
	if (ret) {
		pr_err("register_kretprobe failed: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_file(kernel_kobj, &audit_attr.attr);
	if (ret)
		pr_warn("audit sysfs failed %d\n", ret);

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
