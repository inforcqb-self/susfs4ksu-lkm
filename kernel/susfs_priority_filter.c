// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_priority_filter.c - hide selected app uids from the priority syscalls
 *
 * getpriority/setpriority (kernel/sys.c) and ioprio_get/ioprio_set (block/ioprio.c) answer
 * -ESRCH for a uid that has no processes, so an app can call getpriority(PRIO_USER, uid) for
 * a range of uids and read back which apps are installed/running.  Upstream susfs
 * (simonpunk/susfs4ksu 35cbfe11) patches those functions in-tree to answer -ESRCH for a
 * user-selected uid before find_user().  An LKM cannot patch them, so the four entries are
 * replaced at the syscall table - the same fp-hook layer the stat and create families use.
 *
 * ABI (unchanged from upstream, so the prebuilt ksu_susfs tool drives it unmodified):
 *   CMD_SUSFS_SET_PRIORITY_UID_FILTER takes a comma-separated list of package names, resolves
 *   each to the owner uid of /data/data/<pkg>, and stores them in an RCU bitmap of the app uid
 *   range (10000-19999).  Each call replaces the previous list.
 *
 * Reading /data/data needs the ksu SELinux domain (the ksu_susfs caller is not guaranteed to
 * be in a domain that may read app data).  We build a cred whose task sid is u:r:ksu:s0 and
 * resolve under it: prepare_creds() hands back a cred whose SELinux blob is a fresh copy
 * (security_prepare_creds duplicates task_security_struct), so writing its sid is private to
 * this task.  The sid field offset comes from BTF, resolved once at init.
 *   The SELinux cred-blob base (selinux_blob_sizes.lbs_cred) is resolved separately and both
 *   offsets must be known before this layer arms.  A layout that cannot be proven is rejected,
 *   rather than resolving under the caller's domain with a potentially empty filter.
 *
 * Scope: the uids are resolved when the list is set.  Upstream also re-resolves from the
 * KernelSU package observer on reinstall; the LKM does not hook that, so a reinstalled app
 * keeps its old uid filtered until the list is set again.  That is a miss (the new uid leaks),
 * never a false hide.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/namei.h>		/* kern_path() */
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/security.h>		/* security_secctx_to_secid() */
#include <linux/uidgid.h>
#include <linux/compat.h>
#include <linux/resource.h>		/* PRIO_USER */
#include <linux/ioprio.h>		/* IOPRIO_WHO_USER */
#include <asm/unistd.h>

#include "susfs.h"
#include "susfs_abi.h"
#include "susfs_fp_hook.h"
#include "symbol_resolver.h"
#include "btf_layout.h"
#include "susfs_log.h"

#define PRIO_MIN_UID	10000u
#define PRIO_MAX_UID	19999u
#define PRIO_UID_NUM	(PRIO_MAX_UID - PRIO_MIN_UID + 1)
#define PRIO_BITMAP_LEN	BITS_TO_LONGS(PRIO_UID_NUM)

/* AArch32 table numbers (arch/arm/tools/syscall.tbl); the native ones come from __NR_*.  Spelled
 * out for the reason susfs_fp_hook.h / susfs_create_gate.c spell theirs: the two tables do not
 * share a numbering. */
#define COMPAT_SETPRIORITY_NR	97
#define COMPAT_GETPRIORITY_NR	96
#define COMPAT_IOPRIO_SET_NR	314
#define COMPAT_IOPRIO_GET_NR	315

struct prio_uid_bitmap {
	unsigned long bits[PRIO_BITMAP_LEN];
};

static struct prio_uid_bitmap __rcu *prio_bitmap;	/* NULL = nothing filtered */
static DEFINE_MUTEX(prio_set_lock);			/* serialises the set/replace path */
static bool prio_active;

/* Resolved once at init. */
static u32 prio_ksu_sid;			/* sid of u:r:ksu:s0, 0 = unresolved */
static size_t prio_tsec_sid_off;		/* offset of sid in task_security_struct */
static bool prio_tsec_sid_ok;			/* the offset above was found */
static size_t prio_cred_blob_off;
static bool prio_cred_blob_ok;
static struct cred *(*prio_prepare_creds)(void);

/* Lockless lookup for the syscall path (the caller already holds rcu_read_lock through the
 * wrapper, or takes it here). */
static bool prio_uid_filtered(uid_t uid)
{
	struct prio_uid_bitmap *b;
	uid_t app_id = uid % 100000;	/* secondary Android users map to the same app id */
	bool hit = false;

	if (app_id < PRIO_MIN_UID || app_id > PRIO_MAX_UID)
		return false;

	rcu_read_lock();
	b = rcu_dereference(prio_bitmap);
	if (likely(b))
		hit = test_bit(app_id - PRIO_MIN_UID, b->bits);
	rcu_read_unlock();
	return hit;
}

static bool prio_valid_app_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;
	size_t len = 0;

	if (!*p || !strcmp(name, ".") || !strcmp(name, ".."))
		return false;
	while (*p) {
		if (len++ >= 255 ||
		    !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '.' || *p == '_'))
			return false;
		p++;
	}
	return true;
}

/* An app (uid >= 10000) asking about a DIFFERENT, filtered uid is the enumeration the feature
 * blocks; a process asking about itself, or a non-app (su/system) caller, sees the truth. */
static bool prio_should_hide_user(int which, int who, int who_is_user_class)
{
	kuid_t caller_kuid = current_uid();
	kuid_t target_kuid;
	uid_t caller;
	uid_t target;

	if (which != who_is_user_class)		/* only the by-uid form carries a uid in `who` */
		return false;
	target_kuid = make_kuid(current_user_ns(), (uid_t)who);
	if (!uid_valid(target_kuid) || !uid_valid(caller_kuid))
		return false;
	caller = from_kuid(&init_user_ns, caller_kuid);
	target = from_kuid(&init_user_ns, target_kuid);
	if (caller < PRIO_MIN_UID)		/* not an app: never filtered */
		return false;
	if ((target % 100000) == (caller % 100000))	/* asking about self is allowed */
		return false;
	return prio_uid_filtered(target);
}

/* ---- the four syscall-table wrappers (READ_ONCE(orig), like susfs_create_gate.c) ----
 *
 * One hook per syscall: susfs_fp_install() puts the same wrapper into BOTH the native and the
 * compat table (driven by nr_compat).  getpriority/setpriority/ioprio_get/ioprio_set take only
 * integer arguments (which, who, prio) and have no compat-specific handler, so the wrapper
 * reads the native original and calls it for a 32-bit task too - there is no 32-bit struct to
 * translate, unlike the stat family.  A 32-bit app is therefore filtered as well; patching the
 * native table alone would leave it a way through. */

static susfs_syscall_fn_t prio_orig_getpriority;
static susfs_syscall_fn_t prio_orig_setpriority;
static susfs_syscall_fn_t prio_orig_ioprio_get;
static susfs_syscall_fn_t prio_orig_ioprio_set;
static susfs_syscall_fn_t prio_orig_compat_getpriority;
static susfs_syscall_fn_t prio_orig_compat_setpriority;
static susfs_syscall_fn_t prio_orig_compat_ioprio_get;
static susfs_syscall_fn_t prio_orig_compat_ioprio_set;

#define PRIO_WRAP(fn, origp, compatp, user_class)				\
static __nocfi noinline long fn(const struct pt_regs *regs)			\
{										\
	susfs_syscall_fn_t orig = is_compat_task() ? READ_ONCE(compatp) :\
		READ_ONCE(origp);								\
										\
	if (!orig)								\
		return -ENOSYS;							\
	if (prio_should_hide_user((int)regs->regs[0], (int)regs->regs[1],	\
				  (user_class)))				\
		return -ESRCH;							\
	return orig(regs);							\
}

PRIO_WRAP(prio_w_getpriority, prio_orig_getpriority, prio_orig_compat_getpriority, PRIO_USER)
PRIO_WRAP(prio_w_setpriority, prio_orig_setpriority, prio_orig_compat_setpriority, PRIO_USER)
PRIO_WRAP(prio_w_ioprio_get, prio_orig_ioprio_get, prio_orig_compat_ioprio_get, IOPRIO_WHO_USER)
PRIO_WRAP(prio_w_ioprio_set, prio_orig_ioprio_set, prio_orig_compat_ioprio_set, IOPRIO_WHO_USER)

static struct susfs_fp_hook prio_hooks[] = {
	{ .nr = __NR_getpriority, .nr_compat = COMPAT_GETPRIORITY_NR,
	  .name = "priority/getpriority", .sym = "__arm64_sys_getpriority",
	  .wrapper = prio_w_getpriority, .orig_slot = &prio_orig_getpriority,
	  .orig_slot_compat = &prio_orig_compat_getpriority },
	{ .nr = __NR_setpriority, .nr_compat = COMPAT_SETPRIORITY_NR,
	  .name = "priority/setpriority", .sym = "__arm64_sys_setpriority",
	  .wrapper = prio_w_setpriority, .orig_slot = &prio_orig_setpriority,
	  .orig_slot_compat = &prio_orig_compat_setpriority },
	{ .nr = __NR_ioprio_get, .nr_compat = COMPAT_IOPRIO_GET_NR,
	  .name = "priority/ioprio_get", .sym = "__arm64_sys_ioprio_get",
	  .wrapper = prio_w_ioprio_get, .orig_slot = &prio_orig_ioprio_get,
	  .orig_slot_compat = &prio_orig_compat_ioprio_get },
	{ .nr = __NR_ioprio_set, .nr_compat = COMPAT_IOPRIO_SET_NR,
	  .name = "priority/ioprio_set", .sym = "__arm64_sys_ioprio_set",
	  .wrapper = prio_w_ioprio_set, .orig_slot = &prio_orig_ioprio_set,
	  .orig_slot_compat = &prio_orig_compat_ioprio_set },
};

/* ---- uid resolution (set path only; sleeps, runs in the supercall task_work) ---- */

/* Build a cred in the ksu domain and make it current; returns the cred to restore, and stores
 * the one this call prepared in @made (put after revert).  NULL = run as-is (resolution may
 * then fail with EACCES, which the set path reports). */
static __nocfi const struct cred *prio_enter_ksu_domain(struct cred **made)
{
	struct cred *nc;

	*made = NULL;
	if (!prio_ksu_sid || !prio_tsec_sid_ok || !prio_prepare_creds)
		return NULL;

	nc = prio_prepare_creds();		/* fresh cred, SELinux blob duplicated */
	if (!nc)
		return NULL;
	if (nc->security)
		*(u32 *)((char *)nc->security + prio_cred_blob_off +
			 prio_tsec_sid_off) = prio_ksu_sid;
	*made = nc;
	return override_creds(nc);
}

static void prio_leave_ksu_domain(const struct cred *old, struct cred *made)
{
	if (!made)
		return;
	revert_creds(old);
	put_cred(made);
}

static int prio_resolve_uid(const char *pkg, uid_t *out)
{
	char pathbuf[SUSFS_MAX_LEN_PATHNAME + 16];
	const struct cred *old;
	struct cred *made;
	struct path p;
	uid_t uid;
	int rc;

	if (!prio_valid_app_name(pkg))
		return -EINVAL;
	if (scnprintf(pathbuf, sizeof(pathbuf), "/data/data/%s", pkg) >=
	    (int)sizeof(pathbuf) - 1)
		return -ENAMETOOLONG;

	old = prio_enter_ksu_domain(&made);
	rc = kern_path(pathbuf, 0, &p);
	prio_leave_ksu_domain(old, made);
	if (rc)
		return rc;

	uid = from_kuid(&init_user_ns, d_inode(p.dentry)->i_uid);
	path_put(&p);

	if (uid < PRIO_MIN_UID || uid > PRIO_MAX_UID)
		return -ERANGE;
	*out = uid;
	return 0;
}

/* Parse the comma-separated package list into a fresh bitmap.  A package that cannot be
 * resolved (unknown, uid out of the app range) fails the whole command, exactly like upstream -
 * better than silently filtering nothing. */
static int prio_build_bitmap(char *app_strings, struct prio_uid_bitmap *bm)
{
	char *cursor = app_strings;
	char *tok;
	int rc;

	while ((tok = strsep(&cursor, ",")) != NULL) {
		uid_t uid;

		tok = strim(tok);
		if (!*tok)
			continue;
		rc = prio_resolve_uid(tok, &uid);
		if (rc) {
			SUSFS_LOGI("priority_filter: package '%s' not resolved (%d)\n", tok, rc);
			return rc;
		}
		set_bit(uid - PRIO_MIN_UID, bm->bits);
		SUSFS_LOGI("priority_filter: uid %u (%s) added\n", uid, tok);
	}
	return 0;
}

/* ---- supercall: CMD_SUSFS_SET_PRIORITY_UID_FILTER ---- */

void susfs_priority_filter_supercall(void __user **arg)
{
	struct st_susfs_priority_uid_filter *info;
	struct prio_uid_bitmap *nb = NULL, *ob;
	int err;

	/* 65 KiB payload: a static/stack copy would blow the frame limit (the same reason
	 * susfs_show_enabled_features kzalloc's its answer), so both the input and the bitmap
	 * are heap. */
	info = kvzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		goto out_err;
	}
	if (copy_from_user(info, (struct st_susfs_priority_uid_filter __user *)*arg, sizeof(*info))) {
		err = -EFAULT;
		goto out_free;
	}
	info->app_strings[SUSFS_APP_STR_BUF_SIZE - 1] = '\0';

	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb) {
		err = -ENOMEM;
		goto out_free;
	}

	err = prio_build_bitmap(info->app_strings, nb);
	if (err)
		goto out_free;		/* nb freed below, old list left in place */

	mutex_lock(&prio_set_lock);
	if (!prio_active) {
		mutex_unlock(&prio_set_lock);
		err = -ENODEV;
		goto out_free;
	}
	ob = rcu_dereference_protected(prio_bitmap, lockdep_is_held(&prio_set_lock));
	rcu_assign_pointer(prio_bitmap, nb);
	nb = NULL;			/* published; do not free */
	if (ob) {
		synchronize_rcu();
		kfree(ob);
	}
	mutex_unlock(&prio_set_lock);
	err = 0;

out_free:
	kfree(nb);
	kvfree(info);
out_err:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_priority_uid_filter __user *)*arg)->err,
			 &err, sizeof(err)))
		pr_warn("priority_filter supercall copy_to_user failed\n");
}

/* ---- layer init/exit ---- */

int susfs_priority_filter_init(void)
{
	int installed = 0;
	int rc;
	int i;
	size_t off;

	prio_prepare_creds = (void *)find_kernel_symbol_exact("prepare_creds");

	rc = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &prio_ksu_sid);
	if (rc) {
		prio_ksu_sid = 0;
		pr_warn("priority_filter: secctx_to_secid(u:r:ksu:s0) failed %d - will resolve uids in the caller's domain\n",
			rc);
	}
	/* The SELinux task blob's sid: BTF finds the scalar member offset, the same way the module
	 * already reads inode_security_struct.sid. */
	if (!susfs_btf_member_offset("task_security_struct", "sid", "u32", &off)) {
		prio_tsec_sid_off = off;
		prio_tsec_sid_ok = true;
	} else {
		prio_tsec_sid_ok = false;
		pr_warn("priority_filter: task_security_struct.sid offset not found in BTF - will resolve in the caller's domain\n");
	}
	{
		unsigned long blob_sizes = find_kernel_symbol_exact("selinux_blob_sizes");
		int blob_off = 0;

		if (blob_sizes && susfs_btf_member_offset("lsm_blob_sizes", "lbs_cred",
								"int", &off))
			return -ENOENT;
		if (blob_sizes)
			blob_off = READ_ONCE(*(int *)((char *)blob_sizes + off));
		if (blob_off < 0 || blob_off > 4096)
			return -EINVAL;
		prio_cred_blob_off = (size_t)blob_off;
		prio_cred_blob_ok = true;
	}
	if (!prio_prepare_creds || !prio_ksu_sid || !prio_tsec_sid_ok ||
	    !prio_cred_blob_ok)
		pr_warn("priority_filter: private SELinux cred layout unavailable - feature stays off\n");

	if (!prio_prepare_creds || !prio_ksu_sid || !prio_tsec_sid_ok ||
	    !prio_cred_blob_ok)
		return -ENOENT;

	for (i = 0; i < (int)ARRAY_SIZE(prio_hooks); i++) {
		rc = susfs_fp_install(&prio_hooks[i]);
		if (rc) {
			pr_warn("priority_filter: %s not installed (%d) - rolling back the complete feature\n",
				prio_hooks[i].name, rc);
			while (i > 0) {
				--i;
				if (prio_hooks[i].installed)
					susfs_fp_remove(&prio_hooks[i]);
			}
			susfs_fp_drain();
			return rc;
		}
		installed++;
	}
	if (installed != (int)ARRAY_SIZE(prio_hooks))
		return -ENOENT;
	mutex_lock(&prio_set_lock);
	prio_active = true;
	mutex_unlock(&prio_set_lock);

	SUSFS_LOGI("priority_filter armed: %d of %u entries answer -ESRCH for filtered app uids\n",
		   installed, (unsigned int)ARRAY_SIZE(prio_hooks));
	return 0;
}

void susfs_priority_filter_exit(void)
{
	struct prio_uid_bitmap *b;
	int armed = 0;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(prio_hooks); i++) {
		if (!prio_hooks[i].installed)
			continue;
		susfs_fp_remove(&prio_hooks[i]);
		armed++;
	}
	if (armed)
		susfs_fp_drain();

	mutex_lock(&prio_set_lock);
	prio_active = false;
	b = rcu_dereference_protected(prio_bitmap, lockdep_is_held(&prio_set_lock));
	rcu_assign_pointer(prio_bitmap, NULL);
	if (b) {
		synchronize_rcu();
		kfree(b);
	}
	mutex_unlock(&prio_set_lock);
}
