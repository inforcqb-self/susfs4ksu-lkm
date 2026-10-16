// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_readlinkat.c - answer ENOENT for readlinkat that would expose a path sus_path hides.
 *
 * The leak this closes
 * --------------------
 * sus_path's LSM layer turns stat/open on a hidden path into ENOENT, but readlink has no such
 * hook: do_readlinkat() resolves the path and calls vfs_readlink() without an inode_getattr or
 * inode_permission the sus_path layer sits on. Three readlinkat shapes leak a hidden path:
 *   (1) the path ITSELF is hidden - readlinkat(/data/adb) returns -EINVAL (a dir, not a symlink),
 *       and -EINVAL != -ENOENT proves it exists; every lexical spelling (//, /./, /.., trailing)
 *       leaks the same way.
 *   (2) a SYMLINK whose TARGET is a hidden path - readlinkat(a link -> /data/adb) succeeds and
 *       writes "/data/adb" into the caller's buffer, leaking it even though the link's own path
 *       is not a rule (a detector points its own symlink at /data/adb and reads it back).
 *   (3) a RELATIVE pathname under a dirfd that points into a hidden area.
 * All three are closed here. (1) matches the input path, (2) matches the returned target string,
 * (3) resolves the dirfd to an absolute path first.
 *
 * Why a kretprobe and not the sys_call_table (susfs_opath.c's mechanism)
 * ---------------------------------------------------------------------
 * A syscall-table wrapper like susfs_opath.c would run in process context and could
 * kern_path(LOOKUP_FOLLOW) - but it DOES NOT ARM on this device: GKI keeps sys_call_table out of
 * kallsyms, so susfs_fp_init() cannot find the table (the same reason susfs_opath.c has no /proc
 * node here). So this layer uses what DOES arm on this kernel - a kretprobe, like sus_map.c and
 * susfs_open_redirect.c.
 *
 * The constraint and how each shape is closed WITHOUT sleeping
 * -----------------------------------------------------------
 * A kretprobe handler runs with preemption off - it may NOT sleep, so kern_path() is out. So:
 *   (1) the input path is copied non-sleeping (strncpy_from_user_nofault), lexically canonicalized
 *       (//, /./, /.., trailing - no filesystem walk) and matched against sus_path's rule strings
 *       (sus_path_string_hidden_public(), which takes the sus_path spinlock - safe here).
 *   (2) the returned TARGET is read back from the caller's buffer (copy_from_user_nofault),
 *       canonicalized and matched the same way - the link is never followed, only its own bytes
 *       are inspected.
 *   (3) a relative pathname's dirfd is resolved with fget_raw()+d_path() (both non-sleeping) into
 *       an absolute path, which then goes through (1).
 * 🪤 The syscall arguments (buf = regs[2]) do NOT survive to the return handler (regs[0] becomes
 * the return value), so the entry handler captures them into the kretprobe instance's data.
 *
 * Remaining gap (documented, small): a RELATIVE pathname under AT_FDCWD (resolving the cwd would
 * need a walk), and a symlink whose target is itself RELATIVE. The absolute vectors are closed.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>		/* strncpy_from_user_nofault, copy_from_user_nofault */
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/file.h>			/* fget_raw, fput */
#include <linux/fs.h>			/* struct file, f_path */
#include <linux/dcache.h>		/* d_path */
#include <linux/err.h>			/* IS_ERR */
#include <linux/fcntl.h>		/* AT_FDCWD */
#include <linux/cred.h>			/* current_uid(), for the control node */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <asm/ptrace.h>			/* struct pt_regs, regs_return_value, regs_set_return_value */

#include "susfs_log.h"
#include "susfs.h"			/* sus_path_string_hidden_public(), susfs_control_node_allowed() */
#include "susfs_readlinkat.h"
#include "susfs_kprobe.h"		/* susfs_krp_forget_addr */

/* Rules are stored without a trailing slash and bounded by SUS_PATH_LEN(256) in sus_path.c; a
 * path longer than this cannot equal one, so the per-instance copies are bounded the same way. */
#define RL_PATH_MAX 256

/* Captured at entry, read at return (the arg registers are gone by then). */
struct rl_data {
	void __user *obuf;		/* readlinkat output buffer (regs[2] at entry) */
	char path[RL_PATH_MAX];		/* input path: absolute, or dirfd-resolved, or "" if neither */
};

static atomic_t n_rl_seen = ATOMIC_INIT(0);	/* readlinkat calls the entry handler saw */
static atomic_t n_rl_checked = ATOMIC_INIT(0);	/* a string looked up against sus_path */
static atomic_t n_rl_hidden = ATOMIC_INIT(0);	/* matched a sus_path rule */
static atomic_t n_rl_deny = ATOMIC_INIT(0);	/* return rewritten to -ENOENT */

static bool kr_rl_ok;

/* Lexical canonicalization of an absolute path - NO filesystem walk, so safe in a probe handler.
 * Collapses runs of '/', drops "." components, pops the previous for "..", no trailing slash
 * (root stays "/"). Matches how sus_path.c stores a rule's path[]. False only on overflow. */
static bool rl_canon(const char *in, char *out, size_t outsz)
{
	const char *p = in;
	size_t o = 0;

	out[0] = '\0';
	while (*p) {
		const char *q;
		size_t tl;

		while (*p == '/')
			p++;
		if (!*p)
			break;
		q = p;
		while (*q && *q != '/')
			q++;
		tl = (size_t)(q - p);

		if (tl == 1 && p[0] == '.') {
			/* "." - drop */
		} else if (tl == 2 && p[0] == '.' && p[1] == '.') {
			while (o > 0 && out[o - 1] != '/')
				o--;
			if (o > 0)
				o--;
			out[o] = '\0';
		} else {
			if (o + 1 + tl + 1 > outsz)
				return false;
			out[o++] = '/';
			memcpy(out + o, p, tl);
			o += tl;
			out[o] = '\0';
		}
		p = q;
	}
	if (o == 0) {
		if (outsz < 2)
			return false;
		out[0] = '/';
		out[1] = '\0';
	}
	return true;
}

/* Resolve a relative pathname's dirfd to an absolute path, in-place (@path: relative in, absolute
 * out). Non-sleeping: fget_raw() is a refcount + RCU, d_path() renders under seqlocks, fput()
 * defers the final close. Returns false (leaving @path untouched) for AT_FDCWD, a bad fd, or a
 * dirfd with no pathname (pipe/socket). This is what closes the dirfd-into-a-hidden-area vector. */
static bool rl_resolve_dirfd(int dfd, char *path)
{
	struct file *f;
	char tmp[RL_PATH_MAX], rel[RL_PATH_MAX];
	char *base;
	size_t bl, rll;

	if (dfd < 0)
		return false;
	f = fget_raw((unsigned int)dfd);
	if (!f)
		return false;
	base = d_path(&f->f_path, tmp, sizeof(tmp));
	fput(f);
	if (IS_ERR(base) || base[0] != '/')
		return false;

	strscpy(rel, path, sizeof(rel));
	bl = strlen(base);
	rll = strlen(rel);
	if (bl + 1 + rll + 1 > RL_PATH_MAX)
		return false;
	memcpy(path, base, bl);
	path[bl] = '/';
	memcpy(path + bl + 1, rel, rll);
	path[bl + 1 + rll] = '\0';
	return true;
}

/* do_readlinkat(int dfd, const char __user *pathname, char __user *buf, int bufsiz): arm64 passes
 * args in regs[0..3]. Capture the output buffer (regs[2]) and the input path (resolved to absolute
 * when relative-with-a-dirfd); always let the return handler run so the target check (2) also
 * covers a relative pathname whose target is an absolute hidden path. */
static int rl_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rl_data *d = (struct rl_data *)ri->data;
	const char __user *uptr = (const char __user *)regs->regs[1];
	int dfd = (int)regs->regs[0];
	long n;

	atomic_inc(&n_rl_seen);
	d->obuf = (void __user *)regs->regs[2];
	d->path[0] = '\0';

	if (uptr) {
		n = strncpy_from_user_nofault(d->path, uptr, RL_PATH_MAX);
		if (n < 0 || n >= RL_PATH_MAX) {
			d->path[0] = '\0';
		} else {
			d->path[n] = '\0';
			/* Relative: resolve the dirfd, or give up (target check still runs). */
			if (d->path[0] != '/' &&
			    (dfd == AT_FDCWD || !rl_resolve_dirfd(dfd, d->path)))
				d->path[0] = '\0';
		}
	}
	return 0;
}

/* Return handler: hide if (1) the input path is a hidden rule, or (2) the returned symlink TARGET
 * is. Any non-ENOENT answer proves the path is there, so rewrite it to -ENOENT. */
static int rl_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rl_data *d = (struct rl_data *)ri->data;
	long ret = (long)regs_return_value(regs);
	char canon[RL_PATH_MAX];
	bool hide = false;

	/* (1) input path */
	if (d->path[0] == '/' && ret != -ENOENT && rl_canon(d->path, canon, sizeof(canon))) {
		atomic_inc(&n_rl_checked);
		if (sus_path_string_hidden_public(canon))
			hide = true;
	}

	/* (2) returned target: readlinkat succeeded (ret = bytes written, NOT null-terminated) and
	 * the bytes are the link's target. If that target is a hidden path, it leaks even when the
	 * link's own path is not a rule. Read it back non-sleeping and match the string. */
	if (!hide && ret > 0 && ret < RL_PATH_MAX && d->obuf) {
		char tgt[RL_PATH_MAX], tcanon[RL_PATH_MAX];

		if (copy_from_user_nofault(tgt, d->obuf, (size_t)ret) == 0) {
			tgt[ret] = '\0';
			if (tgt[0] == '/' && rl_canon(tgt, tcanon, sizeof(tcanon))) {
				atomic_inc(&n_rl_checked);
				if (sus_path_string_hidden_public(tcanon))
					hide = true;
			}
		}
	}

	if (hide) {
		atomic_inc(&n_rl_hidden);
		regs_set_return_value(regs, (unsigned long)(long)-ENOENT);
		atomic_inc(&n_rl_deny);
	}
	return 0;
}

static struct kretprobe kr_readlinkat = {
	.kp.symbol_name = "do_readlinkat",	/* fs/stat.c; non-inlined and kprobeable on this kernel */
	.entry_handler = rl_entry,
	.handler = rl_ret,
	.data_size = sizeof(struct rl_data),
	.maxactive = 16,
};

/* ---- /proc/susfs_readlinkat ---- */
static struct proc_dir_entry *rl_proc_entry;

static int rl_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "armed=%d symbol=%s addr=%px\n",
		   (int)kr_rl_ok, kr_readlinkat.kp.symbol_name, (void *)kr_readlinkat.kp.addr);
	seq_printf(m, "seen=%d checked=%d hidden=%d deny=%d\n",
		   atomic_read(&n_rl_seen), atomic_read(&n_rl_checked),
		   atomic_read(&n_rl_hidden), atomic_read(&n_rl_deny));
	return 0;
}

static int rl_proc_open(struct inode *inode, struct file *file)
{
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, rl_proc_show, NULL);
}

static const struct proc_ops rl_proc_ops = {
	.proc_open = rl_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int susfs_readlinkat_init(void)
{
	int rc;

	susfs_krp_forget_addr(&kr_readlinkat);
	rc = register_kretprobe(&kr_readlinkat);
	if (rc) {
		susfs_krp_forget_addr(&kr_readlinkat);
		pr_warn("readlinkat: register_kretprobe(do_readlinkat) failed %d - readlinkat stays visible\n",
			rc);
		return rc;
	}
	kr_rl_ok = true;

	if (susfs_control_node_allowed()) {
		rl_proc_entry = proc_create("susfs_readlinkat", 0777, NULL, &rl_proc_ops);
		if (!rl_proc_entry)
			pr_warn("readlinkat: proc_create(susfs_readlinkat) failed\n");
	}

	SUSFS_LOGI("readlinkat armed: kretprobe do_readlinkat at %px, proc=%d\n",
		   (void *)kr_readlinkat.kp.addr, rl_proc_entry != NULL);
	return 0;
}

void susfs_readlinkat_exit(void)
{
	if (kr_rl_ok) {
		unregister_kretprobe(&kr_readlinkat);
		susfs_krp_forget_addr(&kr_readlinkat);
		kr_rl_ok = false;
	}
	if (rl_proc_entry) {
		proc_remove(rl_proc_entry);
		rl_proc_entry = NULL;
	}
	SUSFS_LOGI("readlinkat disarmed: seen=%d checked=%d hidden=%d deny=%d\n",
		   atomic_read(&n_rl_seen), atomic_read(&n_rl_checked),
		   atomic_read(&n_rl_hidden), atomic_read(&n_rl_deny));
}
