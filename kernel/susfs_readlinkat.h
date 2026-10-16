/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * susfs_readlinkat.h - the readlinkat layer: its control entry points only.
 *
 * The hidden decision this layer post-checks with belongs to sus_path and is declared there
 * (susfs.h, sus_path_string_hidden_public): a header for one layer must not own another's API.
 */

#ifndef __SUSFS_READLINKAT_H
#define __SUSFS_READLINKAT_H

int susfs_readlinkat_init(void);
void susfs_readlinkat_exit(void);

/* The layer's control node: armed flag + the counters that say whether the kretprobe ran and
 * ever answered ENOENT. Registered in susfs_main.c's self-hide list like every other node
 * (0777 plus sus_path's LSM layer answering ENOENT for non-root, see susfs_main.c). */
#define SUSFS_READLINKAT_NODE "/proc/susfs_readlinkat"

#endif /* __SUSFS_READLINKAT_H */
