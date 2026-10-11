// SPDX-License-Identifier: GPL-2.0

/* issue #34: the hide gates ask KernelSU whether it would umount modules for a uid, instead of the
 * old `uid >= 10000` proxy that hid from the manager and from su-granted apps too.
 *
 * The address is resolved ONCE, at load, by name through kallsyms (kernel/symbol_resolver.c) and kept
 * in a function pointer - it is not imported from kernelsu.ko, for two reasons:
 *
 *   - an import would have to be strong.  A __weak one is emitted as a GOT entry
 *     (R_AARCH64_ADR_GOT_PAGE + R_AARCH64_LD64_GOT_LO12_NC), and arm64's module relocator implements
 *     neither, so the module would refuse to load at all - measured on the artifacts, including with
 *     visibility("hidden") and with -fno-pic, neither of which removes that entry (it comes from the
 *     weak reference itself, not from PIC);
 *   - resolving by name answers the environment question directly: the symbol is there or it is not.
 *     Nothing here depends on which loader ran the module or on the SELinux domain it ran in, so no
 *     loader-side detection is needed either.
 *
 * The answer is decided once, here, and the gates only read the flag afterwards.  Consequence worth
 * knowing: a KernelSU loaded after this module is not noticed until this module is reloaded, which the
 * warning below says out loud. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "ksu_umount_gate.h"
#include "symbol_resolver.h"
#include "susfs_log.h"

#define KSU_UMOUNT_GATE_SYMBOL	"ksu_uid_should_umount"

bool susfs_ksu_umount_gate_off;

/* Written once in init, read by every gate through susfs_ksu_umount_ask().  NULL only while the gate
 * is off, which is the invariant the helper relies on instead of testing the pointer on every call. */
static bool (*ksu_uid_should_umount_fn)(uid_t uid);

/* noinline __nocfi: an indirect call through a resolved address.  CFI checks indirect call sites, and
 * LTO would otherwise inline a small static helper back into a caller that is not marked. */
bool __nocfi noinline susfs_ksu_umount_ask(uid_t uid)
{
	return ksu_uid_should_umount_fn(uid);
}

int susfs_ksu_umount_gate_init(void)
{
	unsigned long addr = ksu_kallsyms_lookup_name(KSU_UMOUNT_GATE_SYMBOL);

	if (!addr) {
		susfs_ksu_umount_gate_off = true;
		/* pr_warn, not SUSFS_LOGI: "issue #34's fix is not in effect on this device" is something an
		 * operator has to be able to see, and the load is otherwise silent about it. */
		pr_warn("susfs_guard_lkm: %s is not in kallsyms - the hide gates keep the uid >= 10000 rule, so issue #34's fix (hiding follows KernelSU's exclusion list) is NOT in effect here.  A KernelSU loaded after this module needs this module reloaded to be picked up.\n",
			KSU_UMOUNT_GATE_SYMBOL);
		return 0;
	}

	ksu_uid_should_umount_fn = (bool (*)(uid_t))addr;
	SUSFS_LOGI("ksu_umount_gate: resolved %s at %px - the hide gates now answer KernelSU (issue #34)\n",
		   KSU_UMOUNT_GATE_SYMBOL, (void *)addr);
	return 0;
}
