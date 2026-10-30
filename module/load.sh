#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Load the susfs_guard_lkm .ko that matches the running GKI kernel, once, at boot.
MODDIR=${0%/*}
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0
[ "$(getprop persist.sys.safemode)" != 1 ] || exit 0
[ "$(getprop ro.sys.safemode)" != 1 ] || exit 0
umask 077

# The KernelSU manager shows module.prop's description on the module card, so the outcome of
# the load is written there: a boot where this module failed and one where it worked must not
# look alike.  '#' is the sed delimiter because the text contains '-' (the KMI) but no '#'.
set_description() {
  prop="$MODDIR/module.prop"
  [ -f "$prop" ] || return 0
  sed -i "s#^description=.*#description=$1#" "$prop" 2>/dev/null
}

exec >"$MODDIR/load.log" 2>&1
echo "susfs_guard_lkm loader: $(date)"
# The /proc control nodes exist only while sus_path's LSM layer is installed, so
# their presence means susfs is already up (built-in or an earlier load). Do not stack.
if [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; then
  echo "susfs already present; nothing to do."
  set_description "already present (built-in or loaded earlier)"
  exit 0
fi
REL=$(cat /proc/sys/kernel/osrelease 2>/dev/null) || REL=""
[ -n "$REL" ] || REL="unknown"
. "$MODDIR/kmi.sh"
# A non-empty packaged override wins over the release string, but only when it
# names a KMI whose .ko is actually in this module.  The packaged file starts
# empty, and an empty value is the normal "automatic" path - not an error.
OVERRIDE=$(kmi_override_value "$MODDIR")
KMI=""
if [ -n "$OVERRIDE" ]; then
  KMI=$(select_kmi_override "$MODDIR")
  if [ -n "$KMI" ]; then
    MODE=custom
    echo "kmi_override: $KMI (kernel $REL)"
  else
    MODE=auto
    echo "kmi_override '$OVERRIDE' is not packaged; using automatic KMI detection"
  fi
else
  MODE=auto
fi
if [ "$MODE" = auto ]; then
  if [ "$REL" != unknown ]; then
    KMI=$(select_kmi "$REL" "$MODDIR") || KMI=""
  fi
  if [ -n "$KMI" ] && [ ! -s "$MODDIR/lib/susfs_guard_lkm-$KMI.ko" ]; then
    echo "release matched $KMI but its .ko is missing; trying ksud boot-info current-kmi"
    KMI=""
  fi
  if [ -z "$KMI" ]; then
    # Manual override and release-string matching both failed.  Ask the KernelSU
    # daemon for the KMI it booted; this is the last source before refusing.
    if [ "$REL" = unknown ]; then
      echo "kernel release unreadable; trying ksud boot-info current-kmi"
    else
      echo "no packaged KMI matched kernel $REL; trying ksud boot-info current-kmi"
    fi
    KMI=$(select_kmi_from_ksud "$MODDIR") || {
      echo "KMI detection failed: no release match and ksud current-kmi unavailable or not packaged"
      set_description "❌ KMI detection failed: no packaged .ko for kernel $REL"
      exit 1
    }
    MODE=ksud
    echo "ksud boot-info current-kmi: $KMI"
  fi
fi
KO="$MODDIR/lib/susfs_guard_lkm-$KMI.ko"
[ -s "$KO" ] || {
  echo "KMI detection failed: missing .ko for $KMI"
  set_description "❌ KMI detection failed: missing .ko for $KMI"
  exit 1
}
echo "kernel $REL -> $KMI ($MODE)"
# One minute is the whole userspace load budget: the loader maps/relocates the .ko and then
# blocks in init_module(2) while the kernel runs module_init().  A timeout is a failed load,
# not a reason to try another KMI.
LOAD_TIMEOUT=60
TIMEOUT_LOG=/data/adb/susfsload_timeout.log
TIMEOUT_DMESG_LOG=/data/adb/susfsload_timeout_dmesg.log
TIMEOUT_BIN=""
for candidate in timeout /system/bin/timeout; do
  if command -v "$candidate" >/dev/null 2>&1; then
    TIMEOUT_BIN=$(command -v "$candidate")
    break
  fi
done
# Start the kernel log follower before the loader, so the dmesg file contains the whole
# load attempt rather than only the lines that happened to remain when it timed out.
DMESG_PID=""
dmesg_stop() {
  if [ -n "$DMESG_PID" ]; then
    kill "$DMESG_PID" 2>/dev/null
    wait "$DMESG_PID" 2>/dev/null
    DMESG_PID=""
  fi
}
dmesg_start() {
  {
    echo "susfs_guard_lkm load dmesg: $(date)"
    echo "kernel: $REL"
    echo "KMI: $KMI ($MODE)"
    echo "limit: ${LOAD_TIMEOUT}s"
    echo "--- dmesg from load start ---"
    exec dmesg -W
  } > "$TIMEOUT_DMESG_LOG" 2>&1 &
  DMESG_PID=$!
}
if [ -n "$TIMEOUT_BIN" ]; then
  dmesg_start
  "$TIMEOUT_BIN" "$LOAD_TIMEOUT" "$MODDIR/bin/susfs_insmod" "$KO" expose_proc=1
  rc=$?
else
  echo "load failed: no timeout utility for the ${LOAD_TIMEOUT}s module_init limit"
  rc=1
fi
if [ "$rc" = 124 ]; then
  echo "load timed out after ${LOAD_TIMEOUT}s"
  dmesg_stop
  echo "--- load timed out after ${LOAD_TIMEOUT}s ---" >> "$TIMEOUT_DMESG_LOG" 2>/dev/null
  chmod 0600 "$TIMEOUT_DMESG_LOG" 2>/dev/null
  {
    echo "susfs_guard_lkm load timeout: $(date)"
    echo "kernel: $REL"
    echo "KMI: $KMI ($MODE)"
    echo "limit: ${LOAD_TIMEOUT}s"
    echo "--- load.log ---"
    cat "$MODDIR/load.log"
  } > "$TIMEOUT_LOG" 2>&1
  chmod 0600 "$TIMEOUT_LOG" 2>/dev/null
  set_description "❌ load timed out (${KMI}) after ${LOAD_TIMEOUT}s | kernel $REL"
  exit 124
fi
dmesg_stop
rm -f "$TIMEOUT_DMESG_LOG"
if [ "$rc" = 0 ]; then
  echo "loaded ($MODE)."
  if [ "$MODE" = custom ]; then
    set_description "✅ custom load ($KMI) | kernel $REL"
  elif [ "$MODE" = ksud ]; then
    set_description "✅ ksud-detected ($KMI) | kernel $REL"
  else
    set_description "✅ auto-detected ($KMI) | kernel $REL"
  fi
else
  echo "susfs_insmod failed: $rc"
  set_description "❌ load failed [$MODE] ($KMI): susfs_insmod rc=$rc | kernel $REL"
fi
exit "$rc"
