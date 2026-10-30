#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Pick the packaged KMI for a kernel release string. The packaged set lives in
# "$2/kmis" (one <android-os>-<kver> per line), so adding a KMI needs no edit here.

# The packaged file is deliberately empty by default: an empty override means
# "use automatic detection", not "invalid".  Non-empty content is accepted only
# when it is one of the packaged KMIs and its .ko is present.
kmi_override_value() {
  file="$1/kmi_override"
  [ -f "$file" ] || return 0
  head -n 1 "$file" 2>/dev/null | tr -d '\r' | tr -d '[:space:]'
}

# Print the forced KMI, or fail so callers fall back to select_kmi().  An empty
# override is a normal fallback, not an error.
select_kmi_override() {
  kmi=$(kmi_override_value "$1")
  [ -n "$kmi" ] || return 1
  while IFS= read -r known; do
    [ "$known" = "$kmi" ] || continue
    [ -s "$1/lib/susfs_guard_lkm-$kmi.ko" ] || return 1
    printf '%s\n' "$kmi"
    return 0
  done < "$1/kmis"
  return 1
}

select_kmi() {
  rel="$1"
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    os="${kmi%-*}"
    kver="${kmi#*-}"
    case "$rel" in
      "$kver".*-"$os"-*) echo "$kmi"; return 0 ;;
    esac
  done < "$2/kmis"
  # A present but non-matching Android tag is a real mismatch, not a tag-less kernel.
  case "$rel" in *android[0-9]*) return 1 ;; esac
  # Tag-less: match by version alone, only when it maps to one packaged KMI (5.10 and
  # 5.15 are shared, so refused), with a numeric patch level.
  match=""
  n=0
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    kver="${kmi#*-}"
    case "$rel" in "$kver".*) ;; *) continue ;; esac
    patch="${rel#"$kver".}"; patch="${patch%%-*}"
    case "$patch" in ''|*[!0-9]*) continue ;; esac
    match="$kmi"; n=$((n + 1))
  done < "$2/kmis"
  [ "$n" = 1 ] && { echo "$match"; return 0; }
  return 1
}

# Last resort after manual override and automatic matching both fail: ask the
# KernelSU daemon which KMI it booted.  The answer is accepted only when it is
# one of the packaged KMIs and its .ko is present, so a stale/bogus ksud answer
# cannot select an absent file.
select_kmi_from_ksud() {
  dir="$1"
  ksud_bin=""
  for candidate in ksud /data/adb/ksu/bin/ksud /data/adb/ksud; do
    if command -v "$candidate" >/dev/null 2>&1; then
      ksud_bin=$(command -v "$candidate")
      break
    fi
  done
  [ -n "$ksud_bin" ] || return 1

  out=$("$ksud_bin" boot-info current-kmi 2>/dev/null) || return 1
  kmi=$(printf '%s\n' "$out" | tr -d '\r' | sed -n '1p')
  [ -n "$kmi" ] || return 1
  case "$kmi" in android[0-9]*-[0-9]*) ;; *) return 1 ;; esac
  grep -Fqx -- "$kmi" "$dir/kmis" >/dev/null 2>&1 || return 1
  [ -s "$dir/lib/susfs_guard_lkm-$kmi.ko" ] || return 1
  printf '%s\n' "$kmi"
}
