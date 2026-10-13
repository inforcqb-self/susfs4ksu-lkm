# SPDX-License-Identifier: GPL-2.0-only
# Pick the packaged KMI for a kernel release string. The packaged set lives in
# "$2/kmis" (one <android-os>-<kver> per line), so adding a KMI needs no edit here.
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
  # Fallback: a custom kernel can rename osrelease and drop the -<os>- tag, so the
  # strict match finds nothing. Match by kernel version alone, but only when that
  # version maps to a single packaged KMI; never guess between two that share a
  # version (5.10, 5.15).
  match=""
  n=0
  while IFS= read -r kmi; do
    [ -n "$kmi" ] || continue
    kver="${kmi#*-}"
    case "$rel" in
      "$kver".*) match="$kmi"; n=$((n + 1)) ;;
    esac
  done < "$2/kmis"
  [ "$n" = 1 ] && { echo "$match"; return 0; }
  return 1
}
