#!@bash@/bin/bash
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: aos-selinux-load-policy POLICY MODE" >&2
  exit 2
fi

policy=$1
mode=$2
module_dir=@out@/usr/share/selinux/refpolicy
store_root=/var/lib/selinux
policy_dir="/etc/selinux/$policy/policy"
marker="$store_root/$policy/.aos-refpolicy-source"
desired=@out@

@coreutils@/bin/mkdir -p "$store_root" "/etc/selinux/$policy" "$policy_dir"

policy_file_exists() {
  for policy_file in "$policy_dir"/policy.*; do
    [ -f "$policy_file" ] && return 0
  done
  return 1
}

if [ ! -f "$marker" ] || ! @grep@/bin/grep -qx "$desired" "$marker" || ! policy_file_exists; then
  set -- -s "$policy" -S "$store_root" -i "$module_dir/base.pp"
  for module in "$module_dir"/*.pp; do
    case "$(@coreutils@/bin/basename "$module")" in
      base.pp | aos_base.pp)
        ;;
      *)
        set -- "$@" -i "$module"
        ;;
    esac
  done
  set -- "$@" -i "$module_dir/aos_base.pp"

  @policycoreutils@/sbin/semodule "$@"
  if ! policy_file_exists; then
    echo "SELinux policy install did not create $policy_dir/policy.*" >&2
    exit 1
  fi
  @coreutils@/bin/mkdir -p "$(@coreutils@/bin/dirname "$marker")"
  @coreutils@/bin/printf '%s\n' "$desired" > "$marker"
else
  @policycoreutils@/sbin/load_policy -qi
fi

case "$mode" in
  enforcing)
    @libselinux@/sbin/setenforce 1
    ;;
  permissive)
    @libselinux@/sbin/setenforce 0
    ;;
  disabled)
    ;;
  *)
    echo "unsupported SELinux mode: $mode" >&2
    exit 1
    ;;
esac
