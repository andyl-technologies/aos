set -euo pipefail
export LC_ALL=C

# The caller owns this staging tree exclusively; never run against live roots.
if [ "$#" -ne 1 ]; then
  echo 'expected one directory' >&2
  exit 2
fi
lexical_root=$(realpath -m -s -- "$1")
if [ -L "$lexical_root" ] || [ ! -d "$lexical_root" ]; then
  echo 'expected one real directory, not a symlink' >&2
  exit 2
fi
root=$(realpath -e -- "$1")
if [ "$root" = / ]; then
  echo 'refusing filesystem root' >&2
  exit 2
fi
manifest=$(mktemp)
manifest=$(realpath -e -- "$manifest")
case "$manifest" in
  "$root"/*)
    rm -- "$manifest"
    echo 'permission manifest must be outside the tree' >&2
    exit 2
    ;;
esac

# Store copies retain read-only directories. Restore only the bit we add,
# including after a partial failure, without changing regular-file metadata.
restore_permissions() {
  status=$?
  trap - EXIT HUP INT TERM
  restoration_failed=0
  while IFS= read -r -d '' directory; do
    chmod u-w -- "$directory" || restoration_failed=1
  done < "$manifest"
  rm -- "$manifest" || restoration_failed=1
  if [ "$restoration_failed" -ne 0 ]; then
    echo 'failed to restore directory permissions or remove manifest' >&2
    exit 1
  fi
  exit "$status"
}
trap restore_permissions EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

find -P "$root" -type d ! -perm -u=w -print0 > "$manifest"

while IFS= read -r -d '' directory; do
  chmod u+w -- "$directory"
done < "$manifest"

# Both image builders use -T0, so source mtimes do not distinguish files.
# Contents, ownership, mode, and xattrs must still match; symlinks stay intact.
hardlink --ignore-time --respect-xattrs --reflink=never -- "$root"
