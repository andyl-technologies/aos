# Fail a kernel rebase if the guarded VFS entry-point set or task flag changes.
# This is a source-shape check; the runtime VM probe tests policy behavior.
set -eu

fail() {
  echo "no-setid kernel source check: $1" >&2
  exit 1
}

flag_count=$(grep -Ec '^#define[[:space:]]+PFA_[A-Z0-9_]+[[:space:]]+8([[:space:]]|$)' include/linux/sched.h || true)
[ "$flag_count" -eq 1 ] || fail "task atomic flag 8 is not unique"
grep -Eq '^#define[[:space:]]+PFA_AOS_NO_SETID[[:space:]]+8([[:space:]]|$)' include/linux/sched.h || fail "no-setid task flag moved"

if grep -REq 'TASK_PFA_CLEAR\(AOS_NO_SETID|task_clear_aos_no_setid' include/linux/sched.h kernel fs; then
  fail "one-way no-setid task flag acquired a clear path"
fi

mode_callers=$(grep -c 'vfs_prepare_mode(idmap,' fs/namei.c || true)
[ "$mode_callers" -eq 6 ] || fail "expected six VFS mode-preparation callers"

namei_guards=$(grep -c 'task_aos_no_setid(current)' fs/namei.c || true)
[ "$namei_guards" -eq 3 ] || fail "mode, mkobj, or SGID-parent guard changed"

for guarded_source in fs/open.c fs/attr.c kernel/fork.c; do
  grep -q 'task_aos_no_setid(current)' "$guarded_source" || fail "$guarded_source guard missing"
done
