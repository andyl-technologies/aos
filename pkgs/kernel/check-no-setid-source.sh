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

mode_guard_count=$(grep -c '^static inline bool task_aos_no_setid_mode_guard(' include/linux/sched.h || true)
[ "$mode_guard_count" -eq 1 ] || fail "mode-effect predicate missing or duplicated"
grep -Fq 'return task_aos_no_setid(p) || (p->flags & PF_IO_WORKER);' include/linux/sched.h || fail "io_uring worker mode policy changed"

if grep -REq 'TASK_PFA_CLEAR\(AOS_NO_SETID|task_clear_aos_no_setid' include/linux/sched.h kernel fs; then
  fail "one-way no-setid task flag acquired a clear path"
fi

mode_callers=$(grep -c 'vfs_prepare_mode(idmap,' fs/namei.c || true)
[ "$mode_callers" -eq 6 ] || fail "expected six VFS mode-preparation callers"

namei_guards=$(grep -c 'task_aos_no_setid_mode_guard(current)' fs/namei.c || true)
[ "$namei_guards" -eq 3 ] || fail "mode, mkobj, or SGID-parent guard changed"

for guarded_source in fs/open.c fs/attr.c; do
  guard_count=$(grep -c 'task_aos_no_setid_mode_guard(current)' "$guarded_source" || true)
  [ "$guard_count" -eq 1 ] || fail "$guarded_source effect guard changed"
done

grep -Fq 'if (task_aos_no_setid(current))' kernel/fork.c || fail "child inheritance changed"
grep -Fq 'return task_aos_no_setid(current) ? 1 : 0;' kernel/sys.c || fail "PR_GET must report only the inherited flag"

grep -Fq 'p->flags |= PF_IO_WORKER;' kernel/fork.c || fail "io_uring task flag assignment changed"
grep -Fq 'tsk = create_io_thread(io_sq_thread, sqd, NUMA_NO_NODE);' io_uring/sqpoll.c || fail "SQPOLL task creation changed"
io_wq_workers=$(grep -c 'tsk = create_io_thread(io_wq_worker, worker, NUMA_NO_NODE);' io_uring/io-wq.c || true)
[ "$io_wq_workers" -eq 2 ] || fail "io-wq task creation changed"
