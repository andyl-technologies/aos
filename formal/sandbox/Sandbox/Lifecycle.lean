/-!
# Sandbox lifecycle

A sandbox is a directory of state plus, while it runs, a systemd unit. Its
phase is the unit's state: `running` and `frozen` are an active unit (frozen
through the cgroup freezer), `stopped` is no unit, and `removed` is a
tombstone that keeps the identifier from being reused.

`next` is the complete transition table; an operation it does not list is
rejected. The theorems state the rules the table must keep:

* the writable layer is copied, for a snapshot or a fork, only while no
  process can write it (`copy_quiescent`);
* commands run only in a running sandbox (`exec_running`);
* only a stopped sandbox is removed, and removal is final
  (`remove_stopped`, `removed_final`); and
* after a host reboot no sandbox is active (`boot_inactive`).
-/

namespace Sandbox.Lifecycle

/-- The phase of one sandbox. -/
inductive Phase where
  | stopped
  | running
  | frozen
  | removed
  deriving Repr, DecidableEq

/-- An operation the daemon performs on one sandbox. -/
inductive Op where
  | start
  | stop
  | freeze
  | thaw
  | exec
  | snapshot
  | fork
  | remove
  deriving Repr, DecidableEq

/-- The phase after an operation, or `none` when the daemon rejects it. A
snapshot or fork leaves the sandbox in its phase; the fork's child starts
`stopped`. Stopping a frozen sandbox is allowed because systemd thaws a unit
before it stops it. -/
def next : Phase → Op → Option Phase
  | .stopped, .start => some .running
  | .running, .stop => some .stopped
  | .frozen, .stop => some .stopped
  | .running, .freeze => some .frozen
  | .frozen, .thaw => some .running
  | .running, .exec => some .running
  | .stopped, .snapshot => some .stopped
  | .frozen, .snapshot => some .frozen
  | .stopped, .fork => some .stopped
  | .frozen, .fork => some .frozen
  | .stopped, .remove => some .removed
  | _, _ => none

/-- Whether a process in the sandbox can write its writable layer. -/
def writable : Phase → Bool
  | .running => true
  | _ => false

/-- Whether an operation copies the writable layer. -/
def Op.copies : Op → Bool
  | .snapshot => true
  | .fork => true
  | _ => false

/-- Whether a sandbox has a systemd unit. -/
def active : Phase → Bool
  | .running => true
  | .frozen => true
  | _ => false

/-- The phase after a host reboot: no transient unit survives one. -/
def boot : Phase → Phase
  | .running => .stopped
  | .frozen => .stopped
  | ph => ph

/-- The writable layer is copied only while nothing can write it, and the
copy does not change the sandbox's phase. -/
theorem copy_quiescent {ph ph' : Phase} {op : Op} (copies : op.copies = true)
    (h : next ph op = some ph') : writable ph = false ∧ ph' = ph := by
  cases ph <;> cases op <;> simp_all [next, Op.copies, writable]

/-- Commands run only in a running sandbox. -/
theorem exec_running {ph ph' : Phase} (h : next ph .exec = some ph') : ph = .running := by
  cases ph <;> simp_all [next]

/-- Only a stopped sandbox is removed. -/
theorem remove_stopped {ph ph' : Phase} (h : next ph .remove = some ph') :
    ph = .stopped ∧ ph' = .removed := by
  cases ph <;> simp_all [next]

/-- A removed sandbox accepts no operation. -/
theorem removed_final (op : Op) : next .removed op = none := by
  cases op <;> rfl

/-- No operation other than removal produces a removed sandbox. -/
theorem removed_only_by_remove {ph : Phase} {op : Op} (h : next ph op = some .removed) :
    op = .remove := by
  cases ph <;> cases op <;> simp_all [next]

/-- Thawing undoes freezing. -/
theorem thaw_freeze {ph ph' : Phase} (h : next ph .freeze = some ph') :
    next ph' .thaw = some ph := by
  cases ph <;> simp only [next, Option.some.injEq, reduceCtorEq] at h <;> subst h <;> rfl

/-- After a reboot no sandbox has a unit, and a second reboot changes nothing. -/
theorem boot_inactive (ph : Phase) : active (boot ph) = false ∧ boot (boot ph) = boot ph := by
  cases ph <;> simp [boot, active]

end Sandbox.Lifecycle
