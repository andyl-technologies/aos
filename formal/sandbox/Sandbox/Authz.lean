import Sandbox.Lifecycle

/-!
# Request authorization

`aos-sandboxd` accepts requests on a Unix socket and identifies each client by
the credentials the kernel reports for the connection (`SO_PEERCRED`), never
by anything the client sends. The daemon serializes requests for a sandbox
with a lock, so each request is one atomic `dispatch` over the registry of
sandboxes.

The theorems state the authorization contract:

* a request that does not succeed changes nothing (`dispatch_unchanged`);
* a successful request was authorized: creation by a member of the users or
  admins group, any other operation by the sandbox's owner or an admin
  (`dispatch_authorized`);
* a request changes at most the sandbox it names (`dispatch_frame`);
* a sandbox's owner never changes (`owner_stable`), and a phase changes only
  along the lifecycle table (`phase_follows_lifecycle`); and
* a removed sandbox's identifier is never reused (`removed_permanent`).
-/

namespace Sandbox.Authz

open Lifecycle

/-- A client as the kernel reports it, with its user's groups. -/
structure Peer where
  /-- The client's user ID. -/
  uid : Nat
  /-- The groups of the client's user. -/
  groups : List Nat

/-- The daemon's configured groups. -/
structure Policy where
  /-- Members may create sandboxes. -/
  users : Nat
  /-- Members may operate on every sandbox. -/
  admins : Nat

/-- What the daemon records for one sandbox. -/
structure Record where
  /-- The user ID of the client that created the sandbox. -/
  owner : Nat
  /-- The sandbox's lifecycle phase. -/
  phase : Phase
  deriving DecidableEq

/-- The daemon's sandboxes by identifier. A removed sandbox keeps its record
as a tombstone. -/
abbrev Registry := Nat → Option Record

/-- A client request. -/
inductive Command where
  | create (id : Nat)
  | operate (id : Nat) (op : Op)

/-- The sandbox a request names. -/
def Command.target : Command → Nat
  | .create id => id
  | .operate id _ => id

/-- The daemon's answer to a request. -/
inductive Response where
  | ok
  | denied
  | notFound
  | conflict
  | rejected
  deriving DecidableEq

/-- Whether the client is an administrator. -/
def isAdmin (pol : Policy) (peer : Peer) : Bool :=
  decide (pol.admins ∈ peer.groups)

/-- Whether the client may create sandboxes. -/
def mayCreate (pol : Policy) (peer : Peer) : Bool :=
  decide (pol.users ∈ peer.groups) || isAdmin pol peer

/-- Whether the client may operate on a sandbox. -/
def mayOperate (pol : Policy) (peer : Peer) (rec : Record) : Bool :=
  peer.uid == rec.owner || isAdmin pol peer

/-- The registry with one record replaced. -/
def Registry.set (reg : Registry) (id : Nat) (rec : Record) : Registry :=
  fun j => if j = id then some rec else reg j

/-- Handles one request. Authorization is decided before the lifecycle table
is consulted, so a client learns nothing about a sandbox it may not operate
on beyond its existence. -/
def dispatch (pol : Policy) (peer : Peer) (reg : Registry) : Command → Registry × Response
  | .create id =>
    match reg id with
    | some _ => (reg, .conflict)
    | none =>
      if mayCreate pol peer then (reg.set id ⟨peer.uid, .stopped⟩, .ok) else (reg, .denied)
  | .operate id op =>
    match reg id with
    | none => (reg, .notFound)
    | some rec =>
      if mayOperate pol peer rec then
        match next rec.phase op with
        | none => (reg, .rejected)
        | some ph => (reg.set id { rec with phase := ph }, .ok)
      else (reg, .denied)

variable {pol : Policy} {peer : Peer} {reg : Registry}

/-- A request that does not succeed changes nothing. -/
theorem dispatch_unchanged {cmd : Command} (h : (dispatch pol peer reg cmd).2 ≠ .ok) :
    (dispatch pol peer reg cmd).1 = reg := by
  cases cmd <;> simp only [dispatch] at h ⊢ <;> (repeat' split) <;> simp_all

/-- A successful request was authorized. -/
theorem dispatch_authorized {cmd : Command} (h : (dispatch pol peer reg cmd).2 = .ok) :
    match cmd with
    | .create _ => mayCreate pol peer = true
    | .operate id _ => ∃ rec, reg id = some rec ∧ mayOperate pol peer rec = true := by
  cases cmd <;> simp only [dispatch] at h ⊢ <;> (repeat' split at h) <;> simp_all

/-- A request changes no sandbox other than the one it names. -/
theorem dispatch_frame {cmd : Command} {j : Nat} (hj : j ≠ cmd.target) :
    (dispatch pol peer reg cmd).1 j = reg j := by
  cases cmd <;> simp only [dispatch, Command.target] at hj ⊢ <;> (repeat' split) <;>
    simp_all [Registry.set]

/-- A sandbox's owner never changes. -/
theorem owner_stable {cmd : Command} {id : Nat} {rec rec' : Record} (before : reg id = some rec)
    (after : (dispatch pol peer reg cmd).1 id = some rec') : rec'.owner = rec.owner := by
  cases cmd <;> simp only [dispatch] at after <;> (repeat' split at after) <;>
    simp_all [Registry.set] <;> split at after <;> simp_all <;> subst_vars <;> rfl

/-- A sandbox's phase changes only along the lifecycle table. -/
theorem phase_follows_lifecycle {cmd : Command} {id : Nat} {rec rec' : Record}
    (before : reg id = some rec) (after : (dispatch pol peer reg cmd).1 id = some rec') :
    rec' = rec ∨ ∃ op, next rec.phase op = some rec'.phase := by
  cases cmd <;> simp only [dispatch] at after <;> (repeat' split at after) <;>
    simp_all [Registry.set] <;> split at after <;> simp_all <;> subst_vars <;> simp_all <;>
    exact .inr ⟨_, by assumption⟩

/-- A removed sandbox stays removed, so its identifier is never reused. -/
theorem removed_permanent {cmd : Command} {id : Nat} {rec : Record} (before : reg id = some rec)
    (removed : rec.phase = .removed) : (dispatch pol peer reg cmd).1 id = some rec := by
  cases cmd <;> simp only [dispatch] <;> (repeat' split) <;> simp_all [Registry.set] <;>
    intro hid <;> subst hid <;> simp_all [removed_final]

/-- Creating a sandbox records the client as its owner. -/
theorem create_owner {id : Nat} (h : (dispatch pol peer reg (.create id)).2 = .ok) :
    (dispatch pol peer reg (.create id)).1 id = some ⟨peer.uid, .stopped⟩ := by
  simp only [dispatch] at h ⊢
  repeat' split at h
  all_goals simp_all [Registry.set]

end Sandbox.Authz
