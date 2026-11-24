import Sandbox.Store.Update

/-!
# The Nix daemon proxy

In closure mode a sandbox sees only the closure of its roots, yet a build
inside it must be able to use what it builds. `aos-sbx-nixproxy` sits on the
sandbox's daemon socket and forwards ordinary client requests to the host's
Nix daemon. When a request makes paths valid (a build, a substitution, an
addition, or `EnsurePath`), the proxy adds them to the sandbox's desired
roots and runs the store update procedure before it answers, so `./result`
never points at a path the sandbox cannot see. Requests that change
daemon-wide state are refused without being forwarded.

The theorems state the proxy's contract:

* after a successful build reply, every output's closure is mounted
  (`realize_visible`);
* the proxy only adds roots, so nothing visible disappears through it
  (`handle_monotone`); only the owner's `aos-sandbox store rm` removes roots;
* a failed or refused request changes nothing (`handle_unchanged`); and
* the session's roots and mounts always match its desired roots
  (`handle_consistent`).

The session's roots and mounts here are the procedure's planned results;
`Store.procedure_exec` proves that executing the actions on the real host
produces them while the garbage collector and other builds run.
-/

namespace Sandbox.Proxy

open Store

/-- A daemon request from a sandbox, classified by its effect. -/
inductive Request (α : Type) where
  /-- Reads store metadata, such as path information or validity. -/
  | query (p : α)
  /-- Builds, substitutes, or adds paths; the daemon reports `outputs`. -/
  | realize (outputs : List α)
  /-- Changes daemon-wide state: collection, store optimization or
  verification, a GC root outside the sandbox's directory, or a trusted
  setting. -/
  | administer

/-- The proxy's answer to a request. -/
inductive Reply where
  | ok
  | refused
  | failed
  deriving DecidableEq

/-- The proxy's view of one sandbox. -/
structure Session (α : Type) where
  /-- The sandbox's requested root paths. -/
  desired : List α
  /-- The registered GC roots. -/
  roots : List α
  /-- The mounted store paths. -/
  mounted : List α

variable {α : Type} [DecidableEq α] {g : Graph α}

/-- Whether the proxy sends a request to the host's daemon. -/
def forwards : Request α → Bool
  | .administer => false
  | _ => true

/-- Handles one request. `fuel` bounds the closure computation. A realized
path's closure is exposed before the reply; if that fails, the reply is a
failure and the session is unchanged. -/
def handle (g : Graph α) (fuel : Nat) (s : Session α) : Request α → Reply × Session α
  | .query _ => (.ok, s)
  | .administer => (.refused, s)
  | .realize outputs =>
    let desired := s.desired ++ diff outputs s.desired
    match closure? g desired fuel with
    | none => (.failed, s)
    | some target =>
      match procedure g s.roots s.mounted desired target with
      | none => (.failed, s)
      | some acts =>
        (.ok, { desired, roots := Action.runRoots s.roots acts,
                mounted := Action.runMounted s.mounted acts })

/-- The session's roots are its desired roots and its mounts their closure. -/
def Consistent (g : Graph α) (s : Session α) : Prop :=
  (∀ r, r ∈ s.roots ↔ r ∈ s.desired) ∧ (∀ p, p ∈ s.mounted ↔ InClosure g s.desired p)

/-- The result of a successful realization. -/
theorem handle_realize_ok {fuel : Nat} {s s' : Session α} {outputs : List α}
    (h : handle g fuel s (.realize outputs) = (.ok, s')) :
    s'.desired = s.desired ++ diff outputs s.desired ∧ Consistent g s' := by
  simp only [handle] at h
  split at h
  · simp at h
  · next target htarget =>
    split at h
    · simp at h
    · next acts hacts =>
      simp only [Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      obtain ⟨_, roots, mounted⟩ := procedure_correct (closure?_spec htarget) hacts
      exact ⟨rfl, roots, mounted⟩

/-- After a successful build reply, every output's closure is mounted. -/
theorem realize_visible {fuel : Nat} {s s' : Session α} {outputs : List α}
    (h : handle g fuel s (.realize outputs) = (.ok, s')) :
    ∀ o ∈ outputs, ∀ p, InClosure g [o] p → p ∈ s'.mounted := by
  obtain ⟨hdesired, _, mounted⟩ := handle_realize_ok h
  intro o ho p hp
  refine (mounted p).mpr (hp.mono ?_)
  intro r hr
  rw [List.mem_singleton] at hr
  subst hr
  rw [hdesired, List.mem_append, mem_diff]
  by_cases hd : r ∈ s.desired
  · exact .inl hd
  · exact .inr ⟨ho, hd⟩

/-- A failed or refused request changes nothing. -/
theorem handle_unchanged {fuel : Nat} {s : Session α} {req : Request α}
    (h : (handle g fuel s req).1 ≠ .ok) : (handle g fuel s req).2 = s := by
  cases req with
  | query _ => simp [handle] at h
  | administer => rfl
  | realize outputs =>
    simp only [handle] at h ⊢
    split <;> (try rfl)
    split <;> (try rfl)
    simp_all

/-- The proxy refuses exactly the requests it does not forward. -/
theorem refused_iff_not_forwarded {fuel : Nat} {s : Session α} {req : Request α} :
    (handle g fuel s req).1 = .refused ↔ forwards req = false := by
  cases req with
  | query _ => simp [handle, forwards]
  | administer => simp [handle, forwards]
  | realize outputs =>
    simp only [handle, forwards]
    split
    · simp
    · split <;> simp

/-- The proxy never removes a desired root. -/
theorem handle_monotone {fuel : Nat} {s : Session α} {req : Request α} :
    ∀ d ∈ s.desired, d ∈ (handle g fuel s req).2.desired := by
  intro d hd
  by_cases hok : (handle g fuel s req).1 = .ok
  · cases req with
    | query _ => simpa [handle] using hd
    | administer => simp [handle] at hok
    | realize outputs =>
      have h : handle g fuel s (.realize outputs) =
          (.ok, (handle g fuel s (.realize outputs)).2) := by
        rw [← hok]
      rw [(handle_realize_ok h).1]
      exact List.mem_append_left _ hd
  · rw [handle_unchanged hok]
    exact hd

/-- Every request keeps a consistent session consistent. -/
theorem handle_consistent {fuel : Nat} {s : Session α} {req : Request α}
    (consistent : Consistent g s) : Consistent g (handle g fuel s req).2 := by
  by_cases hok : (handle g fuel s req).1 = .ok
  · cases req with
    | query _ => simpa [handle] using consistent
    | administer => simp [handle] at hok
    | realize outputs =>
      have h : handle g fuel s (.realize outputs) =
          (.ok, (handle g fuel s (.realize outputs)).2) := by
        rw [← hok]
      exact (handle_realize_ok h).2
  · rw [handle_unchanged hok]
    exact consistent

end Sandbox.Proxy
