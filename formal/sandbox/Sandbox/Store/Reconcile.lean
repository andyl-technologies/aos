import Sandbox.Store.Closure

/-!
# Reconciling a sandbox's mounts

A sandbox's `/nix/store` holds one read-only bind mount per visible store
path. The host makes each mount or unmount on a shared staging directory, and
mount propagation shows it inside the sandbox at once. A process in the
sandbox can therefore observe every intermediate mount set, not only the
first and the last.

An update must keep every intermediate set closed, or a program could start
from a newly mounted path whose library is not mounted yet, or keep running
while a library it needs is unmounted. Mounting `p` is safe once its
references are mounted (`CanMount`); unmounting `p` is safe once no other
mounted path references it (`CanUnmount`). Mounts therefore go in dependency
order and unmounts in reverse, and doing all mounts before any unmount is
necessary but not sufficient.

`plan` orders the changes greedily and fails rather than emit an unsafe
order:

* `plan_guarded` and `plan_safe`: every state of a planned run is closed;
* `plan_run`: the run ends with exactly the target mounted;
* `plan_complete`: on a store with ranked references, which every Nix store
  has, a plan to any closed target exists from any mount set; and
* `plan_restart`: after a crash at any point of a run, the mount set is closed
  and a new plan to the same target exists.
-/

namespace Sandbox.Store

/-- One change to a sandbox's mount set. -/
inductive Change (α : Type) where
  | mount (p : α)
  | unmount (p : α)
  deriving Repr, DecidableEq

variable {α : Type} [DecidableEq α] {g : Graph α}

/-- Mounting `p` keeps a closed set closed: each reference of `p` is `p`
itself or already mounted. -/
def CanMount (g : Graph α) (s : List α) (p : α) : Prop :=
  ∀ q ∈ g.refs p, q = p ∨ q ∈ s

/-- Unmounting `p` keeps a closed set closed: no other mounted path
references `p`. -/
def CanUnmount (g : Graph α) (s : List α) (p : α) : Prop :=
  ∀ q ∈ s, q ≠ p → p ∉ g.refs q

/-- Decides `CanMount`. -/
def canMount (g : Graph α) (s : List α) (p : α) : Bool :=
  (g.refs p).all fun q => q == p || decide (q ∈ s)

/-- Decides `CanUnmount`. -/
def canUnmount (g : Graph α) (s : List α) (p : α) : Bool :=
  s.all fun q => q == p || !decide (p ∈ g.refs q)

theorem canMount_iff {s : List α} {p : α} : canMount g s p = true ↔ CanMount g s p := by
  unfold canMount CanMount
  rw [List.all_eq_true]
  constructor
  · intro h q hq
    have hq' := h q hq
    by_cases hqp : q = p
    · exact .inl hqp
    · exact .inr (by simpa [hqp] using hq')
  · intro h q hq
    rcases h q hq with hqp | hqs
    · simp [hqp]
    · simp [hqs]

theorem canUnmount_iff {s : List α} {p : α} : canUnmount g s p = true ↔ CanUnmount g s p := by
  unfold canUnmount CanUnmount
  rw [List.all_eq_true]
  constructor
  · intro h q hq hne hmem
    have hq' := h q hq
    simp [hne, hmem] at hq'
  · intro h q hq
    by_cases hqp : q = p
    · simp [hqp]
    · simp [h q hq hqp]

namespace Change

/-- Applies a change to a mount set. -/
def apply : Change α → List α → List α
  | .mount p, s => if p ∈ s then s else s ++ [p]
  | .unmount p, s => s.filter fun q => q != p

@[simp] theorem mem_apply_mount {p q : α} {s : List α} :
    q ∈ (Change.mount p).apply s ↔ q ∈ s ∨ q = p := by
  by_cases h : p ∈ s
  · simp only [apply, h, ↓reduceIte]
    constructor
    · exact .inl
    · rintro (hq | rfl)
      · exact hq
      · exact h
  · simp [apply, h]

@[simp] theorem mem_apply_unmount {p q : α} {s : List α} :
    q ∈ (Change.unmount p).apply s ↔ q ∈ s ∧ q ≠ p := by
  simp [apply]

/-- The guard under which a change keeps a closed mount set closed. -/
def Enabled (g : Graph α) (s : List α) : Change α → Prop
  | .mount p => CanMount g s p
  | .unmount p => CanUnmount g s p

/-- An enabled change keeps a closed mount set closed. -/
theorem Enabled.closed {s : List α} {c : Change α} (closed : Closed g s)
    (enabled : c.Enabled g s) : Closed g (c.apply s) := by
  cases c with
  | mount p =>
    have enabled : CanMount g s p := enabled
    intro x hx q hq
    rw [mem_apply_mount] at hx ⊢
    rcases hx with hx | rfl
    · exact .inl (closed x hx q hq)
    · rcases enabled q hq with rfl | hqs
      · exact .inr rfl
      · exact .inl hqs
  | unmount p =>
    have enabled : CanUnmount g s p := enabled
    intro x hx q hq
    rw [mem_apply_unmount] at hx ⊢
    refine ⟨closed x hx.1 q hq, ?_⟩
    rintro rfl
    exact enabled x hx.1 hx.2 hq

/-- Applies changes in order. -/
def run (s : List α) : List (Change α) → List α
  | [] => s
  | c :: cs => run (c.apply s) cs

/-- Every change is enabled in the mount set it applies to. -/
def Guarded (g : Graph α) : List α → List (Change α) → Prop
  | _, [] => True
  | s, c :: cs => c.Enabled g s ∧ Guarded g (c.apply s) cs

/-- Every mount set a run passes through, from the first to the last. -/
def trace (s : List α) : List (Change α) → List (List α)
  | [] => [s]
  | c :: cs => s :: trace (c.apply s) cs

theorem run_append (s : List α) (xs ys : List (Change α)) :
    run s (xs ++ ys) = run (run s xs) ys := by
  induction xs generalizing s with
  | nil => rfl
  | cons c cs ih => exact ih _

theorem guarded_append {s : List α} {xs ys : List (Change α)} :
    Guarded g s (xs ++ ys) ↔ Guarded g s xs ∧ Guarded g (run s xs) ys := by
  induction xs generalizing s with
  | nil => simp [Guarded, run]
  | cons c cs ih => simp [Guarded, run, ih, and_assoc]

/-- Every mount set of a guarded run from a closed set is closed. -/
theorem Guarded.closed_trace :
    ∀ {s : List α} {cs : List (Change α)}, Closed g s → Guarded g s cs →
      ∀ t ∈ trace s cs, Closed g t
  | _, [], closed, _, t, ht => by
    simp only [trace, List.mem_singleton] at ht
    subst ht
    exact closed
  | s, c :: cs, closed, guarded, t, ht => by
    have guarded : c.Enabled g s ∧ Guarded g (c.apply s) cs := guarded
    simp only [trace, List.mem_cons] at ht
    rcases ht with rfl | ht
    · exact closed
    · exact Guarded.closed_trace (guarded.1.closed closed) guarded.2 t ht

/-- Stopping a run after any number of changes leaves one of its traced sets. -/
theorem run_take_mem_trace :
    ∀ (s : List α) (cs : List (Change α)) (k : Nat), run s (cs.take k) ∈ trace s cs
  | s, [], _ => by simp [run, trace]
  | s, _ :: _, 0 => by simp [run, trace]
  | s, c :: cs, k + 1 => by
    simp only [List.take_succ_cons, run, trace, List.mem_cons]
    exact .inr (run_take_mem_trace _ cs k)

end Change

/-! ## Planning -/

/-- Orders the pending mounts so that each path's references are mounted
before it, or returns `none` when no pending path can be mounted next. -/
def planMounts (g : Graph α) : Nat → List α → List α → Option (List (Change α))
  | _, _, [] => some []
  | 0, _, _ :: _ => none
  | fuel + 1, s, x :: xs =>
    match (x :: xs).find? (canMount g s) with
    | none => none
    | some p =>
      (planMounts g fuel ((Change.mount p).apply s) ((x :: xs).filter fun q => q != p)).map
        (Change.mount p :: ·)

/-- Orders the pending unmounts so that each path's referrers are unmounted
before it, or returns `none` when no pending path can be unmounted next. -/
def planUnmounts (g : Graph α) : Nat → List α → List α → Option (List (Change α))
  | _, _, [] => some []
  | 0, _, _ :: _ => none
  | fuel + 1, s, x :: xs =>
    match (x :: xs).find? (canUnmount g s) with
    | none => none
    | some p =>
      (planUnmounts g fuel ((Change.unmount p).apply s) ((x :: xs).filter fun q => q != p)).map
        (Change.unmount p :: ·)

/-- Plans the changes from `mounted` to `target`: the missing paths in
dependency order, then the extra paths in reverse dependency order. -/
def plan (g : Graph α) (mounted target : List α) : Option (List (Change α)) :=
  match planMounts g (diff target mounted).length mounted (diff target mounted) with
  | none => none
  | some mounts =>
    match planUnmounts g (diff mounted target).length (Change.run mounted mounts)
        (diff mounted target) with
    | none => none
    | some unmounts => some (mounts ++ unmounts)

section Soundness

theorem planMounts_guarded :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planMounts g fuel s pending = some cs → Change.Guarded g s cs
  | _, _, [], cs, h => by
    simp only [planMounts, Option.some.injEq] at h
    subst h
    trivial
  | 0, _, _ :: _, _, h => by simp [planMounts] at h
  | fuel + 1, s, x :: xs, cs, h => by
    simp only [planMounts] at h
    split at h
    · simp at h
    · next p hfind =>
      cases hrest : planMounts g fuel ((Change.mount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        exact And.intro (canMount_iff.mp (List.find?_some hfind)) (planMounts_guarded hrest)

theorem planMounts_mem :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planMounts g fuel s pending = some cs →
      ∀ q, q ∈ Change.run s cs ↔ q ∈ s ∨ q ∈ pending
  | _, _, [], cs, h, q => by
    simp only [planMounts, Option.some.injEq] at h
    subst h
    simp [Change.run]
  | 0, _, _ :: _, _, h, _ => by simp [planMounts] at h
  | fuel + 1, s, x :: xs, cs, h, q => by
    simp only [planMounts] at h
    split at h
    · simp at h
    · next p hfind =>
      cases hrest : planMounts g fuel ((Change.mount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        have hp := List.mem_of_find?_eq_some hfind
        rw [Change.run, planMounts_mem hrest q, Change.mem_apply_mount, List.mem_filter]
        by_cases hqp : q = p
        · subst hqp
          simp [hp]
        · simp [hqp]

theorem planMounts_changes :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planMounts g fuel s pending = some cs → ∀ c ∈ cs, ∃ p ∈ pending, c = .mount p
  | _, _, [], cs, h, c, hc => by
    simp only [planMounts, Option.some.injEq] at h
    subst h
    simp at hc
  | 0, _, _ :: _, _, h, _, _ => by simp [planMounts] at h
  | fuel + 1, s, x :: xs, cs, h, c, hc => by
    simp only [planMounts] at h
    split at h
    · simp at h
    · next p hfind =>
      cases hrest : planMounts g fuel ((Change.mount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        rcases List.mem_cons.mp hc with rfl | hc
        · exact ⟨p, List.mem_of_find?_eq_some hfind, rfl⟩
        · obtain ⟨p', hp', rfl⟩ := planMounts_changes hrest c hc
          exact ⟨p', (List.mem_filter.mp hp').1, rfl⟩

theorem planUnmounts_guarded :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planUnmounts g fuel s pending = some cs → Change.Guarded g s cs
  | _, _, [], cs, h => by
    simp only [planUnmounts, Option.some.injEq] at h
    subst h
    trivial
  | 0, _, _ :: _, _, h => by simp [planUnmounts] at h
  | fuel + 1, s, x :: xs, cs, h => by
    simp only [planUnmounts] at h
    split at h
    · simp at h
    · next p hfind =>
      cases hrest : planUnmounts g fuel ((Change.unmount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        exact And.intro (canUnmount_iff.mp (List.find?_some hfind))
          (planUnmounts_guarded hrest)

theorem planUnmounts_mem :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planUnmounts g fuel s pending = some cs →
      ∀ q, q ∈ Change.run s cs ↔ q ∈ s ∧ q ∉ pending
  | _, _, [], cs, h, q => by
    simp only [planUnmounts, Option.some.injEq] at h
    subst h
    simp [Change.run]
  | 0, _, _ :: _, _, h, _ => by simp [planUnmounts] at h
  | fuel + 1, s, x :: xs, cs, h, q => by
    simp only [planUnmounts] at h
    split at h
    · simp at h
    · next p hfind =>
      cases hrest : planUnmounts g fuel ((Change.unmount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        have hp := List.mem_of_find?_eq_some hfind
        rw [Change.run, planUnmounts_mem hrest q, Change.mem_apply_unmount, List.mem_filter]
        by_cases hqp : q = p
        · subst hqp
          simp [hp]
        · simp [hqp]

theorem planUnmounts_changes :
    ∀ {fuel : Nat} {s pending : List α} {cs : List (Change α)},
      planUnmounts g fuel s pending = some cs → ∀ c ∈ cs, ∃ p, c = .unmount p
  | _, _, [], cs, h, c, hc => by
    simp only [planUnmounts, Option.some.injEq] at h
    subst h
    simp at hc
  | 0, _, _ :: _, _, h, _, _ => by simp [planUnmounts] at h
  | fuel + 1, s, x :: xs, cs, h, c, hc => by
    simp only [planUnmounts] at h
    split at h
    · simp at h
    · next p _ =>
      cases hrest : planUnmounts g fuel ((Change.unmount p).apply s)
          ((x :: xs).filter fun q => q != p) with
      | none => simp [hrest] at h
      | some rest =>
        simp only [hrest, Option.map_some, Option.some.injEq] at h
        subst h
        rcases List.mem_cons.mp hc with rfl | hc
        · exact ⟨p, rfl⟩
        · exact planUnmounts_changes hrest c hc

theorem plan_eq_some {m t : List α} {cs : List (Change α)} (h : plan g m t = some cs) :
    ∃ mounts unmounts,
      planMounts g (diff t m).length m (diff t m) = some mounts ∧
      planUnmounts g (diff m t).length (Change.run m mounts) (diff m t) = some unmounts ∧
      cs = mounts ++ unmounts := by
  unfold plan at h
  split at h
  · simp at h
  · next mounts hm =>
    split at h
    · simp at h
    · next unmounts hu =>
      exact ⟨mounts, unmounts, hm, hu, (Option.some.inj h).symm⟩

/-- Every change of a plan is enabled where it applies. -/
theorem plan_guarded {m t : List α} {cs : List (Change α)} (h : plan g m t = some cs) :
    Change.Guarded g m cs := by
  obtain ⟨mounts, unmounts, hm, hu, rfl⟩ := plan_eq_some h
  exact Change.guarded_append.mpr ⟨planMounts_guarded hm, planUnmounts_guarded hu⟩

/-- A planned run ends with exactly the target mounted. -/
theorem plan_run {m t : List α} {cs : List (Change α)} (h : plan g m t = some cs) :
    ∀ q, q ∈ Change.run m cs ↔ q ∈ t := by
  obtain ⟨mounts, unmounts, hm, hu, rfl⟩ := plan_eq_some h
  intro q
  rw [Change.run_append, planUnmounts_mem hu q, planMounts_mem hm q, mem_diff, mem_diff]
  by_cases hqt : q ∈ t <;> by_cases hqm : q ∈ m <;> simp [hqt, hqm]

/-- A plan mounts only target paths. -/
theorem plan_mounts {m t : List α} {cs : List (Change α)} (h : plan g m t = some cs) :
    ∀ p, Change.mount p ∈ cs → p ∈ t := by
  obtain ⟨mounts, unmounts, hm, hu, rfl⟩ := plan_eq_some h
  intro p hp
  rcases List.mem_append.mp hp with hp | hp
  · obtain ⟨p', hp', heq⟩ := planMounts_changes hm _ hp
    cases heq
    exact (mem_diff.mp hp').1
  · obtain ⟨_, heq⟩ := planUnmounts_changes hu _ hp
    cases heq

/-- Every mount set a planned run passes through is closed. -/
theorem plan_safe {m t : List α} {cs : List (Change α)} (closed : Closed g m)
    (h : plan g m t = some cs) : ∀ s ∈ Change.trace m cs, Closed g s :=
  (plan_guarded h).closed_trace closed

end Soundness

/-! ## Completeness -/

section Completeness

/-- A rank that strictly decreases along every reference other than a
self-reference. A Nix store path's references are fixed before the path
exists, so they were valid earlier; the order in which paths became valid
ranks every store. -/
def Ranked (g : Graph α) (rank : α → Nat) : Prop :=
  ∀ p q, q ∈ g.refs p → q ≠ p → rank q < rank p

omit [DecidableEq α] in
theorem exists_min_rank (rank : α → Nat) :
    ∀ {l : List α}, l ≠ [] → ∃ p ∈ l, ∀ q ∈ l, rank p ≤ rank q
  | [], h => absurd rfl h
  | [x], _ => ⟨x, by simp, by simp⟩
  | x :: y :: ys, _ => by
    obtain ⟨m, hm, hmin⟩ := exists_min_rank rank (l := y :: ys) (by simp)
    by_cases hle : rank x ≤ rank m
    · refine ⟨x, by simp, ?_⟩
      intro q hq
      rcases List.mem_cons.mp hq with rfl | hq
      · exact Nat.le_refl _
      · exact Nat.le_trans hle (hmin q hq)
    · refine ⟨m, List.mem_cons_of_mem _ hm, ?_⟩
      intro q hq
      rcases List.mem_cons.mp hq with rfl | hq
      · omega
      · exact hmin q hq

omit [DecidableEq α] in
theorem exists_max_rank (rank : α → Nat) :
    ∀ {l : List α}, l ≠ [] → ∃ p ∈ l, ∀ q ∈ l, rank q ≤ rank p
  | [], h => absurd rfl h
  | [x], _ => ⟨x, by simp, by simp⟩
  | x :: y :: ys, _ => by
    obtain ⟨m, hm, hmax⟩ := exists_max_rank rank (l := y :: ys) (by simp)
    by_cases hle : rank m ≤ rank x
    · refine ⟨x, by simp, ?_⟩
      intro q hq
      rcases List.mem_cons.mp hq with rfl | hq
      · exact Nat.le_refl _
      · exact Nat.le_trans (hmax q hq) hle
    · refine ⟨m, List.mem_cons_of_mem _ hm, ?_⟩
      intro q hq
      rcases List.mem_cons.mp hq with rfl | hq
      · omega
      · exact hmax q hq

theorem length_filter_ne_lt {p : α} :
    ∀ {l : List α}, p ∈ l → (l.filter fun q => q != p).length < l.length
  | [], h => by simp at h
  | x :: xs, h => by
    by_cases hxp : x = p
    · subst hxp
      have hle := List.length_filter_le (fun q => q != x) xs
      simp at hle ⊢
      omega
    · have hmem : p ∈ xs := by
        rcases List.mem_cons.mp h with h | h
        · exact absurd h.symm hxp
        · exact h
      have ih := length_filter_ne_lt hmem
      simp [hxp] at ih ⊢
      omega

theorem planMounts_complete {rank : α → Nat} (ranked : Ranked g rank) :
    ∀ {fuel : Nat} {s pending : List α}, pending.length ≤ fuel →
      (∀ p ∈ pending, ∀ q ∈ g.refs p, q = p ∨ q ∈ s ∨ q ∈ pending) →
      ∃ cs, planMounts g fuel s pending = some cs
  | _, _, [], _, _ => ⟨[], by simp [planMounts]⟩
  | 0, _, _ :: _, hlen, _ => by simp at hlen
  | fuel + 1, s, x :: xs, hlen, hrefs => by
    -- The lowest-ranked pending path references nothing else that is pending.
    obtain ⟨m, hm, hmin⟩ := exists_min_rank rank (l := x :: xs) (by simp)
    have hmount : canMount g s m = true := by
      rw [canMount_iff]
      intro q hq
      rcases hrefs m hm q hq with h | h | h
      · exact .inl h
      · exact .inr h
      · by_cases hqm : q = m
        · exact .inl hqm
        · exact absurd (hmin q h) (Nat.not_le.mpr (ranked m q hq hqm))
    cases hfind : (x :: xs).find? (canMount g s) with
    | none => exact absurd hmount (List.find?_eq_none.mp hfind m hm)
    | some p =>
      have hp := List.mem_of_find?_eq_some hfind
      have hshorter := length_filter_ne_lt hp
      obtain ⟨rest, hrest⟩ := planMounts_complete ranked (fuel := fuel)
        (s := (Change.mount p).apply s) (pending := (x :: xs).filter fun q => q != p)
        (by omega)
        (by
          intro p' hp' q hq
          rcases hrefs p' (List.mem_filter.mp hp').1 q hq with h | h | h
          · exact .inl h
          · exact .inr (.inl (Change.mem_apply_mount.mpr (.inl h)))
          · by_cases hqp : q = p
            · exact .inr (.inl (Change.mem_apply_mount.mpr (.inr hqp)))
            · exact .inr (.inr (List.mem_filter.mpr ⟨h, by simp [hqp]⟩)))
      exact ⟨Change.mount p :: rest, by simp [planMounts, hfind, hrest]⟩

theorem planUnmounts_complete {rank : α → Nat} (ranked : Ranked g rank) :
    ∀ {fuel : Nat} {s pending : List α}, pending.length ≤ fuel →
      (∀ q ∈ s, ∀ p ∈ pending, p ∈ g.refs q → q = p ∨ q ∈ pending) →
      ∃ cs, planUnmounts g fuel s pending = some cs
  | _, _, [], _, _ => ⟨[], by simp [planUnmounts]⟩
  | 0, _, _ :: _, hlen, _ => by simp at hlen
  | fuel + 1, s, x :: xs, hlen, hreferrers => by
    -- The highest-ranked pending path has no pending referrer.
    obtain ⟨m, hm, hmax⟩ := exists_max_rank rank (l := x :: xs) (by simp)
    have hunmount : canUnmount g s m = true := by
      rw [canUnmount_iff]
      intro q hq hqm hmq
      rcases hreferrers q hq m hm hmq with h | h
      · exact hqm h
      · exact absurd (hmax q h) (Nat.not_le.mpr (ranked q m hmq (Ne.symm hqm)))
    cases hfind : (x :: xs).find? (canUnmount g s) with
    | none => exact absurd hunmount (List.find?_eq_none.mp hfind m hm)
    | some p =>
      have hp := List.mem_of_find?_eq_some hfind
      have hshorter := length_filter_ne_lt hp
      obtain ⟨rest, hrest⟩ := planUnmounts_complete ranked (fuel := fuel)
        (s := (Change.unmount p).apply s) (pending := (x :: xs).filter fun q => q != p)
        (by omega)
        (by
          intro q hq p' hp' hpq
          have hq := Change.mem_apply_unmount.mp hq
          rcases hreferrers q hq.1 p' (List.mem_filter.mp hp').1 hpq with h | h
          · exact .inl h
          · exact .inr (List.mem_filter.mpr ⟨h, by simp [hq.2]⟩))
      exact ⟨Change.unmount p :: rest, by simp [planUnmounts, hfind, hrest]⟩

/-- On a ranked store, a plan from any mount set to a closed target exists. -/
theorem plan_complete {rank : α → Nat} (ranked : Ranked g rank) {t : List α}
    (closed : Closed g t) (m : List α) : ∃ cs, plan g m t = some cs := by
  obtain ⟨mounts, hm⟩ := planMounts_complete ranked (fuel := (diff t m).length) (s := m)
    (pending := diff t m) (Nat.le_refl _) (by
      intro p hp q hq
      by_cases hqm : q ∈ m
      · exact .inr (.inl hqm)
      · exact .inr (.inr (mem_diff.mpr ⟨closed p (mem_diff.mp hp).1 q hq, hqm⟩)))
  obtain ⟨unmounts, hu⟩ := planUnmounts_complete ranked (fuel := (diff m t).length)
    (s := Change.run m mounts) (pending := diff m t) (Nat.le_refl _) (by
      intro q hq p hp hpq
      -- The target is closed, so a referrer of a path outside it is outside it too.
      have hqt : q ∉ t := fun hqt => (mem_diff.mp hp).2 (closed q hqt p hpq)
      have hqm : q ∈ m := by
        rcases (planMounts_mem hm q).mp hq with hq | hq
        · exact hq
        · exact absurd (mem_diff.mp hq).1 hqt
      exact .inr (mem_diff.mpr ⟨hqm, hqt⟩))
  exact ⟨mounts ++ unmounts, by simp [plan, hm, hu]⟩

/-- Crash recovery: a run interrupted after any number of changes leaves a
closed mount set, and a new plan from it to the same target exists. -/
theorem plan_restart {rank : α → Nat} (ranked : Ranked g rank) {m t : List α}
    {cs : List (Change α)} (closedM : Closed g m) (closedT : Closed g t)
    (h : plan g m t = some cs) (k : Nat) :
    Closed g (Change.run m (cs.take k)) ∧ ∃ cs', plan g (Change.run m (cs.take k)) t = some cs' :=
  ⟨plan_safe closedM h _ (Change.run_take_mem_trace m cs k), plan_complete ranked closedT _⟩

end Completeness

end Sandbox.Store
