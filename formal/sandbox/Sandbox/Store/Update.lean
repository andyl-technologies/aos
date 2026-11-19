import Sandbox.Store.Reconcile

/-!
# GC roots and the store update procedure

A bind mount does not keep a store path alive. If the host's garbage
collector deleted a mounted path, the sandbox would lose its files from under
it. The sandbox therefore registers one GC root per requested root path in its
own GC-root directory, and Nix keeps the closure of every root valid.

`procedure` is the whole update that `aos-sbx-store` performs: register the
new roots, apply a `plan`, then drop the old roots. Each `Action` changes one
thing, and the garbage collector and other builds may run between any two
actions (`Concurrent`). The design decisions the theorems depend on are:

* Registering a root realizes it in the same daemon operation (`Effect.addRoot`):
  the Nix daemon holds a temporary root on the path while it builds or
  substitutes it, so the garbage collector never sees the path both valid and
  unrooted. Realizing a path and rooting it in two separate steps would leave
  a window for the collector.
* A path is mounted only while a root reaches it, and a root is dropped only
  after the paths that need it are unmounted (`Action.Allowed`).

`procedure_exec` proves that executing the actions in order, with any
interleaving of collection and builds, keeps the host `Safe`: every mounted
path stays valid, and the mount set stays closed. It ends with exactly the
desired roots registered and their closure mounted. `procedure_crash` proves
that a crash after any action leaves a safe host from which a new procedure
exists, so rerunning the update after a crash or reboot is always correct.
-/

namespace Sandbox.Store

/-- The host state one sandbox's store update reads and changes. -/
structure Host (α : Type) where
  /-- Whether a path is valid in the host store. -/
  valid : α → Prop
  /-- The paths with a GC root in the sandbox's GC-root directory. -/
  roots : List α
  /-- The store paths bound into the sandbox. -/
  mounted : List α

/-- One step of a store update. -/
inductive Action (α : Type) where
  /-- Realize a path and register a GC root for it. -/
  | addRoot (r : α)
  /-- Bind a store path into the sandbox. -/
  | mount (p : α)
  /-- Remove a store path's bind mount from the sandbox. -/
  | unmount (p : α)
  /-- Remove a path's GC root. -/
  | dropRoot (r : α)
  deriving Repr, DecidableEq

variable {α : Type} [DecidableEq α] {g : Graph α}

namespace Action

/-- The roots after an action. -/
def nextRoots : Action α → List α → List α
  | .addRoot r, roots => roots ++ [r]
  | .dropRoot r, roots => roots.filter fun q => q != r
  | .mount _, roots => roots
  | .unmount _, roots => roots

/-- The mount set after an action. -/
def nextMounted : Action α → List α → List α
  | .mount p, s => (Change.mount p).apply s
  | .unmount p, s => (Change.unmount p).apply s
  | .addRoot _, s => s
  | .dropRoot _, s => s

/-- The condition under which an action keeps the host safe. It depends only
on the roots and the mount set, which only the sandbox's own update changes. -/
def Allowed (g : Graph α) (roots mounted : List α) : Action α → Prop
  | .addRoot _ => True
  | .mount p => InClosure g roots p ∧ CanMount g mounted p
  | .unmount p => CanUnmount g mounted p
  | .dropRoot r => ∀ p ∈ mounted, InClosure g (roots.filter fun q => q != r) p

/-- The roots after a sequence of actions. -/
def runRoots (roots : List α) : List (Action α) → List α
  | [] => roots
  | a :: as => runRoots (a.nextRoots roots) as

/-- The mount set after a sequence of actions. -/
def runMounted (mounted : List α) : List (Action α) → List α
  | [] => mounted
  | a :: as => runMounted (a.nextMounted mounted) as

/-- Every action is allowed in the state it applies to. -/
def Guarded (g : Graph α) : List α → List α → List (Action α) → Prop
  | _, _, [] => True
  | roots, mounted, a :: as =>
    a.Allowed g roots mounted ∧ Guarded g (a.nextRoots roots) (a.nextMounted mounted) as

theorem runRoots_append (roots : List α) (xs ys : List (Action α)) :
    runRoots roots (xs ++ ys) = runRoots (runRoots roots xs) ys := by
  induction xs generalizing roots with
  | nil => rfl
  | cons a as ih => exact ih _

theorem runMounted_append (mounted : List α) (xs ys : List (Action α)) :
    runMounted mounted (xs ++ ys) = runMounted (runMounted mounted xs) ys := by
  induction xs generalizing mounted with
  | nil => rfl
  | cons a as ih => exact ih _

theorem guarded_append {roots mounted : List α} {xs ys : List (Action α)} :
    Guarded g roots mounted (xs ++ ys) ↔
      Guarded g roots mounted xs ∧ Guarded g (runRoots roots xs) (runMounted mounted xs) ys := by
  induction xs generalizing roots mounted with
  | nil => simp [Guarded, runRoots, runMounted]
  | cons a as ih => simp [Guarded, runRoots, runMounted, ih, and_assoc]

/-- A prefix of a guarded sequence is guarded. -/
theorem Guarded.take :
    ∀ {roots mounted : List α} {acts : List (Action α)} (k : Nat),
      Guarded g roots mounted acts → Guarded g roots mounted (acts.take k)
  | _, _, [], _, _ => by simp [Guarded]
  | _, _, _ :: _, 0, _ => by simp [Guarded]
  | roots, mounted, a :: as, k + 1, guarded => by
    have guarded :
        a.Allowed g roots mounted ∧ Guarded g (a.nextRoots roots) (a.nextMounted mounted) as :=
      guarded
    simp only [List.take_succ_cons]
    exact And.intro guarded.1 (Guarded.take k guarded.2)

end Action

/-! ## Execution against a concurrent host -/

/-- The effect of one action on the host. Registering a root also makes the
root's closure valid, because the daemon realizes the path under a temporary
root before it registers the permanent one. -/
inductive Effect (g : Graph α) : Action α → Host α → Host α → Prop where
  | addRoot {r : α} {h : Host α} {valid : α → Prop}
      (keeps : ∀ p, h.valid p → valid p) (realizes : ∀ p, InClosure g [r] p → valid p) :
      Effect g (.addRoot r) h { h with valid := valid, roots := h.roots ++ [r] }
  | mount {p : α} {h : Host α} :
      Effect g (.mount p) h { h with mounted := (Change.mount p).apply h.mounted }
  | unmount {p : α} {h : Host α} :
      Effect g (.unmount p) h { h with mounted := (Change.unmount p).apply h.mounted }
  | dropRoot {r : α} {h : Host α} :
      Effect g (.dropRoot r) h { h with roots := h.roots.filter fun q => q != r }

/-- What the rest of the host may do between two actions. The garbage
collector may delete any path no root reaches; builds and substitutions may
make paths valid. Neither touches the sandbox's roots or mounts. -/
inductive Concurrent (g : Graph α) : Host α → Host α → Prop where
  | collect {h : Host α} {valid : α → Prop} (_deletes : ∀ p, valid p → h.valid p)
      (keeps : ∀ p, InClosure g h.roots p → h.valid p → valid p) :
      Concurrent g h { h with valid := valid }
  | realize {h : Host α} {valid : α → Prop} (keeps : ∀ p, h.valid p → valid p) :
      Concurrent g h { h with valid := valid }

/-- Executing a sequence of actions in order, with concurrent host steps
anywhere between them. -/
inductive Exec (g : Graph α) : List (Action α) → Host α → Host α → Prop where
  | done {h : Host α} : Exec g [] h h
  | concurrent {acts : List (Action α)} {h h' h'' : Host α} :
      Concurrent g h h' → Exec g acts h' h'' → Exec g acts h h''
  | act {a : Action α} {acts : List (Action α)} {h h' h'' : Host α} :
      Effect g a h h' → Exec g acts h' h'' → Exec g (a :: acts) h h''

/-- The host invariant of a sandbox's store. -/
structure Safe (g : Graph α) (h : Host α) : Prop where
  /-- The collector has deleted nothing a root reaches. -/
  rooted_valid : ∀ p, InClosure g h.roots p → h.valid p
  /-- A root reaches every mounted path. -/
  mounted_rooted : ∀ p ∈ h.mounted, InClosure g h.roots p
  /-- Every mounted path's references are mounted. -/
  mounted_closed : Closed g h.mounted

omit [DecidableEq α] in
/-- A sandbox with no roots and no mounts is safe. -/
theorem safe_empty (valid : α → Prop) : Safe g { valid, roots := [], mounted := [] } where
  rooted_valid _ h := by
    exfalso
    induction h with
    | root hr => simp at hr
    | ref _ _ ih => exact ih
  mounted_rooted _ hp := by simp at hp
  mounted_closed _ hp := by simp at hp

omit [DecidableEq α] in
/-- In a safe host every mounted path is valid. -/
theorem Safe.mounted_valid {h : Host α} (safe : Safe g h) : ∀ p ∈ h.mounted, h.valid p :=
  fun p hp => safe.rooted_valid p (safe.mounted_rooted p hp)

omit [DecidableEq α] in
theorem Concurrent.safe {h h' : Host α} (step : Concurrent g h h') (safe : Safe g h) :
    Safe g h' ∧ h'.roots = h.roots ∧ h'.mounted = h.mounted := by
  cases step with
  | collect _ keeps =>
    exact ⟨⟨fun p hp => keeps p hp (safe.rooted_valid p hp), safe.mounted_rooted,
      safe.mounted_closed⟩, rfl, rfl⟩
  | realize keeps =>
    exact ⟨⟨fun p hp => keeps p (safe.rooted_valid p hp), safe.mounted_rooted,
      safe.mounted_closed⟩, rfl, rfl⟩

theorem Effect.safe {a : Action α} {h h' : Host α} (eff : Effect g a h h')
    (allowed : a.Allowed g h.roots h.mounted) (safe : Safe g h) :
    Safe g h' ∧ h'.roots = a.nextRoots h.roots ∧ h'.mounted = a.nextMounted h.mounted := by
  cases eff with
  | addRoot keeps realizes =>
    refine ⟨⟨?_, ?_, safe.mounted_closed⟩, rfl, rfl⟩
    · intro p hp
      rcases InClosure.append_cases hp with hp | hp
      · exact keeps p (safe.rooted_valid p hp)
      · exact realizes p hp
    · intro p hp
      exact (safe.mounted_rooted p hp).mono fun q hq => List.mem_append_left _ hq
  | @mount p _ =>
    have allowed : InClosure g h.roots p ∧ CanMount g h.mounted p := allowed
    refine ⟨⟨safe.rooted_valid, ?_, ?_⟩, rfl, rfl⟩
    · intro q hq
      rcases Change.mem_apply_mount.mp hq with hq | rfl
      · exact safe.mounted_rooted q hq
      · exact allowed.1
    · exact Change.Enabled.closed (c := .mount p) safe.mounted_closed allowed.2
  | @unmount p _ =>
    have allowed : CanUnmount g h.mounted p := allowed
    refine ⟨⟨safe.rooted_valid, ?_, ?_⟩, rfl, rfl⟩
    · intro q hq
      exact safe.mounted_rooted q (Change.mem_apply_unmount.mp hq).1
    · exact Change.Enabled.closed (c := .unmount p) safe.mounted_closed allowed
  | @dropRoot r _ =>
    have allowed : ∀ p ∈ h.mounted, InClosure g (h.roots.filter fun q => q != r) p := allowed
    refine ⟨⟨?_, allowed, safe.mounted_closed⟩, rfl, rfl⟩
    intro p hp
    exact safe.rooted_valid p (hp.mono fun q hq => (List.mem_filter.mp hq).1)

/-- Executing a guarded sequence keeps a safe host safe, whatever the rest of
the host does in between, and changes the roots and mounts as the actions say. -/
theorem Exec.safe {acts : List (Action α)} {h h' : Host α} (exec : Exec g acts h h') :
    Action.Guarded g h.roots h.mounted acts → Safe g h →
      Safe g h' ∧ h'.roots = Action.runRoots h.roots acts ∧
        h'.mounted = Action.runMounted h.mounted acts := by
  induction exec with
  | done => exact fun _ safe => ⟨safe, rfl, rfl⟩
  | @concurrent acts _ _ _ step _ ih =>
    intro guarded safe
    obtain ⟨safe', hroots, hmounted⟩ := step.safe safe
    obtain ⟨safe'', roots, mounted⟩ := ih (by rw [hroots, hmounted]; exact guarded) safe'
    exact ⟨safe'', roots.trans (congrArg (fun rs => Action.runRoots rs acts) hroots),
      mounted.trans (congrArg (fun ms => Action.runMounted ms acts) hmounted)⟩
  | @act a acts _ _ _ eff _ ih =>
    intro guarded safe
    have guarded : a.Allowed g _ _ ∧ Action.Guarded g _ _ acts := guarded
    obtain ⟨safe', hroots, hmounted⟩ := eff.safe guarded.1 safe
    obtain ⟨safe'', roots, mounted⟩ := ih (by rw [hroots, hmounted]; exact guarded.2) safe'
    exact ⟨safe'', roots.trans (congrArg (fun rs => Action.runRoots rs acts) hroots),
      mounted.trans (congrArg (fun ms => Action.runMounted ms acts) hmounted)⟩

/-! ## The update procedure -/

/-- The action that performs a mount change. -/
def Change.toAction : Change α → Action α
  | .mount p => .mount p
  | .unmount p => .unmount p

/-- The update from the current roots and mounts to `desired`, whose closure
is `target`: register the new roots, apply the plan, then drop the old roots. -/
def procedure (g : Graph α) (roots mounted desired target : List α) : Option (List (Action α)) :=
  (plan g mounted target).map fun changes =>
    (diff desired roots).map Action.addRoot ++ changes.map Change.toAction ++
      (diff roots desired).map Action.dropRoot

section Lemmas

theorem guarded_addRoots :
    ∀ (roots mounted rs : List α), Action.Guarded g roots mounted (rs.map Action.addRoot)
  | _, _, [] => trivial
  | _, mounted, _ :: rs => And.intro trivial (guarded_addRoots _ mounted rs)

theorem mem_runRoots_addRoots :
    ∀ (roots rs : List α) (q : α), q ∈ Action.runRoots roots (rs.map Action.addRoot) ↔ q ∈ roots ∨ q ∈ rs
  | roots, [], q => by simp [Action.runRoots]
  | roots, r :: rs, q => by
    show q ∈ Action.runRoots (roots ++ [r]) (rs.map Action.addRoot) ↔ _
    rw [mem_runRoots_addRoots]
    simp [or_assoc]

theorem runMounted_addRoots :
    ∀ (mounted rs : List α), Action.runMounted mounted (rs.map Action.addRoot) = mounted
  | _, [] => rfl
  | mounted, _ :: rs => runMounted_addRoots mounted rs

theorem guarded_changes {roots : List α} :
    ∀ {mounted : List α} {cs : List (Change α)}, Change.Guarded g mounted cs →
      (∀ p, Change.mount p ∈ cs → InClosure g roots p) →
      Action.Guarded g roots mounted (cs.map Change.toAction)
  | _, [], _, _ => trivial
  | mounted, c :: cs, guarded, rooted => by
    have guarded : c.Enabled g mounted ∧ Change.Guarded g (c.apply mounted) cs := guarded
    have rest : ∀ p, Change.mount p ∈ cs → InClosure g roots p :=
      fun q hq => rooted q (List.mem_cons_of_mem _ hq)
    cases c with
    | mount p =>
      exact And.intro (And.intro (rooted p (by simp)) guarded.1) (guarded_changes guarded.2 rest)
    | unmount _ => exact And.intro guarded.1 (guarded_changes guarded.2 rest)

theorem runRoots_changes (roots : List α) :
    ∀ (cs : List (Change α)), Action.runRoots roots (cs.map Change.toAction) = roots
  | [] => rfl
  | c :: cs => by cases c <;> exact runRoots_changes roots cs

theorem runMounted_changes :
    ∀ (mounted : List α) (cs : List (Change α)),
      Action.runMounted mounted (cs.map Change.toAction) = Change.run mounted cs
  | _, [] => rfl
  | mounted, c :: cs => by cases c <;> exact runMounted_changes _ cs

theorem guarded_dropRoots {desired mounted : List α}
    (rooted : ∀ p ∈ mounted, InClosure g desired p) :
    ∀ {roots drops : List α}, (∀ d ∈ desired, d ∈ roots) → (∀ r ∈ drops, r ∉ desired) →
      Action.Guarded g roots mounted (drops.map Action.dropRoot)
  | _, [], _, _ => trivial
  | roots, r :: rs, kept, notDesired => by
    have kept' : ∀ d ∈ desired, d ∈ roots.filter fun q => q != r := by
      intro d hd
      have hdr : d ≠ r := fun hdr => notDesired r (by simp) (hdr ▸ hd)
      exact List.mem_filter.mpr ⟨kept d hd, by simp [hdr]⟩
    exact And.intro (fun p hp => (rooted p hp).mono kept')
      (guarded_dropRoots rooted kept' fun r' hr' => notDesired r' (List.mem_cons_of_mem _ hr'))

theorem mem_runRoots_dropRoots :
    ∀ (roots drops : List α) (q : α),
      q ∈ Action.runRoots roots (drops.map Action.dropRoot) ↔ q ∈ roots ∧ q ∉ drops
  | roots, [], q => by simp [Action.runRoots]
  | roots, r :: rs, q => by
    show q ∈ Action.runRoots (roots.filter fun q => q != r) (rs.map Action.dropRoot) ↔ _
    rw [mem_runRoots_dropRoots, List.mem_filter]
    by_cases hqr : q = r <;> simp [hqr]

theorem runMounted_dropRoots :
    ∀ (mounted drops : List α), Action.runMounted mounted (drops.map Action.dropRoot) = mounted
  | _, [] => rfl
  | mounted, _ :: rs => runMounted_dropRoots mounted rs

end Lemmas

/-- The procedure's actions are guarded, and they end with exactly the
desired roots registered and exactly their closure mounted. -/
theorem procedure_correct {roots mounted desired target : List α} {acts : List (Action α)}
    (spec : ∀ p, p ∈ target ↔ InClosure g desired p)
    (hproc : procedure g roots mounted desired target = some acts) :
    Action.Guarded g roots mounted acts ∧
      (∀ r, r ∈ Action.runRoots roots acts ↔ r ∈ desired) ∧
      (∀ p, p ∈ Action.runMounted mounted acts ↔ InClosure g desired p) := by
  unfold procedure at hproc
  cases hplan : plan g mounted target with
  | none => simp [hplan] at hproc
  | some changes =>
    simp only [hplan, Option.map_some, Option.some.injEq] at hproc
    subst hproc
    -- After the new roots are registered, every desired path has a root.
    let roots₁ := Action.runRoots roots ((diff desired roots).map Action.addRoot)
    have mem_roots₁ : ∀ q, q ∈ roots₁ ↔ q ∈ roots ∨ q ∈ diff desired roots :=
      mem_runRoots_addRoots roots _
    have desired_rooted : ∀ d ∈ desired, d ∈ roots₁ := by
      intro d hd
      by_cases hdr : d ∈ roots
      · exact (mem_roots₁ d).mpr (.inl hdr)
      · exact (mem_roots₁ d).mpr (.inr (mem_diff.mpr ⟨hd, hdr⟩))
    have mem_mounted₂ : ∀ p, p ∈ Change.run mounted changes ↔ InClosure g desired p :=
      fun p => (plan_run hplan p).trans (spec p)
    refine ⟨?_, ?_, ?_⟩
    · refine Action.guarded_append.mpr ⟨Action.guarded_append.mpr ⟨guarded_addRoots _ _ _, ?_⟩, ?_⟩
      · rw [runMounted_addRoots]
        exact guarded_changes (plan_guarded hplan) fun p hp =>
          ((spec p).mp (plan_mounts hplan p hp)).mono desired_rooted
      · rw [Action.runRoots_append, Action.runMounted_append, runMounted_addRoots,
          runRoots_changes, runMounted_changes]
        exact guarded_dropRoots (fun p hp => (mem_mounted₂ p).mp hp) desired_rooted
          fun r hr => (mem_diff.mp hr).2
    · intro r
      rw [Action.runRoots_append, Action.runRoots_append, runRoots_changes,
        mem_runRoots_dropRoots, mem_runRoots_addRoots, mem_diff, mem_diff]
      by_cases hrd : r ∈ desired <;> by_cases hrr : r ∈ roots <;> simp [hrd, hrr]
    · intro p
      rw [Action.runMounted_append, Action.runMounted_append, runMounted_addRoots,
        runMounted_changes, runMounted_dropRoots]
      exact mem_mounted₂ p

/-- Executing the procedure, with any collection and builds interleaved, keeps
the host safe and ends with exactly the desired roots and their closure. -/
theorem procedure_exec {h h' : Host α} {desired target : List α} {acts : List (Action α)}
    (spec : ∀ p, p ∈ target ↔ InClosure g desired p) (safe : Safe g h)
    (hproc : procedure g h.roots h.mounted desired target = some acts)
    (exec : Exec g acts h h') :
    Safe g h' ∧ (∀ r, r ∈ h'.roots ↔ r ∈ desired) ∧
      (∀ p, p ∈ h'.mounted ↔ InClosure g desired p) := by
  obtain ⟨guarded, roots, mounted⟩ := procedure_correct spec hproc
  obtain ⟨safe', hroots, hmounted⟩ := exec.safe guarded safe
  exact ⟨safe', hroots ▸ roots, hmounted ▸ mounted⟩

/-- On a ranked store a procedure to any desired roots exists. -/
theorem procedure_complete {rank : α → Nat} (ranked : Ranked g rank)
    {roots mounted desired target : List α} (spec : ∀ p, p ∈ target ↔ InClosure g desired p) :
    ∃ acts, procedure g roots mounted desired target = some acts := by
  obtain ⟨changes, hplan⟩ := plan_complete ranked (closed_of_spec spec) mounted
  exact ⟨(diff desired roots).map Action.addRoot ++ changes.map Change.toAction ++
    (diff roots desired).map Action.dropRoot, by simp [procedure, hplan]⟩

/-- Crash recovery: interrupting the procedure after any number of actions,
with any concurrent host steps, leaves a safe host from which a new
procedure to the same roots exists. -/
theorem procedure_crash {rank : α → Nat} (ranked : Ranked g rank) {h h' : Host α}
    {desired target : List α} {acts : List (Action α)}
    (spec : ∀ p, p ∈ target ↔ InClosure g desired p) (safe : Safe g h)
    (hproc : procedure g h.roots h.mounted desired target = some acts) (k : Nat)
    (exec : Exec g (acts.take k) h h') :
    Safe g h' ∧ ∃ acts', procedure g h'.roots h'.mounted desired target = some acts' :=
  ⟨(exec.safe ((procedure_correct spec hproc).1.take k) safe).1, procedure_complete ranked spec⟩

end Sandbox.Store
