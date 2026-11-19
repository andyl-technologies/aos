/-!
# Store closures

A Nix store is a graph: every valid store path records the store paths it
references, and Nix keeps a path valid only while its references are valid. A
sandbox sees a sub-store chosen by a list of *roots*. Its visible store is the
closure of those roots, so every visible path's references are visible too.

`InClosure` is the specification of that closure and `Closed` is the property
every mount set must keep. `closure?` computes a closure by expanding the roots
until the result contains each member's references. It returns `none` instead
of an unchecked answer when its iteration budget runs out, and
`closure?_spec` proves any answer it returns exact.
-/

namespace Sandbox.Store

/-- A store reference graph. `refs p` lists the paths `p` references, which
Nix fixes when `p` becomes valid; a path the store does not know has none. -/
structure Graph (α : Type) where
  /-- The paths a store path references. -/
  refs : α → List α

variable {α : Type} {g : Graph α}

/-- `p` is reachable from `roots` by following references. -/
inductive InClosure (g : Graph α) (roots : List α) : α → Prop where
  | root {p : α} : p ∈ roots → InClosure g roots p
  | ref {p q : α} : InClosure g roots p → q ∈ g.refs p → InClosure g roots q

/-- A list of paths is closed when it contains every reference of each of its
members. A closed mount set never exposes a path without its dependencies. -/
def Closed (g : Graph α) (s : List α) : Prop :=
  ∀ p ∈ s, ∀ q ∈ g.refs p, q ∈ s

namespace InClosure

/-- More roots reach at least the same paths. -/
theorem mono {roots roots' : List α} (sub : ∀ r ∈ roots, r ∈ roots') {p : α}
    (h : InClosure g roots p) : InClosure g roots' p := by
  induction h with
  | root hr => exact .root (sub _ hr)
  | ref _ hq ih => exact .ref ih hq

/-- A closed list that contains the roots contains their whole closure. -/
theorem mem_of_closed {roots s : List α} (closed : Closed g s)
    (sub : ∀ r ∈ roots, r ∈ s) {p : α} (h : InClosure g roots p) : p ∈ s := by
  induction h with
  | root hr => exact sub _ hr
  | ref _ hq ih => exact closed _ ih _ hq

/-- A path reachable from two root lists is reachable from one of them. -/
theorem append_cases {roots extra : List α} {p : α}
    (h : InClosure g (roots ++ extra) p) : InClosure g roots p ∨ InClosure g extra p := by
  induction h with
  | root hr =>
    rcases List.mem_append.mp hr with hr | hr
    · exact .inl (.root hr)
    · exact .inr (.root hr)
  | ref _ hq ih =>
    rcases ih with ih | ih
    · exact .inl (.ref ih hq)
    · exact .inr (.ref ih hq)

end InClosure

/-- A list whose members are exactly a closure is closed. -/
theorem closed_of_spec {roots s : List α} (spec : ∀ p, p ∈ s ↔ InClosure g roots p) :
    Closed g s :=
  fun p hp q hq => (spec q).mpr (.ref ((spec p).mp hp) hq)

/-- Closedness depends only on membership. -/
theorem Closed.congr {s t : List α} (same : ∀ p, p ∈ s ↔ p ∈ t) (closed : Closed g s) :
    Closed g t :=
  fun p hp q hq => (same q).mp (closed p ((same p).mpr hp) q hq)

section Compute

variable [DecidableEq α]

/-- The members of `a` that are not in `b`, in the order of `a`. -/
def diff (a b : List α) : List α :=
  a.filter fun p => decide (p ∉ b)

@[simp] theorem mem_diff {p : α} {a b : List α} : p ∈ diff a b ↔ p ∈ a ∧ p ∉ b := by
  simp [diff]

/-- The list without repeated members, keeping each member's last occurrence. -/
def dedup : List α → List α
  | [] => []
  | p :: ps => if p ∈ ps then dedup ps else p :: dedup ps

@[simp] theorem mem_dedup {p : α} {s : List α} : p ∈ dedup s ↔ p ∈ s := by
  induction s with
  | nil => simp [dedup]
  | cons q qs ih =>
    by_cases h : q ∈ qs
    · rw [dedup, ite_eq_left h, ih, List.mem_cons]
      constructor
      · exact .inr
      · rintro (rfl | hp)
        · exact h
        · exact hp
    · rw [dedup, ite_eq_right h, List.mem_cons, List.mem_cons, ih]

/-- The list followed by each reference of a member that the list lacks. -/
def expand (g : Graph α) (s : List α) : List α :=
  s ++ diff (s.flatMap g.refs) s

theorem mem_expand {q : α} {s : List α} :
    q ∈ expand g s ↔ q ∈ s ∨ ∃ p ∈ s, q ∈ g.refs p := by
  simp only [expand, List.mem_append, mem_diff, List.mem_flatMap]
  constructor
  · rintro (hq | ⟨hq, _⟩)
    · exact .inl hq
    · exact .inr hq
  · rintro (hq | hq)
    · exact .inl hq
    · by_cases hs : q ∈ s
      · exact .inl hs
      · exact .inr ⟨hq, hs⟩

/-- Decides `Closed`. -/
def isClosed (g : Graph α) (s : List α) : Bool :=
  s.all fun p => (g.refs p).all fun q => decide (q ∈ s)

theorem isClosed_iff {s : List α} : isClosed g s = true ↔ Closed g s := by
  simp [isClosed, Closed]

/-- Expands `s` until it is closed, spending one unit of `fuel` per round. -/
def closureFrom (g : Graph α) : Nat → List α → Option (List α)
  | 0, _ => none
  | fuel + 1, s => if isClosed g s then some (dedup s) else closureFrom g fuel (expand g s)

/-- The closure of `roots`, or `none` when `fuel` rounds do not reach it.
A round adds at least one path, so a budget above the number of distinct
reachable paths always suffices. -/
def closure? (g : Graph α) (roots : List α) (fuel : Nat) : Option (List α) :=
  closureFrom g fuel roots

theorem closureFrom_spec {roots : List α} :
    ∀ {fuel : Nat} {s out : List α}, (∀ r ∈ roots, r ∈ s) →
      (∀ p ∈ s, InClosure g roots p) → closureFrom g fuel s = some out →
      ∀ p, p ∈ out ↔ InClosure g roots p
  | 0, _, _, _, _, h => by simp [closureFrom] at h
  | fuel + 1, s, out, hroots, hsound, h => by
    unfold closureFrom at h
    split at h
    · next hclosed =>
      have hout := Option.some.inj h
      subst hout
      intro p
      rw [mem_dedup]
      exact ⟨hsound p, InClosure.mem_of_closed (isClosed_iff.mp hclosed) hroots⟩
    · refine closureFrom_spec (fuel := fuel) (s := expand g s) ?_ ?_ h
      · exact fun r hr => mem_expand.mpr (.inl (hroots r hr))
      · intro p hp
        rcases mem_expand.mp hp with hp | ⟨q, hq, hpq⟩
        · exact hsound p hp
        · exact .ref (hsound q hq) hpq

/-- Every answer `closure?` returns is exactly the closure of the roots. -/
theorem closure?_spec {roots out : List α} {fuel : Nat} (h : closure? g roots fuel = some out) :
    ∀ p, p ∈ out ↔ InClosure g roots p :=
  closureFrom_spec (fun _ hr => hr) (fun _ hp => .root hp) h

/-- Every answer `closure?` returns is closed. -/
theorem closure?_closed {roots out : List α} {fuel : Nat} (h : closure? g roots fuel = some out) :
    Closed g out :=
  closed_of_spec (closure?_spec h)

end Compute

end Sandbox.Store
