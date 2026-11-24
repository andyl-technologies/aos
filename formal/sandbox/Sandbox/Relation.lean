/-!
# Transition systems

A model in this library is a step relation over states. `Star` is the
reflexive transitive closure of a step relation, and `Star.invariant` is the
induction principle behind every safety theorem: a predicate that holds in the
first state and is preserved by every step holds in every reachable state.
-/

namespace Sandbox

/-- The reflexive transitive closure of a step relation. -/
inductive Star {σ : Type} (step : σ → σ → Prop) : σ → σ → Prop where
  | refl (s : σ) : Star step s s
  | tail {s t u : σ} : Star step s t → step t u → Star step s u

namespace Star

variable {σ : Type} {step : σ → σ → Prop}

/-- A predicate preserved by every step holds in every state reachable from a
state that satisfies it. -/
theorem invariant {inv : σ → Prop} (preserve : ∀ s t, inv s → step s t → inv t)
    {s t : σ} (reach : Star step s t) (init : inv s) : inv t := by
  induction reach with
  | refl => exact init
  | tail _ hstep ih => exact preserve _ _ ih hstep

end Star

end Sandbox
