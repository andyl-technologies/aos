import Lean

/-!
# The `#audit_sandbox_axioms` command

Defined apart from its use because Lean runs a command only from an imported
module.
-/

open Lean Elab Command

/-- Lean's standard axioms, which classical proofs use. -/
def standardAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

/-- Fails unless every `Sandbox` declaration depends only on `standardAxioms`. -/
elab "#audit_sandbox_axioms" : command => do
  let env ← getEnv
  let mut audited : Nat := 0
  for (name, _) in env.constants.toList do
    if (`Sandbox).isPrefixOf name then
      audited := audited + 1
      for ax in (← collectAxioms name) do
        unless standardAxioms.contains ax do
          throwError "{name} depends on the nonstandard axiom {ax}"
  if audited == 0 then
    throwError "the axiom audit found no Sandbox declarations"
  logInfo m!"audited {audited} Sandbox declarations"
