import Sandbox
import SandboxAudit.Command

/-!
# Axiom audit

Lean accepts a theorem whose proof depends on an axiom, and `sorry` is such an
axiom. Building this module fails when any declaration in the `Sandbox`
namespace depends on an axiom other than Lean's standard three: propositional
extensionality, the axiom of choice, and quotient soundness. Platform
behavior the model relies on is stated as definitions and hypotheses, never
as axioms, so this audit keeps every assumption visible in a theorem's
statement.
-/

#audit_sandbox_axioms
