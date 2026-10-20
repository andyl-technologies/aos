# Abilities and their use

An ability groups related operations under
`aos.abilities.<ability>.operations.<operation>`. Each operation declares input
and result modules. A selected handler interprets an enabled effect either as a
program invocation or as a composition of other operations.

A package can expose an operation, select an implementation, configure effects,
or do several of these. These roles are ordinary module definitions rather than
separate package registries. Independent modules can extend the same operation
input or domain option tree. `moduleDeps` declares exact or explicitly compatible
module dependencies needed to evaluate those definitions.

Domain packages provide convenient configuration options and derive effects
from the merged values. For example, a service implementation can reuse its
operation input module under a service-name attribute set. A service package
then configures that option instead of duplicating the contract. The complete
example is in [the author guide](../../users/aos/runtime-abilities.md).

Typed output references connect operations without executing them during Nix
evaluation. A reference records the producer identity, result name, and result
schema. The graph checker verifies the producer and type before execution;
the runtime supplies the concrete value only after successful completion.

Selecting a handler is module configuration. An unused contract may have no
handler. An enabled effect without an implementation fails evaluation before
mutation. There is no automatic fallback to a backend with fewer features.

Static documentation describes declarations and configured uses present in the
fixed point. It cannot infer every use hidden behind disabled conditions or
establish what has actually executed on a host.
