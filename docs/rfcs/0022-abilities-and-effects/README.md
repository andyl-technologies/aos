# RFC-0022: Runtime abilities and deferred package execution

- **Status:** Native infrastructure and consumer cutover implemented; image qualification remains separate.
- **Audience:** package authors, operators, and maintainers of Nix modules, APM,
  APR, system activation, AOS Hub, and documentation tooling.
- **Normative design:** [Target state](13-target-state.md).
- **Implemented APIs and limits:** [Infrastructure cutover](infrastructure-cutover.md).
- **End-to-end guide:** [Runtime abilities](../../users/aos/runtime-abilities.md).
- **Integration and qualification:** [Migration status](consumer-migration.md).

A package distributes built software and an optional immutable Nix module.
Interface, implementation, package, and operator modules compose through one
recursive fixed point per installation scope. An ability operation declares
typed input and result modules. Its selected handler is either a retained
program or a composition of other operations. Evaluation produces a deferred
effect graph; Rust checks and executes it, retaining results and generations.

```mermaid
flowchart LR
  modules["Package and system modules"] --> evaluation["Nix fixed point"]
  evaluation --> graphData["Typed effect graph"]
  graphData --> runtime["Package transaction runtime"]
  runtime --> handlers["Selected handlers"]
  handlers --> primitives["OS primitives"]
```

The generic library defines module/effect machinery, not service, network, or
filesystem interfaces. Those domains belong to their packages or system modules.
Other modules can extend the same operation and domain option trees through
ordinary imports and option merging. Generated documentation uses the same
fixed point and provenance, without an independently authored ability catalog.

The native cutover intentionally replaces the earlier registry-shaped authoring
API. There is no compatibility target for static `interfaces`, `implementations`,
`requirementTemplates`, or provider/binding maps. Consumers use the native module
tree directly; the superseded authoring and execution paths have been removed.

## Reading order

1. [Target state](13-target-state.md): ownership, interfaces, phases, and limits.
2. [User and author guide](../../users/aos/runtime-abilities.md): concrete Nix
   examples, handler composition, execution paths, CLI, and Hub inspection.
3. [Infrastructure cutover](infrastructure-cutover.md): concrete build and Rust APIs.
4. [Implementation contract](implementation-contract.md) and
   [execution contract](execution-contract.md): source boundaries and runtime protocol.
5. [Consumer migration](consumer-migration.md): implementation checks and image qualification limits.

The numbered chapters describe the same native design at each boundary. The
[completion criteria](implementation-completeness.md) distinguish implementation
checks from qualification of an actual image and its handlers.
