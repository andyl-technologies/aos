# Target state: native modules and deferred package execution

This is the normative target for RFC-0022. It supersedes the earlier static
registry/provider model. The [infrastructure cutover](infrastructure-cutover.md)
describes implemented mechanisms; [consumer migration](consumer-migration.md)
records implementation checks and qualification limits. The [end-to-end guide](../../users/aos/runtime-abilities.md)
is the central source of author-facing examples.

## Ownership and composition

Every package may expose a native `module` directory and explicit `moduleDeps`.
Its recipe continues to build ordinary payload outputs. Packages with no module
remain valid payload-only members of an installation scope.

Plain module dependencies inherit the package recipe's generated version
requirement. Bare strict SemVer implies caret; `^`, `~`, and `=` recipe shorthand
set a policy alongside the normalized exact release version. Bare non-SemVer
versions remain exact-only. Explicit package ranges override inference, while
`exact = true` pins source identity. Each dependency retains an exact build-time
seed. Package interfaces use their
owning package's release version, and OS/base interfaces use the OS release
version. Ability declarations have no independent release version. An optional
recipe `osVersion` requirement checks the selected host OS, a fixed input that the
dependency resolver never selects or upgrades. Effect revisions remain separate.
A scope selects one exact identity per package name. The resolver records
exact choices and original requirements for offline replay. See
[resolution and binding](04-resolution-and-binding.md) for scoped upgrades,
registry discovery, and lock semantics.

The module engine owns generic recursive evaluation, typed submodules,
conditional definitions, priorities, provenance, deferred module values, and
typed references. Domain interfaces belong to packages or system modules.
There must be no service, networking, database, or init-specific lowering in
`lib/`, and no package-name dispatch in a generic runtime or renderer.

All configuration is authored through ordinary `options` and `config`.
Independent modules may define or extend the same domain and operation trees.
A domain manager reuses its operation's input module for convenient user options
and derives effects from the final merged configuration. It does not require
parallel declaration/configuration maps or empty instance declarations.

## Native operation shape

The authoring tree is:

```text
aos.abilities.<ability>.operations.<operation>
  input                         deferred module declaring input options
  result                        deferred module declaring result options
  handler                       selected deferred handler module, or null
  effects.<instance>
    enable                      whether to include this effect
    input                       configuration checked by the input module
    lifetime                    instance | transaction | persistent
    after                       explicit typed output dependencies
    timeoutMs                   bounded process duration
    outputs.<result>            read-only typed output references
    execution                   evaluated handler configuration
  module                        read-only reusable effect submodule
  documentation                 derived operation reference
```

A handler selects `program` or composes `children` and `exports`. Child modules
import the selected lower operation's `module`; their inputs merge and typecheck
through that operation's schema. `types.deferred T` admits a concrete `T` or a
compatible output reference. References induce graph dependencies; compositions
export checked child results. Selection is ordinary module configuration, not a
second provider-discovery language.

The generated `aos.activation.graph` is a serialization boundary, never an
operator-maintained catalog. An enabled effect without a handler, incompatible
reference, conflicting definition, or invalid composition must fail before
mutation. Unused interface declarations remain valid without a handler.

## Build, publication, evaluation, execution

1. **Build:** realize payloads, retain module source, and generate the deployment
   envelope and documentation artifact. Payload construction remains lazy with
   respect to deployment evaluation. No activation runs in a build.
2. **Publication:** retain and authenticate exact artifacts and their dependency
   identities through the package manager's release machinery. Publishing a
   document does not authorize or perform its effects.
3. **Evaluation:** resolve one exact package/module closure for a scope. Combine
   package, operator, and runtime modules using the immutable generic library.
   Evaluate with fixed inputs, pure/restricted Nix, and IFD disabled. Return the
   desired transaction and documentation without building or mutating the host.
4. **Execution:** admit and retain required artifacts, validate the generated
   graph, prepare a durable generation, execute selected handlers in dependency
   order, check results, and commit only after effect completion is durable.
5. **Reconfiguration:** evaluate new desired configuration and reconcile against
   retained state. Removal, interrupted work, rollback, and pruning use the same
   transaction and effect state machines.

`lib.evalPackageModules` is the shared Nix entry point. Build callers may supply
packages directly; deployment callers supply resolved module/artifact records.
The Rust owners are `aos-ability-plan::module_graph`,
`aos-ability-runtime::activation`, and `aos-package::deployment`.

Package, profile, container, and host scopes use the same machinery. OS boot is
a consumer, not a separate whole-host interpreter. Alternative service managers
and other platform implementations supply compatible contracts and handlers;
any platform-specific process transport also needs a matching backend.

## Identity and lifetime

Logical identity comes from scope, declaring package, ability, operation, and
instance, with parent identity for composed children. Package versions and store
paths must not create a new logical instance by themselves. Shared domain
managers own effects derived from shared configuration.

Revisions derive from semantic content and selected artifacts. Documentation
edits do not change revision identity. Authors do not maintain manual revision
counters for routine package changes.

Instance effects live across generations until removed from desired state.
Transaction effects are cleaned up after their dependents complete. Persistent
effects survive package removal until explicitly retired. Old handlers remain
retained while update, teardown, or recovery still needs them.

Handlers implement observation for uncertain outcomes. The runtime never assumes
arbitrary external mutations are reversible. Rollback submits retained desired
configuration as a new transaction. Generation pruning releases roots; journal
compaction is a separate storage operation.

## Documentation and interfaces

Option descriptions and types live beside their executable declarations.
Operation input/result schemas and definition provenance are projected from the
same evaluation. Package documentation is `aos.module.documentation`; evaluated
execution paths use `aos.package.transaction` and its checked activation graph.

CLI and Hub share one native reader and renderers. Reference views show package
and environment owners, operation declarations, selected handlers, and configured
effects. Transaction views show execution order, dependencies, lifetimes, and
implementation artifacts. Neither is evidence of observed live state. Conditional
uses absent from the fixed point cannot be invented by the documentation layer.

The CLI, Hub import viewer, authenticated release index, package reference pages,
and deployment reports use these native outputs through the shared reader. A separate authored documentation model or silent adapter
for the obsolete registry schemas is not the target.

## Completion boundary

The native infrastructure, package domains, publication, APM, and generated
documentation paths are implemented. The isolated boot-to-APM handoff check
covers adoption, reconfiguration, repeated boot, and recovery. Image consumers
use canonical provider metadata and separate delivery records. Qualification
cohorts retain independently checked adopted and selected evaluations.
No qualification or platform support claim follows merely from having the
interface. Current journals are bounded without automatic compaction; current process transport uses Linux facilities.
