# Infrastructure cutover

The former registry authoring API is removed. This branch is deliberately not
system-buildable while its callers are migrated. There is no compatibility
wrapper for `requirementTemplates`, request/binding maps, provider-selection
passes, or the old constructor functions.

The new core is in `lib/effects/module.nix`. An ability owns operation submodules.
An operation owns its input module, named result types, selected handler module,
and configured effects. Independent definitions of input and handler modules
merge through `types.deferredModule` and the ordinary evaluator. Effect inputs
are evaluated submodules of the merged contract. Domain modules remain responsible
for exposing ordinary user-facing configuration and deriving invocations from it.

A handler supplies either a derivation-backed program or child effect modules.
Composed handlers import another operation's evaluated `module` value, access
child outputs through the `children` module argument, and export typed results.
Output references are ordinary read-only configuration attributes. The
`types.deferred` option type accepts a concrete value or a reference with the
matching result type.

`aos.activation.graph` is a generated projection, not a configuration surface.
Its compiler checks missing handlers, missing producers, output compatibility,
composition exports, duplicate identities, dependency cycles, and bounded handler
expansion. Logical identities derive from module scopes; revisions derive from
the operation's input and selected implementation artifact. Documentation is
projected from input option declarations and result types.

## Verification

`nix-instantiate --eval --strict tests/effects/modules.nix` exercises module
extension, merged configuration, handler overrides and composition, typed output
connections, disabled effects, missing handlers, cycles, and recursive expansion.
The fixtures use synthetic derivation records and perform no host modifications.

## Unfinished infrastructure

This is a module/compiler checkpoint, not a completed activation implementation.
The new graph is not yet accepted by the Rust executor. Before any system can use
it, the infrastructure must:

- Adapt the checked runtime plan boundary, including artifact authentication and
  runtime validation of inputs and results. The current graph contains native
  option-type projections; these are not yet the existing runtime schema format.
- Connect resource ownership, retention, transitions, observation, and recovery
  to the existing lifecycle and journal machinery. A graph revision alone is not
  a complete resource lifecycle model.
- Replace the remaining image/on-host evaluation entry points that still call
  the removed provider-selection API.
- Adapt package contract projection and documentation consumers to the new
  declaration and graph projections.

Existing runtime code remains in place for that adaptation. It must not be
bypassed with an unjournaled script runner, nor treated as compatible with the
new graph merely because both represent deferred operations.
