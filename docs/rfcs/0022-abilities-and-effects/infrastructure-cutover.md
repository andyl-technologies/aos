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

## Runtime and stage evaluation

`aos-ability-plan::module_graph` decodes the native projection, checks identity
and content hashes, validates portable option types, and checks every edge and
execution position. It retains the original document so journal replay preserves
its exact schema encoding. Documentation text is excluded from state revisions.

`aos-ability-runtime::activation` uses the existing framed, locked, checksummed
journal. It records exact invocations before dispatch, checks results before
committing, and observes interrupted mutations before retrying them. Changed
inputs or implementations receive previous state rather than automatically
tearing it down. Transaction resources are removed after their consumers finish;
instance resources are removed when their configuration disappears; persistent
resources require explicit retirement. Artifact release is journaled separately
so interrupted cleanup can be retried without repeating teardown.

`aos-package::config_eval::module_activation` supplies the process adapter using
the existing bounded subprocess transport. The host supplies artifact admission
and retention through `HandlerArtifacts`. Programs receive `apply`, `remove`, or
`observe` and a JSON invocation on stdin. This adapter is not yet connected to the
production activation entry point.

Image and on-host evaluation now compose ordinary authenticated package modules
for each deployment stage. The provider-selection resolver and frozen parallel
maps are removed. `modules/base/activation-stages.nix` owns the host/early-boot
stage definitions, outside the generic effect library. Stage tests exercise
isolation, identity scopes, package deduplication, and rejection of conflicting
package records.

Native option types project into the runtime type algebra. Opaque values,
arbitrary Nix predicates, and string-pattern descriptions without a portable
validator are rejected at this boundary rather than silently weakened.

## Remaining infrastructure

The migration is not complete. Remaining work includes:

- Replace package contract construction, which still calls the removed registry
  projection API, and generate its documentation from native module declarations.
- Wire authenticated artifact retention and the new graph controller into the
  production activation, boot, and reconfiguration entry points.
- Migrate static stage contracts and source-stage materialization to the new
  graph format, then remove the old Rust planning and dispatch path.
- Complete bounded journal maintenance, negative
  graph tests, and production transport/lifecycle integration tests.
- Migrate graph/documentation decoding in the hub API, UI, and CLI.

The module fixture and runtime tests validate the new boundary independently;
they do not establish that existing systems can boot through it. Existing domain
consumers remain intentionally incompatible until their separate migration.
