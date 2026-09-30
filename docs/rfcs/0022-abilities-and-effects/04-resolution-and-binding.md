# Module resolution and handler selection

Package resolution selects an exact module closure and payload artifacts before
evaluation. `moduleDeps` accepts exact package references or explicit compatibility
requirements with an exact build-time seed. Ability versions are declared through
`aos.abilities.<name>.version`; signed exports are generated from that module
configuration and its declaring provenance owner. Package versions and effect
revisions remain independent.

A scope selects one contract version and declaring owner per ability, and one
exact identity per package name. The bounded dependency solver considers
transitive requirements and historical releases from configured authenticated
registries. Compatible releases must retain the requested package identity;
resolution does not substitute unrelated implementations. Ordinary installation
prefers compatible retained choices; explicit upgrades permit reselection.
Unsatisfiable requirements and exhausted search budgets are distinct failures.

Any ranged closure retains a resolution lock containing every original dependency
edge, selected exact source, and requesting package's deployment companion.
Moduleless requesters are included. Nix image construction locks its checked
build-time seeds. Runtime reconfiguration, boot, and rollback validate and replay
those choices without solving against current registries. Exact-only closures do
not need an additional lock.

Sources may originate in different Git repositories or registries. Pinned flakes
are an optional build-input mechanism, not a runtime import protocol. Publication
retains source companions and signs the generated dependency/export metadata.
Registry discovery stays within configured trust and source policy; dependencies
cannot introduce their own registry trust anchors. Local registry aliases do not
create package namespaces.

Handler selection is ordinary Nix module configuration under the operation's
`handler`. It is not a separately authored provider map or runtime discovery
loop. The generated graph retains the exact selected implementation and typed
dependencies. An enabled effect without a handler fails before host mutation.
Unused interfaces and reference-only evaluation need no selected handler.

APR authenticates exact deployment and documentation companions in release
metadata. APM resolves the selected module closure and admits its retained
artifacts before execution. Module-only dependencies remain available for
offline reconfiguration without installing their payloads. The generic evaluator
does not infer authorization from an import, store path, or declaration.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
