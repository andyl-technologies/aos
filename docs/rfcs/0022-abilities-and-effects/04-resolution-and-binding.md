# Module resolution and handler selection

Package resolution selects an exact module closure and payload artifacts before
evaluation. Plain `moduleDeps` entries inherit `package.versionRequirement`
from the dependency recipe. Bare strict SemVer recipe versions imply caret;
`^`, `~`, or `=` followed by a full version set the policy while preserving
the exact published version. Other bare version schemes remain exact-only.
The caret default is an authoring convention, not an upstream policy detector.
Recipes narrow it to a documented patch series or an exact release when a
broader guarantee has not been reviewed. Upstream ABI, configuration, and upgrade
policies do not establish compatibility of the AOS-authored module automatically.
Explicit `packageVersion` ranges override inference; `exact = true` pins immutable
source identity, unlike an equal-version requirement. Every entry retains its
exact build-time seed. Interfaces
released by a package use that package's release version; OS/base interfaces use
the selected OS release version. Ability declarations have no independent
version. Effect revisions remain independent of release compatibility.

A scope selects one exact identity per package name. An optional recipe
`osVersion` requirement checks the selected host OS release, which is a fixed
input and is never solved for or upgraded by the dependency resolver.
The bounded dependency solver considers transitive requirements and historical
releases from configured authenticated registries. Compatible releases must retain the requested package identity;
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
