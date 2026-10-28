# Package modules and evaluation

This page covers how a package's module reaches an evaluated deployment: the
build-time envelope, module dependency resolution, the immutable evaluation
descriptor, restricted evaluation, and the generated reference. See the
[overview](README.md) for the operation model.

## Package envelope

`mkDerivation` accepts `module` and `moduleDeps`:

```nix
{ mkDerivation, echo-interface }:
mkDerivation {
  pname = "example";
  version = "1";
  # Ordinary source, dependencies, and build phases go here.
  module = ./module;
  moduleDeps = [ echo-interface ];
}
```

The directory must contain `module.nix`, and imported files stay within that
retained source tree. Module dependencies are package coordinates with exact
source store paths. They supply configuration interfaces or implementations and
are separate from build dependencies and runtime libraries. Packages without a
module remain ordinary payload packages and still belong to their generation.

A runtime dependency that carries its own module does not enable it. Only
explicit package selections and their `moduleDeps` enter the fixed point. APM
retains module selections in the evaluation descriptor separately from installed
payload artifacts, so reconfiguration preserves the distinction.

The builder exposes these derived values:

| Attribute | Meaning |
| --- | --- |
| `module` | Retained module source directory, when supplied |
| `moduleDeps` | Explicit package module dependency edges |
| `deployment` | Envelope with the target platform, payload outputs, runtime dependencies, and module locators |
| `deploymentArtifact` | Derivation containing `deployment.json` |
| `documentation` | `aos.module.documentation` projected from the package's module closure |
| `documentationArtifact` | Derivation containing `options.json` |

The JSON companions are separate derivations, so payload construction stays lazy
with respect to deployment evaluation. `mkDerivation` injects no host
configuration, service-specific lowering, or authored documentation schema. The
removed `abilities` and `configModule` recipe arguments fail when the deployment
envelope is requested.

A deployment module receives ordinary evaluator arguments: `lib`, `config`,
`options`, its own `package` artifact, and its named runtime `dependencies`.
`runtimeDeps` accepts either a package list, bound by package name, or a named
attribute set; named bindings can distinguish two artifacts of the same package
without changing their identities. Artifacts carry explicit `name`, `version`,
`path`, `outputs`, and `mainProgram` fields, so string interpolation,
`lib.getOutput`, and `lib.getExe` work without reconstructing derivations.

Selecting a payload output installs that output. Available sibling outputs and
module dependency packages are resolution context, not instructions to install
their software. Effect inputs and handlers add the artifacts they actually use,
and generated documentation or qualification metadata does not make unused
payloads or build-only probe tools runtime dependencies. Publication
authenticates each selectable output with its own companion; a named output
cannot borrow another output's measurement or signed binding.

## Module resolution

A scope selects one exact identity per package name. Plain `moduleDeps` entries
inherit the dependency recipe's `package.versionRequirement`:

- a bare strict SemVer recipe version implies a caret range;
- `^`, `~`, or `=` followed by a full version sets the policy while preserving
  the exact published version;
- other bare version schemes are exact-only.

The caret default is an authoring convention; recipes narrow it when a broader
guarantee has not been reviewed. An explicit `packageVersion` range overrides
inference, and `exact = true` pins immutable source identity rather than an
equal version. Every entry retains its exact build-time seed.

Package interfaces follow their owning package's release version, and OS/base
interfaces follow the OS release version. Ability declarations have no
independent version, and effect revisions are unrelated to release
compatibility. An optional recipe `osVersion` requirement checks the selected
host OS release, which is fixed input that the resolver never selects or
upgrades.

The bounded solver (`aos_package_manager::native_registry`) considers transitive
requirements and historical releases from configured authenticated registries.
It never substitutes an unrelated implementation. Ordinary installation prefers
compatible retained choices; explicit upgrades permit reselection. Unsatisfiable
requirements and exhausted search budgets are distinct failures. Dependencies
cannot introduce their own registry trust anchors.

Whenever a closure contains ranges, the evaluation descriptor carries a
`resolutionLock` with every original dependency edge, selected exact source, and
requesting package's deployment companion, including moduleless requesters.
Image construction locks the checked build-time seeds. Reconfiguration, boot,
and rollback replay the lock instead of solving against current registries.

## Evaluation entry points

`lib.evalPackageModules` is the shared Nix entry point. Build-time callers pass
selected packages directly:

```nix
lib.evalPackageModules {
  scope = [ "profile" "main" ];
  packages = [ example echo-handler ];
  operatorModules = [ { example.message = "hello"; } ];
}
```

Deployment callers pass resolved `packageModules`, `packageArtifacts`, and locked
source roots instead. The returned `deployment` contains the scope, target
platform, retained evaluation inputs, payload artifacts, exact module contexts,
explicit `aos.activation.retire` decisions, and the generated graph. The returned
`documentation` projects options and operation declarations with declaration
owners, handler availability, and configured effects. Documentation is lazy with
respect to graph construction and handler selection.

## Evaluation-input descriptor

`lib.build.evaluationInput` produces the immutable `aos.package.evaluation-input`
descriptor for host and container builders. It carries the source library's
exact NAR identity, the resolved package set, the scope, and the ordered baseline
and operator sources; it never contains the output graph. Package modules receive
its path as an ordinary argument, which lets an operation request a further
authorized evaluation without a self-reference.

- `moduleEnvelopes` retains the deployment companions for the complete module
  closure, including schema-only dependencies. APM verifies each decoded
  envelope against the retained module context before resolving a later
  configuration, so dependency edges survive offline without installing the
  dependencies' payloads.
- `supplementalInputs` retains immutable source receipts or other provenance
  needed across reconfiguration without making them payload packages or
  executable operations.

Image stages retain their ordered policy files through
`aos.activation.stages.<stage>.configuration`, and
`aos.activation.stages.<stage>.supplementalInputs` retains additional immutable
store roots without importing them (`lib/build/evaluate-stages.nix`). There is
no inline stage-module channel whose configuration could disappear from replay.

Early provisioning projects and validates the typed storage plan from the
accepted module fixed point before committing disk changes. Its descriptor
retains evaluation sources and supplemental evidence but not unused payload
outputs. Full host graph validation happens at host activation, before host
effects.

## Restricted evaluation

`lib.packageModuleLibrary` is the immutable source bundle for the evaluator; it
does not contain an image baseline. `aos_deployment::evaluation` resolves the
module closure through a `PackageResolver`, then invokes stock Nix with
fixed-NAR source inputs, pure restricted evaluation, and import-from-derivation
disabled. Its process transport bounds input, output, duration, and
cancellation.

`Evaluation` carries the selected `nix-store` executable explicitly; source
access and evaluation never pick another evaluator from `PATH`. The selected
store exports each distinct source root as a bounded NAR (at most 64 MiB) and
`aos_deployment::source_views` restores a private, hash-locked read view. This
works even when the store's logical paths are absent from the host's
`/nix/store`, and the temporary read locations never replace the original source
identities in the descriptor or transaction.

`aos_package_manager::native_deployment::evaluate_input` replays a descriptor
without building payloads or applying effects. It temporarily roots the
descriptor and its sources, checks the library NAR identity, runs the restricted
evaluator, and returns a checked desired deployment. It creates no generation,
effect journal, or persistent deployment root. Integrity checking alone does not
grant authority; callers authenticate the source before using the result.
`aos ability evaluate` exposes the same path.

## Provenance and admission

Module provenance comes from the resolver and the module engine. A package
module cannot establish ownership by assigning its own package name or
diagnostic metadata. Shared extensible options merge through their declared
types; unrelated packages cannot silently replace another package's private
configuration.

A generated graph describes desired behavior. It is not authority to download
or execute arbitrary artifacts: the caller authenticates the selected release or
image and admits exact sources, payloads, and handlers before a generation is
prepared. A local receipt, quoted descriptor, or path name cannot make itself a
trust anchor. Wire readers reject unknown schemas and unsupported fields.

## Generated reference

`aos.module.documentation` includes package identities, input and result types
with descriptions, source ownership, handler availability, and configured effect
names. Recipes publish it as `documentationArtifact/options.json`; evaluated
execution paths use `aos.package.transaction` and its checked activation graph.

`aos docs runtime` renders a reference or a transaction as text, JSON, or HTML.
Hub serves the same reader through `/-/runtime-abilities` and the read-only
`/-/api/runtime-documentation` endpoint, and authenticated release ingestion
checks the signed artifact locators before indexing the same data. These views
describe evaluated configuration, not observed live state, and cannot infer
conditional uses that are absent from the fixed point.

`aos ability check-compat BEFORE AFTER --owner PACKAGE` (or `--os`) compares the
generated public input and result schemas of two owner releases. Removed
operations or fields, new required inputs, and type changes are breaking;
optional input additions and new operations are allowed. Opaque constraints need
explicit review. A breaking change is permitted outside the previous release's
captured compatibility range, or with an `--exceptions FILE` entry naming the
exact diagnostic and the reason. A structural comparison does not prove runtime
behavior.
