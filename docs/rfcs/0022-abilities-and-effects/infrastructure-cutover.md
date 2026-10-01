# Package deployment infrastructure

Packages publish a payload and, optionally, a Nix module directory. APM resolves
explicit module dependencies before evaluating one recursive module fixed point
for an installation scope. That evaluation produces a deferred effect graph.
Rust retains the inputs, executes the selected handlers, and commits a package
generation. A profile and a system deployment use the same infrastructure.

This is an immediate API cutover. The [consumer checklist](consumer-migration.md)
tracks integration and qualification separately from the infrastructure
contract. The infrastructure fixtures exercise the native path independently;
they do not establish whole-system boot qualification.

## Package build and publication

`mkDerivation` accepts native `module` and `moduleDeps` arguments:

```nix
{ mkDerivation, echo-interface }:
mkDerivation {
  pname = "example";
  version = "1";
  # The ordinary source, dependencies, and build phases belong here.
  module = ./module;
  moduleDeps = [ echo-interface ];
}
```

The directory must contain `module.nix`. Imported files stay within that retained
source tree. Module dependencies are package coordinates with exact source store
paths. They supply configuration interfaces or implementations; they are separate
from build dependencies and runtime libraries. Packages without a module remain
ordinary payload packages and still belong to their generation.

A runtime dependency carrying its own optional module does not enable that module.
Only explicit package selections and their `moduleDeps` enter the fixed point.
APM retains the module selections in the evaluation descriptor separately from
installed payload artifacts, so later reconfiguration preserves this distinction.
The generic build projections are `lib.packageModules`, `lib.packageArtifacts`,
`lib.build.evaluationInput`, and `lib.build.closureInfo`. Host and container
builders share the same descriptor builder; image builders use these public
helpers rather than importing private library files.

The builder exposes these derived values:

| Attribute | Meaning |
| --- | --- |
| `module` | Retained module source directory, when supplied |
| `moduleDeps` | Explicit package module dependency edges |
| `deployment` | Envelope containing the target platform, payload outputs, runtime dependencies, and module locators |
| `deploymentArtifact` | Derivation containing `deployment.json` |
| `documentation` | `aos.module.documentation`: options and ability documentation projected from the package's module closure |
| `documentationArtifact` | Derivation containing `options.json` |

Payload construction does not force deployment evaluation. The JSON companions
are separate derivations. Available output locators remain authenticated catalog
metadata; selected payloads, module sources, and graph-used artifacts determine
runtime retention. No host
configuration, service-specific lowering, or authored documentation schema is
injected by `mkDerivation`. Legacy `abilities` and `configModule` inputs fail when
the native deployment envelope is requested.

A deployment module receives ordinary evaluator arguments: `lib`, `config`,
`options`, its own `package` artifact, and its named runtime `dependencies`.
`runtimeDeps` accepts either a package list, bound by package name, or a named
attribute set. Named bindings can distinguish two artifacts of the same package
without changing their identities. The builder normalizes dependency values for
compilation; the deployment envelope preserves the binding names.

Artifacts have explicit `name`, `version`, `path`, `outputs`, and `mainProgram`
fields. String interpolation, `lib.getOutput`, and `lib.getExe` operate on these
values without reconstructing derivations or making builders available.

## Abilities through ordinary module merging

An interface package declares operations with input and result modules:

```nix
{ lib, ... }: {
  aos.abilities.echo.operations.run = {
    input.options.message = lib.mkOption {
      type = lib.types.str;
      description = "Message to return.";
    };
    result.options.message = lib.mkOption {
      type = lib.types.str;
      description = "Message returned by the handler.";
    };
  };
}
```

Other modules can extend those same option trees. Inputs, results, handlers, and
configured effects merge through the standard module evaluator. There is no
separately authored interface registry, provider map, or documentation table.

An implementation package selects its own built handler:

```nix
{ package, ... }: {
  aos.abilities.echo.operations.run.handler.program = package;
}
```

A consumer exposes ordinary domain configuration and derives effects from it:

```nix
{ config, lib, ... }: {
  options.example.message = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
  };

  config = lib.mkIf (config.example.message != null) {
    aos.abilities.echo.operations.run.effects.main.input.message =
      config.example.message;
  };
}
```

A handler can instead compose child effect modules, importing another operation's
`module` and exporting its typed outputs. Output references are read-only config
values; `types.deferred` accepts either a concrete value or a compatible output
reference. Rust executes the generated dependency graph after evaluation. An
unhandled configured operation fails graph construction; an unused interface or
a documentation-only evaluation needs no selected handler.

Domain options and implementations belong to their declaring packages or system
modules. The generic library has no knowledge of services, databases, networking,
or a particular init implementation.

## Evaluation and documentation

Build-time callers can evaluate already selected packages directly:

```nix
lib.evalPackageModules {
  scope = [ "profile" "main" ];
  packages = [ example echo-handler ];
  operatorModules = [ { example.message = "hello"; } ];
}
```

Deployment callers pass resolved `packageModules`, `packageArtifacts`, and locked
source roots instead. Both entry points use the same evaluator. The returned
`deployment` contains the scope, target platform, retained evaluation inputs,
payload artifacts, exact module contexts, explicit `aos.activation.retire`
decisions, and generated graph. The returned
`documentation` projects options and operation declarations, including declaration
owners, handler availability, and configured effects. Its evaluation is lazy with
respect to graph execution and handler selection.

A caller may also supply `evaluationInput`, the immutable
`aos.package.evaluation-input` descriptor produced before evaluation. It carries
the source library's exact NAR identity, resolved package set, scope, and ordered
baseline/operator sources, never the output graph. Package modules receive its
path as an ordinary argument and may use it in typed effect inputs. This avoids
self-references when an operation performs a further authorized evaluation.

`lib.build.evaluationInput` constructs this descriptor for both host and
container builders. Its `moduleEnvelopes` map retains the actual deployment
companions for the complete module closure, including schema-only dependencies.
APM verifies each decoded envelope against the retained module context before
resolving a later configuration. This preserves dependency edges offline without
installing the dependencies' payloads or reconstructing envelopes from a flattened
evaluation result.

The descriptor also retains `supplementalInputs`: immutable source receipts or
other provenance needed by the caller across reconfiguration. They retain exact
source identities without becoming installed payload packages or executable
operations. Reconfiguration preserves these inputs together with their original
source roles.

Image stages retain their ordered policy files through
`aos.activation.stages.<stage>.configuration`. Package modules and these sources
participate in both image evaluation and later replay. There is no separate
inline stage-module channel whose configuration disappears from the descriptor.
`aos.activation.stages.<stage>.supplementalInputs` retains additional immutable
store roots without importing them. For example, qualification can admit a future
scenario source while adopting an inactive baseline. The descriptor, deployment
inputs, and admission catalog retain the same roots; custody does not execute
that source.

`aos-package::native_deployment::evaluate_input` replays a descriptor without
building payloads or applying effects. It temporarily roots the descriptor and
its sources, checks the library NAR identity, invokes the restricted evaluator,
and returns a checked desired deployment. The caller supplies a staging directory,
a Nix store executable, a timeout, and cancellation. The API creates no generation,
effect journal, or persistent deployment root. Callers authenticate the source
before using its result; integrity checking alone does not grant source authority.

`deployment::evaluation::Evaluation` carries the selected `nix_store` executable
explicitly. Source access and pure evaluation use that immutable tool suite;
they do not select another evaluator from `PATH`. Private NAR-backed read views
make selected-store sources readable without replacing their original retained
identities. The [runtime guide](../../users/aos/runtime-abilities.md) describes
the source limits and the early-provisioning projection boundary.

The same path is available for inspection:

```console
aos ability evaluate /nix/store/…-evaluation-input.json \
  --nix-store /nix/store/…-nix/bin/nix-store --timeout-ms 60000
```

Successful output is the canonical deployment JSON. Diagnostics go to stderr.
The selected store resolves immutable documents and sources, including stores
whose canonical identities differ from the host's readable filesystem view.

`lib.packageModuleLibrary` is an immutable source bundle for this evaluator. It
does not contain an image baseline. The Rust `deployment::evaluation` module
resolves the module closure through `PackageResolver`, then invokes stock Nix with
fixed-NAR source inputs, pure/restricted evaluation, and IFD disabled. Its process
transport bounds input, output, duration, and cancellation. The generated document
must retain the selected platform, package contexts, and artifact identities.

A package appears once in a scope's resolved module closure. Plain dependencies
inherit `package.versionRequirement` from the recipe's normalized release and
compatibility policy. Explicit `packageVersion` overrides that range;
`exact = true` pins immutable source identity. Compatible dependencies retain
an exact build-time seed; build evaluation checks the seed and APM resolves
compatible authenticated package releases. Package interfaces follow their owning package
release; OS/base interfaces follow the selected OS release. The selected host OS
is fixed input, and optional `osVersion` requirements check it without asking the
dependency resolver to select or upgrade the OS. Conflicts fail before evaluation.

`resolutionLock` in the evaluation descriptor retains original dependency edges,
exact selections, and requester companions whenever ranges occur. Saved
activation inputs replay that lock, including declarations from moduleless
packages. Signed dependency and interface metadata must match generated
companions and their package or OS release owners. Generated reference
documentation projects the same release ownership and requirements.
See [resolution and binding](04-resolution-and-binding.md) for solver policy and
[user examples](../../users/aos/runtime-abilities.md#version-and-compose-interfaces-across-packages)
for authoring syntax.

An empty package set is valid and allows removal of all configured instance effects. Runtime output paths retain
their canonical identities even when module sources are read from another
immutable store view.

## Identity, execution, and lifetime

Top-level effect identity is derived from the installation scope, declaring
package, ability, operation, and configured instance name. Package version and
handler artifact are excluded from that logical identity. Composed child identity
also incorporates its parent. Revisions derive from semantic operation content
and the selected implementation; documentation changes do not trigger updates.
When multiple packages extend shared domain configuration, its manager derives
the resulting effects and owns their lifecycle.

`aos-ability-plan::module_graph` checks hashes, native option type projections,
references, composition exports, ordering, and bound handlers. Arbitrary Nix
predicates without a portable validator cannot cross this boundary. The original
JSON representation is retained for stable hashing and replay. Declared sets
are normalized again after deferred results are substituted: two references may
return the same value, and their returned values may sort differently from their
symbolic identities. Ordered lists, including command sequences, preserve their
order. Graph admission and recorded invocation validation remain strict.

Terminal handlers receive `apply`, `remove`, or `observe` and a JSON invocation
on stdin. Apply returns the declared result object. Remove returns an empty
object. Observe reports `current` with results, `absent`, `retry-safe`, or
`indeterminate`. Changed implementations or inputs receive previous state.
Interrupted mutations are observed before retry; the runtime does not assume
that arbitrary external operations can be undone automatically.

The effect journal distinguishes three lifetimes:

- `transaction`: removed after dependent operations finish.
- `instance`: retained across generations and removed when configuration disappears.
- `persistent`: retained until explicitly retired, including after package removal.

`aos.activation.retire` holds the exact retained identities to release. The
canonical deployment carries this decision; frontends do not supply a second
retirement list to `Transactions::apply`. Configured or unknown identities are
rejected before preparation. Already completed retirements remain valid across
later generations; durable removal outcomes supply that history.

Artifact release is separately journaled. Old implementations remain available
until their update or teardown has durably completed.

## Package generations

`aos-package::deployment::transaction::Transactions` coordinates a generation
journal with the effect journal. It prepares the exact document before dispatch
and commits only after all checked results are available. The effect runtime
retains the most recent caller transaction receipt, closing the crash window
between effect completion and generation commit without repeating one-shot work.
Recovery resumes pending work before accepting a new generation.
`transaction::inspect` uses the same generation decoder and replay state machine
under a shared lock. Its snapshot cannot create or repair journals and retains
the lock while callers inspect associated profile publications.

Committed generations retain their documents and results for inspection and
rollback. Rollback applies a retained desired document as a new transaction;
handlers reconcile it with current state. `prune` journals removal of an older
generation and retries interrupted root cleanup. The current generation cannot be
pruned. Persistent effects retain independent handler roots.

`deployment::retention::NixStore` implements generation and handler rooting using
an explicitly supplied Nix store executable. `ArtifactAdmission` binds those
roots to the owning package manager's authenticated resolution or retained
receipts. It requires already-realized artifacts. Registry authentication and
profile-link publication remain responsibilities of the calling consumers; the
generation journal is the authoritative committed pointer.

Boot may adopt an original provisioning receipt into the first host generation.
The image's retained policy selects whether that receipt is required, and the
bridge checks the exact committed initrd result before admitting its source.
Subsequent package generations preserve that original provenance. Independent
attestation uses externally established proof and root identities; a signer name
inside a receipt, or expectations copied from the quote being checked, cannot
establish original source authority.

Journals use the existing framing, exclusive locking, checksums, and configured
size limits. They stop at their capacity limits; pruning releases store roots but
does not compact journal bytes. Automatic journal compaction is not implemented.

## Focused verification

`checks.effects` evaluates recursive contracts, merging, composition, deferred
outputs, ownership, stage isolation, and artifact freezing, then builds real
publication artifacts for a small package closure. The Cargo example
`package_deployment_check` consumes that fixture and exercises publication,
deployment-time evaluation, process handling, generation recovery, reconfiguration,
and pruning. Rust tests separately exercise interruption at the generation/effect
commit boundary and during root cleanup.

Consumer migration should use these infrastructure entry points directly. The
old registry projections, host provider-discovery loop, image-specific dispatch,
and duplicated graph/documentation parsers are not compatibility targets.

## Author and operator documentation

The [runtime abilities guide](../../users/aos/runtime-abilities.md) contains the
shared Nix examples and phase diagrams. `aos docs runtime options.json` inspects
the native reference without Nix or a checkout. Passing a transaction instead
shows its ordered execution path. Both support text, JSON, and HTML output.
Hub exposes the same reader through `/-/runtime-abilities` and the read-only
`/-/api/runtime-documentation` JSON endpoint. These are artifact inspection
surfaces. Authenticated release ingestion additionally checks signed native
artifact locators before indexing the same generated data. See the
[migration status](consumer-migration.md) for implementation checks and qualification limits.
