# Target state

This chapter is the normative component and data-ownership map for RFC-0022.
The other chapters define semantics and motivation. Where an illustrative
helper, migration sequence, or historical implementation note conflicts with
this chapter, this chapter governs the completed implementation.

## One authoritative value at each boundary

The implementation has one source of truth for each kind of information:

| Information | Authoritative value |
| --- | --- |
| Interface semantics | A provider-neutral feature module in the relevant domain |
| Package declarations | The package's first-class ability module |
| Available implementations | `package.abilities.implementations` from packages selected for the target environment |
| Consumer requirements | Package requirement templates and the final fixed point's concrete requests |
| Concrete configuration | One final evaluated AOS module fixed point |
| Provider selection | The checked binding plan |
| Requested runtime changes | The checked effect plan |
| Live results | The execution journal and provider observations |
| Package reference documentation | A projection of the package module's checked options and declarations |
| Deployment documentation | A projection of the evaluated configuration, binding plan, and effect plan |
| Qualification subjects | A projection of the implementations and methods exposed by selected packages |

Derived views may cache a canonical serialization of an authoritative value.
They MUST NOT restate its package names, interfaces, handlers, unit names,
counts, digests, or documentation ownership in a separately maintained
catalog.

## One typed module vocabulary

Every authored configuration fact enters through the ordinary AOS module
system. The generic ability graph under `aos.abilities` is a derived,
typed intermediate representation for resolution and execution. It is not the
primary interface for packages to describe a service, network endpoint, or
other domain object. The shared graph schema includes:

```nix
options.aos.abilities = {
  environment = lib.mkOption {
    type = lib.types.nullOr environmentIdentityModule;
    default = null;
    internal = true;
  };

  interfaces = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule interfaceModule);
    default = {};
  };

  implementations = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule implementationModule);
    default = {};
  };

  requirementTemplates = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule requirementModule);
    default = {};
  };

  guarantees = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule guaranteeModule);
    default = {};
  };

  instances = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule instanceModule);
    default = {};
  };

  requests = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule requestModule);
    default = {};
  };

  bindings = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule bindingModule);
    default = {};
  };

  desiredResources = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule desiredResourceModule);
    default = {};
  };
};
```

The graph submodules are supplied by `lib.abilities`, but they are ordinary
`mkOption`, `types.attrsOf`, and `types.submodule` values. Domain feature
modules own the public recursive option trees and derive the graph from their
evaluated values. Base, system, operator, runtime, package, and provider modules use ordinary
`options`, `config`, `imports`, `mkIf`, `mkMerge`, defaults, priorities, and
assertions to contribute to this tree. Package and provider provenance is
attached to the definitions by the existing module evaluator. There is no
second `abilities.exports` / `abilities.imports` / `abilityBindings` module
schema.

The outer evaluator sets `aos.abilities.environment` for the explicit target.
It is absent while a package's static projection is evaluated. An enabled
package module uses that value to derive stable consumer and provider instance
identities; it never hard-codes a host identity. Consumer instances may emit
requests without implementing an interface. Provider instances additionally
refer to their exact selected implementation and its typed configuration.

`lib.abilities.types` is the portable subset of AOS option types. Its Boolean,
bounded integer, bounded string and enumeration, list, map, record, tagged
union, reference, and lifetime constructors return normal Nix option types
with a canonical portable-schema projection. An interface field is authored
once with one of these types. The same value drives module evaluation,
normalized package and wire schemas, generic configuration parsing, editor
metadata, and reference documentation. Rust implements the generic closed
schema decoder and validator; it does not repeat interface fields, defaults,
method sets, or package declarations. Conformance checks compare the generic
Nix and Rust schema implementations.

Every interface, implementation, requirement template, option type, default,
semantic constraint, method, guarantee, handler selector, and description has
one owning module declaration. Each method declares its required target access
and whether it stops its provider. Those are the only authored method scheduling
facts because neither can be recovered from the method's input and output
schemas. Provider readiness is derived from the declared readiness output and
its producer binding. There is no central operation-family or backend-action
catalog. Checked operations carry the selected method's exact projected
semantics, and validation requires them to agree with the retained interface
document. Facts that can be determined from a method's schemas, references,
visibility, or retained bindings are derived rather than authored as additional
flags. Configured instances and requests refer to those declarations by typed
identity instead of copying their contents.

Option reference annotations are fields of the same `mkOption` declaration.
Visibility, extension policy, deprecation and replacement information, and
declaration provenance are projected with the option's path, type,
description, default, and example. Publication signs that complete projection.
Documentation and registry clients consume the signed projection directly;
they do not re-evaluate the module or join it with a separate documentation
manifest. Operational impact is derived from the final desired-resource diff,
selected methods, and effect plan. An option declaration does not repeat unit
names or predict backend actions in a documentation-only activation field.

Bindings refer to requests and implementations; desired resources refer to
the selected definitions. Module type checking rejects unknown fields,
malformed values, invalid merges, and missing required values during the final
evaluation. TOML, JSON, CLI, and editor inputs are converted generically into
module definitions from the exported option schema and then pass through that
same evaluation path; they have no handwritten package parser tables.

This is semantic single authorship, not a ban on materializing derived output.
A canonical package document, release manifest, documentation page, or cache
may contain the projected value needed at its boundary, but it is generated
from the evaluated option graph and cannot be edited as another source. Human
guides may explain workflows and concepts. Types, defaults, accepted values,
ability relationships, provider features, unit names, and other machine
reference material are generated from their owning declarations and evaluated
outputs.

## End-to-end data flow

```text
package definitions
  mkDerivation { abilities = packageIntegrationModule; }
        |
        +--> ordinary payload derivations
        +--> checked option declarations and normalized package projections
                         |
selected packages -------+
        |
        +--> static provider candidates and module locators
        +--> package requirements
                         |
explicit target environment and operator bindings
                         |
             selected package/provider modules
                         |
       one complete AOS module fixed point
                         |
concrete instances, requirements, provider definitions, and desired resources
                         |
             checked binding and effect plans
                         |
selected handler artifacts and observed provider state
                         |
                 admission and execution
                         |
             journaled outcomes and observations

The same normalized package documents, plans, and observations
        +--> CLI inspection
        +--> package and deployment documentation
        +--> Hub reference and deployment views
        +--> release verification
        +--> generated qualification subjects
```

No frontend reconstructs this graph from source text, filenames, unit names,
human-readable output, or a private copy of the provider inventory.

## Composed domain option trees

The service domain owns `aos.services`, declared as an attribute set of strict
submodules. A service is one module value; feature modules extend its option
schema and configuration in the same nested fixed point:

```nix
options.aos.services = lib.mkOption {
  type = lib.types.attrsOf (lib.types.submodule [
    serviceCore
    commandLifecycle
    ordering
    readiness
  ]);
  default = {};
};

config.aos.services.web = {
  enable = true;
  lifecycle.start = [ /* typed command values */ ];
  ordering.after = [ "database" ];
};
```

The module list is illustrative. A target selects domain API modules before
evaluating service values; no import depends on a selected provider or on a
service's final `enable` value. Different modules may declare and define
different fields of one named service. Normal module defaults, priorities,
conditions, provenance, type checks, and option documentation apply at each
field. The domain projection derives static requirement templates even when a
service is disabled, then derives concrete instances and requests when it is
enabled. Package authors do not call `splitDefinition`, copy the service
declaration into requirement and request maps, or add an empty instance solely
to make resolution work.

Feature schemas belong to the relevant domain modules, not to language-level
`lib`. `lib.abilities` supplies generic option types, interface machinery,
normalization, and graph validation. It does not auto-import a catalog of
service, storage, network, boot, or kernel interfaces. A target without a
service domain need not import its schema. A provider package owns its concrete
implementation modules and handler artifacts; the service API remains
provider-neutral.

Schema composition and runtime composition are separate. A command lifecycle
feature and an ordering feature can both extend `aos.services.web`. A manager
that implements ordering must then schedule the start/stop operations supplied
by the selected lifecycle implementation. Provider binding checks the required
features, scope, and lower-interface dependencies. One controller owns each
resource and transition; two managers cannot independently start the same
service. A single manager can satisfy all requested features, or a composite
manager can delegate to lower implementations.

## Package construction

`abilities` is a first-class AOS package field whose value is an authenticated,
path-backed standard module directory. The directory contains `module.nix` and
any package-owned implementation files that it imports:

```nix
mkDerivation {
  pname = "example";
  version = "1.0";

  abilities = ./_example-package-module;
};
```

The referenced module is ordinary module source shipped in the package's
authenticated module output. It contributes typed options and ability values
through the standard module fixed point:

```nix
{ lib, ... }: {
  config.aos.services.example = {
    enable = true;
    lifecycle.start = [{
      executable = {
        artifact = lib.abilities.packageOutput {};
        entry_point = "bin/example";
        arguments = [];
      };
      ignore_failure = false;
    }];
  };
}
```

Package definitions receive the composed AOS `lib` through the existing
package call mechanism. They use generic `lib.abilities` value constructors
and the selected domain option modules. They MUST NOT import private library
files by relative path.

The module owns the package's configuration options and service declarations;
domain modules derive their static interfaces, requirement templates, and
conditional instances and requests. Provider packages also own their
implementation declarations and guarantees. Package authors do not maintain a
configuration module and a parallel ability manifest containing the same facts.
The wrapper removes
`abilities` before invoking the low-level derivation primitive, evaluates it
against the shared ability schema, and returns the normalized package-local
tree as `package.abilities`. Its public fields remain `interfaces`,
`implementations`, `requirementTemplates`, and `guarantees`; wire names in the
separately derived signed `PackageDocument` are not part of the Nix API. When
the package is admitted to a system,
the evaluator imports the exact same module value into the complete system
fixed point. The public model does not use
`passthru.abilityPackage`, `passthru.abilities`, or a parallel package wrapper.

The signed package projection contains statically discoverable implementations,
requirement templates, guarantees, the module option surface and provenance,
and the exact authenticated module locator used by selection. It does not
expose another `abilityModule` or `configModule` field alongside
`package.abilities`. The final system projection contains enabled instances
and concrete requests. An enabled
instance references its package-owned template; it does not restate the
interface, schema, methods, or guarantees. A provider instance likewise
references its package-owned implementation declaration. This preserves
static discovery without introducing a second declaration.

Static interface declarations, implementation declarations, and requirement
templates are unconditional module definitions. Disabling a package feature
must not erase the package's potential provided or consumed abilities from its
signed publication projection. Enable conditions apply only to concrete instances,
requests, desired resources, and effects in the final system fixed point.

The package carrier derives collision-free final keys from the package identity
and each package-local alias. Package authors may therefore use ordinary local
names such as `service` without repeating their package name, while bindings
still identify one exact package declaration when multiple packages use the
same alias.

Ability-only changes alter the package release contract without needlessly
rebuilding unchanged payload bytes. The release identity binds the payload,
normalized ability document, provider modules, handler artifacts, and generated
documentation. A package contract refers to its own files with symbolic output
and relative-path selectors; it never embeds its own store path, NAR hash, or
closure digest.

The publication layer resolves those selectors after the payload exists and
uses the repository's canonical artifact metadata. Packages do not run a
private closure scanner or JSON rewriting derivation to manufacture their
ability document.

## Interfaces and constructors

`lib.abilities` contains provider-neutral schemas, constructors, normalization,
and local validation. It does not contain package-specific policy or a catalog
of packages that happen to implement an interface.

An interface document defines request and result schemas, methods, guarantees,
lifetimes, aggregation rules, and compatibility identity. Applications and
providers reference the same interface value. A consumer authors a symbolic
interface selector and generic structured request values; it neither imports
nor depends on an implementation package to declare that requirement. The
final module fixed point selects the interface document and validates those
values against its portable request schema. A core provider-neutral interface
has one shared canonical owning module, while each provider package declares
its implementation of that interface. A provider package declares an interface
only for an intrinsically package- or backend-specific extension. There is no
separate `abilityDeps` edge or consumer-owned copy of the interface schema.

A package may define a package-specific interface alongside its package when
that interface is intrinsically owned by the package. Shared service, process,
storage, credential, endpoint, and policy interfaces remain provider-neutral
so a consumer does not depend on one implementation merely to name its
requirement.

Nix and Rust consume the same canonical interface documents. Rust does not
carry a handwritten second copy of an interface catalog, descriptor digest, or
method inventory. Language-specific types may encode the closed wire model,
but generated fixtures or conformance checks prove agreement with the canonical
documents.

## Package-provided implementations

Every implementation is exposed by the package that ships it:

```nix
systemd = mkDerivation {
  # Ordinary package fields are omitted from this example.
  abilities = ./_systemd-package-module;
};
```

An implementation declaration names its interface, supported methods and
guarantees, symbolic provider module locator, and symbolic handler artifact.
The outer resolver imports that provider module only when it selects the exact
implementation. Package-specific
composition and transition logic stays with the provider package. Generic
libraries never dispatch on a package name.

Service-management features remain separate abilities. A provider may supply
the full set from one manager, or the resolver may compose compatible
providers. Packages request the exact features they use, such as lifecycle,
dependency ordering, readiness, reload, credential delivery, socket
activation, logging, identity, or isolation. They do not request a named init
implementation unless they intentionally rely on its specific interface.

## Package consumers and service declarations

A package describes a service by consuming service-management abilities. Its
declaration identifies its executable and immutable assets through symbolic
package-output selectors and describes the semantics it needs. It does not
emit manager-specific units, call manager tools, or import a manager helper in
the provider-neutral path.

Manager-specific configuration remains available through an explicitly named
manager-specific ability. It is not silently translated to a weaker generic
service. A package can offer more than one deployment form, such as a rich
managed service and a foreground process, when it implements and declares both
contracts.

Configuration definitions, service declarations, and ability requirements
retain package, instance, request, and option provenance through module
evaluation. They are operational inputs used for ownership and resolution;
documentation consumes that provenance but does not create a documentation-only
ownership map.

## Provider discovery and the module fixed point

Provider discovery starts from the packages selected for the explicit target
environment. The outer evaluator collects their static
`package.abilities.implementations` declarations, applies explicit operator
bindings and bounded selection, and imports only the selected provider modules.
Imports do not depend on the final `config` value.

The AOS module fixed point then composes all deploy-time configuration: base
features, the system variant, operator and runtime modules, admitted package
configuration modules, admitted provider modules, and policy definitions.
It produces concrete instances, provider definitions, desired resources, and
conditional requirements. No second ability-specific module set owns or merges
configuration.

The evaluator stamps every concrete instance and request with its closed
declaration authority: source-composed system configuration, authenticated
operator configuration, generation-pinned runtime configuration, or one exact
authenticated package module. That authority is not inferred from a qualified
attribute name. A selected package artifact is a separate, optional identity:
pure consumer instances need no package artifact, while provider instances and
handler selections retain the exact package document and immutable artifact
identities they execute. Root requests retain their consumer's module authority.
Nested requests authored by a selected provider module retain that module's
authenticated package authority even when the provider instance was selected
by system or operator configuration.

Source-composed stages serialize this completed fixed point directly. Their
bundle retains the evaluated root requirement contracts referenced by concrete
requests, the module authority and local key of every instance and request,
and selected provider package artifacts as separate fields. Materialization
does not reopen a package document to reconstruct a root requirement, infer an
authority from a namespace, or assign a package owner to a package-free
consumer. The committed environment also inventories exact store artifacts
referenced by the fixed point, including outputs outside selected provider
manifests, before validating resource and artifact references.

An image cannot observe a future boot's live provider assignments. Its
source-stage artifact therefore seals the selected fixed point, exact package
artifacts, pure transition results, and a structurally validated effect
template. It does not claim that a planned provider is available or label the
template an executable checked plan. Pure composition implementations need no
runtime provider inventory entry; terminal implementations require either a
verified root assignment or a readiness producer in the eventual effect plan.

The source-stage package document seals the build source's content, NAR, and
closure identities. The signed release record retains its exact store locator
and source closure for reproduction. Boot-stage artifact retention selects the
module and handler outputs needed to evaluate and execute the fixed point;
source derivations and their build inputs do not enter the image merely because
the package document records source provenance.

At stage entry, the environment adapter observes the existing executor,
manager and broker connections, storage, and other root facilities needed by
the selected handlers. It authenticates those observations against the sealed
artifact and static package contract. The runtime then instantiates and fully
validates the binding and effect plan against that fresh inventory, including
readiness paths for providers established by operations. A missing root
facility, changed implementation, or unresolved readiness path fails before
the first effect. Retained pure transition results may be reused only when
their checked inputs still match; runtime-sensitive changes require a fresh
pure evaluation or rejection.

The admitted plan identity and root evidence are retained with the durable
stage transaction. Recovery checks the same identities and current provider
assignments before resuming; a new boot observation cannot silently rewrite a
transaction already holding resource ownership. The receiving stage verifies
that exact admitted plan and journal at handoff. Source sealing, boot-time
admission, and receiving-stage continuation are distinct checks of one
source-authored configuration.

Image modules are source-backed paths retained with the in-image evaluator, so
the evaluator replays the exact system graph that produced the image. Inline
module values are limited to evaluation-only callers and explicitly
non-deployable repository fixtures. Requesting a deployable image or base
library from a graph containing one fails rather than packaging a partial
graph; fixture overlays do not count as evaluator-replay evidence.

If concrete requirements need another provider-selection round, the outer
evaluator updates the selected module set and reevaluates the entire fixed point
from explicit inputs. The final successful evaluation is the sole authoritative
desired configuration. Missing providers remain explicit deployment obligations
or errors; arbitrary attribute lookup is not discovery.

There is no central list of production packages, providers, services, or
activation dispositions. Absence or presence of native package abilities is
itself the classification. Test fixtures live in explicit test package sets and
do not require production code to maintain a fixture-name exclusion list.

## Binding and planning

The validator accepts normalized package documents, the target environment,
operator bindings, and evaluated requests. It checks interface compatibility,
guarantees, phases, lifetimes, ownership, module definition scopes, and bounded
composition before constructing checked values.

The resolver operates on provider declarations rather than built-in package
knowledge. Selected provider modules register pure composition and transition
definitions in the module fixed point. The final evaluated projection contains
their concrete desired resources and authenticated callable definitions.

Planning may invoke a provider transition with explicit old state,
observations, and checked bindings after configuration evaluation. That
invocation evaluates a pure projection of the frozen provider definition; it
does not assemble, import, or merge another configuration module graph. The
planner emits typed bindings and effect operations. Every changed resource has
one controller and one activation path.

The model and validation layers contain no Nix runner, package manager,
registry transport, manager connection, filesystem mutation, or handler
dispatch. Orchestration code supplies those inputs around the pure libraries.

## Effects and handlers

An effect is a typed request to one selected provider implementation. It names
the interface method, logical resource, canonical semantic revision, inputs,
dependencies, deadline, recovery behavior, and expected evidence. It does not
encode an arbitrary shell activation phase.

The runtime resolves a handler from the implementation bound in the checked
plan. Dispatch is data-driven from authenticated provider declarations. A
central `match` over PostgreSQL, nginx, Kubernetes, systemd, or other package
names is forbidden.

Built-in executors may implement a deliberately small primitive operation ABI.
Their registry is the implementation of that ABI, not a second catalog of
package abilities. Package handler executables and provider modules remain in
their owning packages. Dependencies such as JSON parsers belong to the handler
or runtime closure that executes them; declarative package contracts have no
tool dependencies.

## Identity, revision, lifetime, and state

Logical identity, semantic revision, live incarnation, and transaction attempt
remain distinct.

- A logical instance survives package upgrades.
- A resource key identifies one provider-owned resource within an environment.
- A revision is derived from canonical semantic inputs that affect requested
  behavior.
- An incarnation is assigned by the live provider and is revalidated before
  use.
- An attempt identifies one execution of an operation.

Revision material is derived centrally from canonical content and exact
artifact identities after symbolic package outputs have been resolved. An
artifact's semantic content identity is based on immutable NAR/content and
closure identities; its store path remains an authenticated locator and is
excluded from semantic revision material. Per-resource revisions project the
typed instance configuration, its concrete requests, selected interface and
implementation identities, and normalized artifact identities. They do not
reuse a package-document digest that contains locator fields. Raw store-path
strings, manually copied hashes, package lists, and hand-maintained counters
are not revision inputs. Package authors do not set a revision for ordinary
service changes. An operator may supply one explicit restart token to force
reapplication; providers may expose narrowly typed additional content inputs
when an external resource is intentionally outside the normal graph.

Lifetimes are interface semantics:

| Lifetime | Meaning |
| --- | --- |
| Attempt | Valid only while one operation attempt is executing |
| Transaction | Retained through completion or recovery of one transaction |
| Instance | Exists while the configured logical instance exists |
| Persistent | Survives disablement until an explicit authorized deletion |

Provider state is stored by logical provider and resource identity. The
runtime owns one current state schema when this implementation lands. Draft
schemas and migrations created while developing the same unreleased change do
not remain in the final tree.

## Version and cutover policy

The final externally persisted and exchanged formats begin at version 1 and
retain their `/v1` schema discriminator. Interface ABI, wire schema, required
client features, handler ABI, and provider state format remain separate
compatibility dimensions.

Versioning does not preserve abandoned drafts from the same unreleased change.
The final implementation has:

- one version-1 definition for each new format;
- one parser and one serializer for that definition;
- no `legacy` representation of the same new concept;
- no adoption-v1/adoption-v2 fixtures for branch-local designs;
- no handler-name suffix used only to distinguish discarded drafts;
- no migration code between schemas that have never shipped.

Compatibility code is added only for a format that exists in an already
supported release or persisted state that users can actually possess. Such a
change names the released boundary, its support window, and its independent
qualification. Within the RFC-0022 implementation PR, packages move directly
from the pre-ability activation model to the final ability model. The final
tree does not retain both paths for migrated packages.

## Activation and package migration

All service-owning packages in the completed change use structured abilities
and effects. Their previous expose/config activation ownership is removed when
their ability path lands. Payload-only packages simply have no service
requirement; this is derived rather than recorded in an inventory.

At every point in the final system, one resource has one controller. A package
cannot publish both an opaque legacy activation script and a structured effect
plan for the same service. Generated manifests for an old script are not a
migration.

The activation engine consumes only the checked binding and effect plans. It
does not select behavior from a package-name allowlist, a migration disposition,
or the presence of old metadata. Retained generations store exact final-format
plans and artifacts needed for recovery.

## Platform and service-management composition

The core model is independent of a kernel, init implementation, container
runtime, filesystem manager, and network-policy backend. Platform packages
expose concrete abilities and guarantees. System definitions select those
packages and describe the target environment.

A service package can therefore remain unchanged when the target selects a
different compatible provider set. Rich service features are expressed as
composable abilities instead of being reduced to the least capable manager.
When a selected provider set cannot meet a required feature, resolution fails
with the missing ability or guarantee.

Host, early-boot, container, and user service managers are distinct provider
instances. A package installed as payload does not imply that a compatible
manager instance is running or selected.

## Configuration, images, and staged environments

Package ability modules use the restricted module evaluation boundary. Their
ordinary package settings and their ability declarations share one `options`
and `config` graph, and the resulting fixed point preserves definition and
option provenance. Ability outputs may feed authorized option definitions.
Runtime-produced values remain typed deferred results rather than being read
during pure Nix evaluation.

Early-boot, host, container, and image-build stages advertise separate
environment abilities. Requirements cannot cross stages implicitly. Image
construction records unresolved runtime obligations and does not claim that an
artifact supplies live runtime facilities merely because it contains their
executables.

Container launch, foreground execution, system containers, and bootable images
are separate interfaces. Each advertises the semantics it actually implements.

## Documentation and inspection

The shared inspection library constructs one bounded documentation/view model
from checked package documents, plans, and observations. `aos docs`, APM-facing
package documentation, AOS Hub, editor tooling, and JSON exports render that
model rather than implementing their own joins.

Package reference documentation reads the checked package option declarations
and canonical package projection and shows every provided and consumed
interface, method, guarantee, configuration option, handler
artifact, and supported environment. Deployment documentation adds the
selected provider for each requirement, effects, current observations, and the
typed values and provider realizations of resolved resources from the checked
inspection view.

The central documentation module is a pure projection over the package and
module fixed points. Separate service and option-prefix catalogs, copied unit
name lists, and package-specific documentation branches do not exist. Unit
names and other backend artifacts appear only inside typed provider
realizations validated by the resource's interface schema. Option names, types,
defaults, descriptions, examples, and provenance come from evaluated `mkOption`
declarations. Ability schemas and relationships
come from the corresponding `aos.abilities` definitions. A frontend cannot
provide a second default, method description, provider feature list, or
package-to-option association.

Documentation prose has its own identity and does not change a semantic
revision. Semantic fields are documented from the canonical schemas so prose
cannot silently disagree with validation.

## AOS Hub, registry, and publication

Publication binds the normalized ability document and resolved artifact
references to the exact package release. The registry serves that checked
document. It does not evaluate arbitrary package Nix in a request path.

AOS Hub consumes the shared public inspection model. Deployment overlays use
separately authorized plan and observation inputs. Native and Worker
implementations share the same bounded decoder and view semantics; they do not
maintain package or interface switch statements.

For each indexed release platform, Hub derives one bounded canonical graph
from the verified package references. Exact interface documents appear once;
package exports and consumed requirements refer to those identities, and
requirement matches account for interface selectors, required methods, and
required guarantees. The graph is a disposable release-index projection used
unchanged by the Connect API, REST API, CLI, and web renderer. It never becomes
an authored catalog or an independent package-contract authority.

Release verification walks the declarations in the published package document.
It derives required artifacts, handlers, interfaces, and qualification subjects
from that document. It does not compare against a checked-in copy of the
production provider matrix.

## Qualification and fixtures

Qualification is generated from the selected providers and their advertised
methods. A provider declaration includes the conformance families required for
the semantics it claims. The qualification layer expands those declarations
into subjects and schedules them into reusable, parameterized harnesses.

Human-authored test data is limited to small semantic examples, invalid edge
cases, explicit policy choices, and independent observations. Large normalized
documents, adapter matrices, handler inventories, hashes, counts, and package
lists are generated during the check and are not committed as golden files.

Scheduling cohorts may be explicit when they express resource or runtime
policy. They reference generated subject identities and are checked as a
partition; they do not repeat interface methods or expected global counts.
Adding a provider or method automatically changes the generated qualification
surface and fails if its required evidence is absent.

Tests call shared model and validation libraries. CLI, Hub, release, and Nix
tests verify their orchestration and presentation boundaries rather than
reimplementing semantic validation.

## Component boundaries

| Component | Owns | Must not own |
| --- | --- | --- |
| `lib.abilities` | Language-level ability types, graph primitives, normalization, and local checks | OS-domain interface catalogs, package/provider catalogs, runtime commands |
| Domain feature modules | Typed recursive service, storage, network, boot, and other relevant option trees and graph projections | Assumptions about an unrelated target's available OS primitives |
| AOS `mkDerivation` | Native ability-module field, package projection, and payload/contract separation | Provider selection or target-specific binding |
| Package definitions | Their provided/consumed abilities, modules, handlers, service declarations | Generic resolver behavior or self-computed artifact identity |
| AOS module evaluator | The sole deploy-time configuration fixed point, provider definitions, and provenance | Registry traversal, a parallel ability configuration graph, or runtime effects |
| `aos-ability-model` | Wire types, canonical encoding, typed identities | Nix evaluation, transport, package-specific handlers |
| `aos-ability-validate` | Pure structural and semantic validation | Filesystem mutation or provider discovery I/O |
| `aos-ability-plan` | Pure bounded resolution, composition, and transition planning | Package-name dispatch or live effects |
| `aos-ability-inspect` | Shared queries, documentation views, diffs, diagnostics | Independent graph reconstruction or activation |
| `aos-ability-runtime` | Admission, handler invocation, journaling, recovery | Package-specific implementation catalogs |
| AOS/APM orchestration | Evaluation, registry I/O, environment snapshots, calling shared libraries | Duplicate semantic validation |
| Provider packages | Backend-specific modules, handlers, observations, guarantees | Changes to unrelated package contracts |
| `aos-doc-model` and frontends | Shared serializable presentation model and rendering | Hand-maintained service/provider joins |
| Release tooling | Artifact binding, publication checks, generated qualification surface | Checked-in production matrix snapshots |
| Qualification harnesses | Parameterized execution and independent evidence | Parallel provider or method inventories |

Crate boundaries may change, but these dependency directions and ownership
rules do not.

## Forbidden final-state patterns

The completed implementation rejects these patterns during review or checks:

- package definitions importing private `lib/abilities` files;
- `passthru` as the public home of package abilities;
- package-specific branches in generic Nix or Rust layers;
- a central production adapter or service inventory copied from packages;
- manual hashes or counts for values available to the evaluator;
- checked-in generated provider matrices or normalized production snapshots;
- documentation-only package-to-option or package-to-unit mappings;
- an ability fact authored both in package metadata and module configuration;
- handwritten parser, option, default, or reference-documentation tables for
  package abilities;
- a central operation-family, backend-action, or method-classification catalog;
- declarative contracts depending on `jq`, shell, or another executable tool;
- an independently assembled ability-module configuration evaluation;
- raw store paths used as semantic revisions;
- two activation owners for one migrated resource;
- compatibility code for drafts introduced and replaced within the same PR;
- tests that prove behavior only by comparing two copies of the same catalog.

## Completion condition

RFC-0022 is implemented only when every supported package and system path uses
this ownership model, every semantic fact is authored once through the typed
module vocabulary, all deploy-time configuration shares one final module fixed
point, all parsers and frontends consume generated schemas or shared
projections, production qualification is derived from package declarations,
and searches plus tests demonstrate that the forbidden patterns are absent. A
working engine beneath a parallel legacy package model does not satisfy the
RFC.
