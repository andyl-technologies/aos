# Nix authoring and authenticated contracts

## Keep the language and extend the AOS module vocabulary

Nix attribute sets, functions, imports, and the AOS module engine express
interfaces, provider declarations, requests, explicit bindings, and pure
lowering into configuration through ordinary `options` and `config`. This
proposal requires no new syntax or evaluator fork. It extends the shared AOS
option vocabulary, libraries, and package construction.

The existing option interfaces remain useful. A virtual-host request should
reuse nginx's types within an explicitly authorized option extension surface. A
package service requests the typed `aos.service-management` lifecycle and the
exact features it needs. Backend-specific definitions stay inside the selected
provider, so the public contract remains rich without becoming a universal
workload schema.

One final module fixed point composes base, system, operator, runtime, selected
package, and selected provider modules. The outer APM resolver discovers and
selects package/provider modules before each complete evaluation. Imports MUST
NOT depend on the final `config` being computed; arbitrary missing-attribute
recursion is not a provider-selection algorithm. A bounded selection loop may
reevaluate the whole fixed point, but it does not create a parallel
ability-specific configuration graph.

## Authoring responsibilities

`abilities` is a first-class field of an AOS package. Its value is an ordinary
AOS module, not a free-form manifest. The module uses the shared typed
`aos.abilities` option tree for provided interfaces, consumed abilities,
lower-interface requirements, and provider-owned composition and transitions.
Operator modules use the same tree for explicit deployment bindings. The
package's checked static projection is available as `package.abilities`, and
the exact same module is imported when the package participates in the final
system fixed point. A `passthru` convention, companion package model, or
separate ability module evaluator is not part of the public authoring API. The
complete authoring rules are in the
[target state](13-target-state.md), and a composition example is in
[recursive composition](03-recursive-composition.md).

`lib.abilities.types` supplies ordinary AOS option types with a canonical
portable-schema projection. Authors declare each field, default, constraint,
description, interface method, and guarantee once. Module evaluation, generic
configuration parsing, package publication, Rust validation, editor metadata,
and generated reference documentation consume projections from those
declarations. Package modules do not repeat the same facts in metadata or a
documentation-only tree.

Existing pure definitions in nginx or another owner's option tree remain a
useful extension mechanism. They are only one facet of an exported ability.
The provider must also declare how it consumes other abilities to realize the
merged desired state and its transitions. Those relationships cannot remain
implicit inside an unrelated central renderer.

Package-local declarations do not permit arbitrary writes into a shared global
authority tree. Authenticated deployment composition supplies exact instance
identities and grants. A Nix attribute describing a binding is a claim for the
validator to check, never a self-authenticating capability.

## Configuration as a consumed interface

Configuration interactions have different authority:

| Interaction | Example | Contract |
| --- | --- | --- |
| Extend owner options | Define one application virtual host | Authorized option path and interface ABI |
| Consume an output | Read an endpoint or rendered config artifact | Named result and data/retention dependency |
| Apply behavior | Reload a service after config changes | Separately authorized lifecycle effect |

The trusted projection attributes lowered definitions to the original
consumer, provider, request, and binding. It validates both the provider's
declared mapping authority and the consumer's granted option scope.
Calling provider-authored code is not a way to launder a consumer request into
owner privileges. Privileged results, such as Kubernetes RBAC declarations,
require their own authorization before application.

Existing root ownership, `extensible` option declarations, and interface ABI
checks remain the basis for ownership. Configuration merging happens inside the
authorized surface. `mkForce`, option precedence, `readOnly`, and a fabricated
attribute set MUST NOT expand that surface.

Multiple consumers can define disjoint named entries. Colliding exclusive
slots fail validation. Shared aggregate interfaces must define their merge
semantics rather than depend on incidental import ordering. Enablement and
global service policy remain operator/owner decisions unless explicitly
delegated.

Structural option ownership is necessary but not sufficient for safe
delegation. Raw configuration fragments, filesystem paths, endpoints, and
privileged object fields can change behavior outside the apparent named slot.
The exported extension interface must restrict or separately authorize
those uses. The owner's full native configuration interface remains available
under its own authority; a narrower caller grant does not inherit it.

Returned values may feed other configuration: an application supplies a
backend endpoint, nginx derives a public endpoint, and another module consumes
that result. Such definitions must be well-founded. Cyclic communication does
not authorize a cyclic value definition or an impossible bootstrap order.

## Recursive providers

Any package may export interfaces and consume others. For example, nginx's
configuration provider consumes service management and credential delivery;
systemd's provider consumes process, mount, and cgroup facilities; a filesystem
provider can export immutable artifacts from an authorized storage interface.

Interfaces declare their own ABI, request/result shape, required guarantees,
and supported operation semantics. New higher-level protocols can be provided
using existing primitive effects. A new privileged primitive requires a
registered, authenticated runtime implementation and operator authorization.

Systemd-specific interfaces are allowed and expected. They preserve rich unit
semantics. A generic process interface may coexist for applications that
explicitly support foreground execution without a service manager.

## Pure evaluation and the runtime boundary

Evaluation receives an explicit target environment description and binding
inputs. It MUST NOT probe the evaluator host to infer the future runtime.
Package modules continue to receive only authenticated outputs permitted by
the existing evaluator contract, not an unrestricted `pkgs` or host filesystem.

Pure mappings may produce configuration, operation requests, and immutable
artifact references. They MUST NOT execute privileged effects during
evaluation. Secrets remain opaque references; resolved runtime paths may enter
configuration, but secret bytes do not enter the store or manifests.

Nix values are not unforgeable runtime capabilities. Runtime code reacquires
logical resources through trusted providers and checks their scope and
generation. The authorization decision must survive serialization without
depending on a particular in-memory Nix value.

## Publication artifacts

Package construction separates the ordinary payload derivation from the
normalized projection of its first-class ability module. Integration edits
should not rebuild unchanged payload bytes, and the payload must not acquire a
circular reference to its own integration artifacts. Publication resolves
symbolic package-output selectors and binds the resulting ability document to
the release using the same canonical artifact metadata as other release
inputs. A package does not run a private closure scanner or
manifest-rewriting derivation.

The exact signed release associates:

- package payload and transitive store graph;
- restricted configuration modules and module ABI compatibility;
- provided interface identities and supported versions;
- discoverable static requests and bounded provider prerequisites;
- authenticated mappings and any runtime handler artifacts;
- concrete declared permissions and artifact ownership;
- generated documentation and its locator.

The compiler may retain Nix functions in the authenticated module source, but
cannot serialize those functions as executable JSON or derive their arbitrary
semantics. Registry discovery metadata is a closed data description. Actual
configuration evaluation produces the concrete requests and results that the
Rust validator understands. Publish-time lint checks metadata/module agreement
for the supported declaration model.

## Normalized contracts

The implementation must version at least these distinct concepts:

| Contract | Contents |
| --- | --- |
| Interface description | Identity, ABI, parameter/result schema, required semantics |
| Package ability manifest | Authenticated exports, imports, mappings, handlers, ownership |
| Target environment description | Available or promised facilities, scope, policy inputs, freshness |
| Bound plan | Exact requests, selected providers/resources, unresolved deployment obligations |
| Effect plan | Operations, inputs, dependencies, authority, commit and recovery rules |
| Execution record | Attempts, observations, commit outcomes, active consumer associations |

The [implementation contract](implementation-contract.md) specifies the initial
format families, encoding, identity, bounded profile, and matching policy.
Interface ABI, module ABI, operation-handler ABI, and wire format version
are separate compatibility dimensions. Documentation prose has a separate
identity and MUST NOT cause runtime restarts or measurement churn by itself.

Both source builds and APM invoke a common semantic validator over normalized
plans. A source build uses an AOS-built validator as a required check
derivation; Nix assertions provide earlier errors. This does not require
import-from-derivation or a new build-host tool dependency.

## Validation from Nix source to runtime admission

The semantic implementation belongs to shared Rust libraries. CLI commands,
build-check executables, registry publication checks, and runtime controllers
call those libraries; they do not maintain separate interpretations of the
ability contract. Validation proceeds through distinct boundaries:

| Boundary | Checks | Result and limit |
| --- | --- | --- |
| Nix authoring/evaluation | Option types, required fields, supported declarations, merge rules, local assertions | Concrete normalized declarations; no proof about arbitrary function behavior or a future host |
| Rust contract validation | Bounded decoding, schema/version agreement, unique identities, reference existence, request/result types and phases, composition bounds | Structurally and semantically checked graph |
| Rust binding/planning | Provider compatibility, authenticated provenance, authorized scopes, guarantees, ownership conflicts, bootstrap, effect dependencies and recovery contracts | Plan checked against explicit policy/environment inputs, with unresolved obligations identified |
| Runtime admission/execution | Actual provider identity, resource assignment, current policy, freshness, preconditions, completion evidence | Scoped admitted operations and observed outcomes; checks remain necessary when state changes |

The Nix adapter evaluates authenticated modules through the restricted
evaluation path and forces the exported data needed for validation. It emits
versioned data rather than closures or an arbitrary source-code AST. Parse-only
checks cannot establish that configuration-dependent requests are valid; the
concrete configuration must be evaluated. Nontermination and evaluation
resource limits remain explicit error conditions.

Each interface's portable option type is the common schema contract. Its
canonical schema projection drives Rust structural validation and generated
editor and reference documentation. Generic Nix/Rust conformance tests prove
agreement of the closed type vocabulary; interface-specific fields and
defaults are not copied into Rust or frontend tables.
Native Nix predicates that cannot be represented in the supported schema remain
additional evaluation checks; they cannot masquerade as portable Rust solver
constraints. Cross-resource semantics and authorization require dedicated
validator logic beyond structural schema validation.

Keep unchecked decoded data distinct from checked graphs and plans in the Rust
API. Only validation constructs a checked value for a specified input identity
and context. Deserializing a record labelled `validated` does not bypass the
checks, and a checked plan is not a permanent runtime grant. This makes the
library API reusable without relying on callers to remember an informal
sequence of CLI commands.

For source builds, evaluation produces the contract and an AOS-built check
derivation validates it. Supported image/package outputs and publication gates
must depend on or require that successful check; an optional flake check users
can skip is insufficient. The validator is built from lower-level AOS inputs
so this does not create a dependency on the image or suite being validated.
APM feeds equivalent normalized input directly to the same Rust library before
live activation. Registry checks can establish package-level validity but
cannot certify an unknown future deployment's grants.

Diagnostics retain exact artifact/package identity, instance, request name,
option path, and composition ancestry. Include source file/line locations when
available, but do not promise that arbitrary Nix transformations preserve a
complete source map. The trusted adapter authenticates artifact identity;
package-supplied location text is descriptive and never authorization evidence.
The library returns structured diagnostics for CLI, editor, and Hub rendering.

## What the module library does not prove

It does not infer every effect in arbitrary shell or native code, prove ABI
compatibility from an interface name, or make serialized handles unforgeable.
It cannot safely solve arbitrary Nix predicates. Provider selection operates
on a bounded declarative constraint vocabulary; pure evaluation may discover
additional concrete requests within the bounded outer loop.

A future language extension could add stronger effect tracking or dependency
use provenance through arbitrary expressions. That is a separate research
direction. The first implementation must be useful with the existing Nix
language, evaluator, and package configuration source.
