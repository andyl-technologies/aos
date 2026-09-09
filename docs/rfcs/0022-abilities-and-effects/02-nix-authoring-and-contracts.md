# Nix authoring and authenticated contracts

## Keep the language and extend the AOS module vocabulary

Nix attribute sets, functions, imports, and the AOS module engine can express
interfaces, provider declarations, requests, explicit bindings, and pure
lowering into configuration. This proposal requires no new syntax or evaluator
fork. It extends AOS libraries and package construction.

The existing option interfaces remain useful. A virtual-host request should
reuse nginx's option schema. A systemd service request should reuse the typed
systemd service vocabulary. There is no requirement to replace these with a
lowest-common-denominator workload schema.

The module fixed point composes already-admitted definitions. The outer APM
resolver discovers and selects provider modules. Imports MUST NOT depend on
the final `config` being computed; arbitrary missing-attribute recursion is not
a provider-selection algorithm.

## Authoring responsibilities

The library provides package-local declarations for exported interfaces,
consumer requests, lower-interface requirements, explicit deployment bindings,
and provider-owned composition and transitions. The complete authoring example
is in [recursive composition](03-recursive-composition.md).

Existing pure mappings into nginx or another owner's option tree remain a
useful contribution mechanism. They are only one facet of an exported ability.
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
| Contribute | Add one application virtual host | Authorized write scope and interface ABI |
| Consume an output | Read an endpoint or rendered config artifact | Named result and data/retention dependency |
| Apply behavior | Reload a service after config changes | Separately authorized lifecycle effect |

The trusted projection attributes lowered definitions to the original
consumer, provider, request, and binding. It validates both the provider's
declared mapping authority and the consumer's granted contribution scope.
Calling provider-authored code is not a way to launder a consumer request into
owner privileges. Privileged results, such as Kubernetes RBAC declarations,
require their own authorization before application.

Existing `ownsRoots`, `contributes`, `contributable`, and interface ABI checks
remain the basis for ownership. Configuration merging happens inside the
authorized surface. `mkForce`, option precedence, `readOnly`, and a fabricated
attribute set MUST NOT expand that surface.

Multiple consumers can contribute disjoint named entries. Colliding exclusive
slots fail validation. Shared aggregate interfaces must define their merge
semantics rather than depend on incidental import ordering. Enablement and
global service policy remain operator/owner decisions unless explicitly
delegated.

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

Extend the existing companion-artifact pattern. Integration edits should not
rebuild an unchanged payload, and the payload must not acquire a circular
reference to its own integration companion.

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

Canonical encoding, size/depth bounds, stable ordering, unknown-field handling,
and digest domains must be specified before these contracts become persistent
APIs. Interface ABI, module ABI, operation-handler ABI, and wire format version
are separate compatibility dimensions. Documentation prose has a separate
identity and MUST NOT cause runtime restarts or measurement churn by itself.

Both source builds and APM invoke a common semantic validator over normalized
plans. A source build uses an AOS-built validator as a required check
derivation; Nix assertions provide earlier errors. This does not require
import-from-derivation or a new build-host tool dependency.

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
