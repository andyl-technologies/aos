# Security, trust, and compatibility

## Authority survives every lowering boundary

The declaration-to-execution chain is:

```text
authenticated package implementation
  + consumer request
  + operator grant and environment ceiling
  -> scoped provider binding
  -> attributed child requests and effects
  -> runtime resource acquisition and enforcement
```

Each expansion retains the original request provenance and the provider's
identity. A signed package is trusted as that publisher's artifact; its
signature does not authorize root effects. A provider manifest can advertise
an interface but cannot grant itself the resources needed to implement it.

Provider mediation is intentional. An application allowed to add one virtual
host need not receive nginx's file-write or service-reload handle. Nginx may
use its separately authorized implementation resources to fulfill that public
request. The grant must explicitly permit that mediation, and the provider
must validate the caller's allowed names, parameters, and contribution scope.
The caller cannot choose an arbitrary destination or command and borrow the
provider's authority. Child requests remain within the applicable provider
grants and inherited environment ceilings.

Pure lowering is not an enforcement boundary by itself. Validate normalized
outputs after module merging, including ownership and privileged results.
`mkForce`, fabricated binding attributes, and provider-generated definitions
cannot bypass contribution restrictions. Runtime providers then enforce the
actual resource scope; Nix types alone cannot do so.

## Environment admission and races

Use authenticated logical resource identities and scoped acquisition protocols
from the sandbox/runtime providers. Avoid resolving a checked name once and
later reopening an unchecked path after its identity may have changed.
Implementation-specific filesystem and IPC handlers must define how they
preserve identity across use, including symlink, namespace, and incarnation
changes.

Revalidate freshness, assignment, policy revision, and relevant preconditions
before effects. A lease or lock coordinates only participants that honor it;
external effects may require provider fencing or compare-and-swap revisions.
Record ambiguous outcomes and reconcile them rather than claiming a local
journal makes remote effects atomic.

Revocation must state its enforcement behavior. Existing descriptors, running
processes, and in-process libraries may retain access after metadata changes.
When required revocation needs stopping or restarting a consumer, the plan
must include that operation. An unsupported guarantee blocks admission.

## Runtime handlers

The trusted executor recognizes a small set of versioned operations or
dispatches to authenticated, explicitly authorized handlers. Handler artifacts
are pinned with the plan and run within declared resource/identity constraints.
Installing a package does not register an unrestricted privileged plugin.

Scripts may implement bounded operations during migration, with honest opaque
effect declarations and qualified recovery behavior. A root script that can
modify arbitrary host state is not made least-privileged merely by placing it
behind a typed request. New privileged primitives require implementation and
security review before being accepted by the execution contract.

## Persistent contracts and old clients

Version interface semantics, Nix module ABI, operation/handler ABI, manifest
encoding, and journal format separately. Define canonical data, digest domains,
bounds, stable identities, and feature negotiation before publication.
Bounded parsing precedes expensive evaluation or graph expansion.

Unknown optional descriptive fields may be ignored only under an explicit
schema rule. Unknown required guarantees, operation kinds, authority fields,
or execution features MUST fail closed. An old client must not activate a
new contract by treating its unrecognized requirements as absent.

Legacy packages keep their existing execution path until a qualified adapter
exists. The adapter records what is known and what remains opaque; it cannot
claim newly proven guarantees. New releases that require ability-aware
activation must declare that requirement in a place old clients already
enforce, or use a publication/compatibility boundary that prevents those
clients from selecting them. Merely adding an unfamiliar field is insufficient.

Persisted plans never embed Nix closures, Rust-native enum layouts, raw handles,
or secrets. Retain exact authenticated source/modules and artifacts where
re-evaluation is needed. Runtime observations and private authorization evidence
have separate access and retention policies from public package metadata.

## Hermeticity and established boundaries

Every new compiler, validator, helper, or handler must be built from source as
an AOS package using the existing bootstrap and dependency rules. The Nix
module vocabulary requires neither an evaluator fork nor an upstream nixpkgs
dependency. Build and test derivations must use AOS-provided tools and shells.

The Crucible Apache host and GPL-side QEMU/plugin remain separate processes,
integrated only through their versioned protocols. Ability metadata is not an
exception to those boundaries. Changes to the public ABI or licensing boundary
must pass the existing required gates, and patched QEMU distribution retains
matching corresponding source under the established release policy.
