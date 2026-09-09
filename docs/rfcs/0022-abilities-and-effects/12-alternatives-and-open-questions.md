# Alternatives, prior art, and implementation decisions

## Architectural choices

| Alternative | Decision and reason |
| --- | --- |
| A universal replacement workload schema | Retain native typed systemd and package schemas; a generic process interface covers explicitly portable cases |
| Environment booleans and package-name dependencies | Useful discovery hints, insufficient for resource identity, consumption, authority, or compatibility |
| Treat Nix option lowering as the complete ability implementation | Insufficient; providers must explicitly compose requests and transitions through lower abilities |
| Execute the complete dependency graph on every activation | Derive a transition from current and desired state; unchanged relationships often need no effect |
| Express plans directly as arbitrary syscalls | Retain typed semantic operations for authorization, completion, and recovery; trusted implementations own the syscall details |
| Introduce Haskell or another general-purpose execution language | Use pure Nix authorship and a bounded Rust-interpreted operation representation; a new language is not necessary for these contracts |
| Fork Nix to add effect inference | Defer; module libraries and checked normalized data can support the first implementation |
| Infer all effects from scripts or binaries | Unsupported; retain explicit opaque effects and actual runtime enforcement |
| Privileged containers as automatic compatibility repair | Reject; the selected environment must satisfy explicit authorized requirements |
| Rebind arbitrary existing shared libraries at deployment | Defer; exact linked artifacts and closure retention remain authoritative |
| Reverse the operation graph for rollback | Replan under current authority and state; use only explicitly supported compensation |
| Add AOS ability semantics to Crucible | Keep Crucible guest-agnostic; an optional AOS-side adapter uses its generic guest interfaces |

## Prior art and limits of the comparison

These projects inform the design; none establishes that AOS can obtain their
properties merely by adopting similar names. Comparisons below are design
inferences from the linked primary documentation.

### Genode: recursive services and resource delegation

Genode is a close architectural comparison for components that consume and
provide services within a parent-mediated composition. Its common session
interfaces include ROM delivery for executable and shared-library content;
component composition includes adapters between filesystem and ROM services.
This demonstrates a useful relationship between software artifacts, service
interfaces, and recursive composition.

AOS still runs Linux applications with existing ambient process authority.
This RFC does not claim the isolation or object-capability properties of a
different kernel/component architecture. AOS must state and enforce its actual
process and broker boundaries.

Sources: [common session interfaces](https://www.genode.org/documentation/genode-foundations/25.05/components/Common_session_interfaces.html),
[component composition](https://www.genode.org/documentation/genode-foundations/25.05/components/Component_composition.html),
[core and the component tree](https://www.genode.org/documentation/genode-foundations/25.05/architecture/Core_-_the_root_of_the_component_tree.html).

### Fuchsia: components, routed capabilities, and runners

Fuchsia separates component organization and capability routing from package
distribution. Runners implement execution environments for components. This
supports the distinction between an artifact, a component instance, and the
provider that executes it. AOS can use that separation while preserving its
own package/configuration and systemd interfaces.

Sources: [organizing components](https://fuchsia.dev/fuchsia-src/get-started/learn/components/organizing-components),
[runner capabilities](https://fuchsia.dev/fuchsia-src/concepts/components/v2/capabilities/runner).

### Spack: dependency use and provider selection

Spack distinguishes build, link, and run dependencies and supports virtual
dependency providers. These are useful precedents for recording how a
dependency is consumed and how a concrete implementation is selected. They
do not supply the host authorization, runtime handles, or durable activation
semantics proposed here.

Sources: [package creation and dependency types](https://spack.readthedocs.io/en/latest/packaging_guide_creation.html),
[spec syntax and virtual dependencies](https://spack.readthedocs.io/en/latest/spec_syntax.html).

### Nix and NixOS: pure description and runtime activation

Nix string contexts preserve dependency references in evaluated values. That
is valuable retention/build provenance but does not by itself express why a
consumer links, executes, mounts, or configures an output. The module system
supplies composition and option checking without requiring new language
syntax.

NixOS already performs runtime activation and service switching after building
system artifacts. The proposed AOS change makes provider-authored transition
interfaces, authority, typed results, and recovery explicit. It should not be
described as inventing runtime activation where NixOS has only a static graph.

Sources: [Nix string context](https://nix.dev/manual/nix/2.34/language/string-context.html),
[NixOS switching](https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/what-happens-during-a-system-switch.chapter.md).
These are design references, not proposed nixpkgs dependencies.

### Runtime and loader contracts

Systemd's container interface and the OCI image/runtime specifications support
the distinction between image contents and launch-time facilities. The GNU
libc dynamic-linker guidance illustrates why library names alone are not a
sufficient compatibility contract. None of these mechanisms removes the need
to verify actual target behavior and retain exact artifacts.

Sources: [systemd container interface](https://systemd.io/CONTAINER_INTERFACE/),
[OCI image configuration](https://github.com/opencontainers/image-spec/blob/main/config.md),
[OCI Linux runtime configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md),
[GNU libc dynamic linker](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html).

## Resolved implementation questions

The following questions have normative answers in the detailed contracts.
They are not left to independent interpretation by each adapter or frontend.

| Question | Specified decision |
| --- | --- |
| Nix authorship and symbolic results | Pure composition and transition constructors; versioned closed schemas; typed scoped ports with checked phases; no serialized closures |
| Existing single-root configuration to multiple instances | Stable `default` mapping; additional instances require isolated unit, directory, credential, endpoint, and ownership rendering |
| Conditional discovery | Authenticated bounded alias vocabulary; deterministic outer evaluation/selection loop; no arbitrary solver predicates |
| Parent/child scheduling | One controller per mutable resource; child method composition does not independently reconcile the same resource |
| Initial operations and handler extension | Ten semantic families; trusted compiled adapters, existing protocols, or constrained cataloged helpers; no privileged package-loaded plugin |
| Guarantee equivalence | Exact admitted semantics in version 1; new equivalence requires an explicit tested adapter |
| Provider selection | Explicit binding, existing pin, then operator-ordered bounded search; invalid pins fail and unordered ambiguity rejects |
| Runtime revocation | Provider-specific enforcement contract and fresh assignments; stop/restart when needed, reject unsupported revocation guarantees |
| Boot and executor upgrades | Grounded staged admission and explicit ownership handoff; retained recovery artifacts; unknown journal/method versions prohibit resume |
| Legacy clients | Existing `requires-features` gate with `abilities-v1` and `ability-effects-v1`; qualify all supported entry paths |
| Partial publication | Independent generation axes with actual receipts; post-publication failure retains the commit and reports failed/uncertain consumers |
| Retention and privacy | Root plans before effects and retain active/recovery inputs; protected execution evidence separate from public redacted views |

See the [implementation contract](implementation-contract.md),
[execution contract](execution-contract.md), and
[completion map](implementation-completeness.md) for their full requirements.

## API qualification and future extensions

Exact helper signatures, Rust names, serialized field spellings, and UI layout
are implementation choices within the specified semantics. Publish their
versioned definitions and shared fixtures before freezing the API. The complete
reference fixture, not syntax sketches alone, establishes that independently
authored providers can compose without hidden central special cases.

Future providers must specify their own concrete guarantees, observation,
revocation, and state-migration contracts. Supporting a new runtime is a tested
extension, not an assumption that an existing interface name implies semantic
equivalence. General Nix effect inference, unrestricted runtime languages, and
deployment-time substitution of arbitrary linked libraries remain outside the
accepted scope; they require separate designs.

The first stable API should be smaller than the full ecosystem vocabulary.
It must nevertheless preserve the ability to compose independently authored
providers, retain semantic operations, and enforce the same contracts in both
source-defined and registry-installed deployments.
