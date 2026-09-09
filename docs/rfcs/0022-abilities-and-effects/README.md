# RFC-0022: Package abilities, typed consumption, and structured effects

- **Status:** Proposed; design only. No runtime, CLI, registry, or Nix API in
  this proposal is implemented by adding this RFC.
- **Date:** 2026-09-08.
- **Audience:** package authors; maintainers of APM, AOS, APR, the Nix module
  system, systemd integration, boot and image construction, sandbox runtimes,
  security policy, AOS Hub, and documentation tooling.
- **Baseline:** repository commit `10432f8cca97a169754759e42c19cff08fa0a946`.
  Code links describe that baseline; canonical user documentation remains the
  authority for current behavior.
- **Builds on:** [RFC-0001](../0001-package-sandboxing/README.md),
  [RFC-0005](../0005-ca-trust-map.md),
  [RFC-0011](../0011-on-host-config-eval/README.md),
  [RFC-0016](../0016-package-documentation/README.md), and
  [RFC-0019](../0019-oci-containers/README.md).
- **Coordinates with:** the sandbox and filesystem-view proposal in
  [PR #232](https://github.com/andyl-technologies/aos/pull/232). Its authority,
  resource identity, and execution machinery are integration surfaces, not
  facilities this RFC independently replaces.
- **Number allocation:** RFC-0022 was explicitly selected for this proposal.
  Active PR trees were checked before drafting. RFC-0020 appears in both
  PR #232 and [PR #194](https://github.com/andyl-technologies/aos/pull/194);
  this RFC does not resolve that existing collision or allocate RFC-0021.

## Summary

AOS will represent how software consumes its dependencies, from build tools
and shared libraries through configuration contributions, service management,
credentials, storage, networking, and image construction. A package can export
an ability, consume abilities from other packages or its execution environment,
and implement higher-level abilities using those bindings.

Nix remains the authoring and configuration language. Package-owned modules
declare typed interfaces, requests, and pure mappings. Source-defined systems
select bindings explicitly and validate them during evaluation and build.
APM resolves eligible providers for authenticated registry packages, evaluates
their configuration modules, and constructs equivalent bound plans. Both paths
use the same versioned contracts and authorization rules.

An ability declaration describes an interface and its requirements; it is not
itself authority. Operator policy authorizes bindings. Trusted runtime code
acquires scoped handles and verifies the environment before performing effects.
Neither an installed package, a Nix attribute, a path, nor a container marker
proves that a resource is available or authorized.

Systemd remains a rich execution interface. Packages continue to author typed
systemd units. A host or a suitably provisioned system container may provide a
local systemd manager. An application container may provide a narrower launch
interface. Unsupported unit semantics or required security guarantees cannot
be discarded to make a deployment appear compatible.

Activation becomes a planned transition from observed and retained state to
desired state. Providers propose typed effects; a validator checks authority,
dependencies, conflicts, and recovery rules; existing executors such as systemd
and Kubernetes perform the operations. A durable transaction record supports
crash recovery, rollout, compensation, and checked activation of older
generations. Scripts may implement individual operations, but do not hide the
transaction's ordering or failure semantics.

## Decisions proposed for acceptance

1. Keep packages as distribution and authoring units; distinguish deployed
   instances, exported interfaces, requests, bindings, and concrete handles.
2. Record dependency consumption explicitly, including mechanism, phase,
   interface compatibility, authority, and lifetime. Preserve separate build,
   configuration, activation, communication, authority, and retention graphs.
3. Permit recursive provider composition, grounded in explicitly granted
   primitive resources and a valid bootstrap path.
4. Retain the Nix language and extend AOS libraries/modules. Do not require an
   evaluator fork, language-level effect inference, or a new service DSL.
5. Preserve systemd declarations and package configuration ownership. Translate
   only an explicitly supported subset when using an alternative executor.
6. Use explicit matching for source-defined outputs and bounded resolution for
   registry inputs, with common validation and exact artifact identities.
7. Separate environment discovery, policy authorization, and resource binding.
   Availability never grants authority; missing enforcement prevents activation.
8. Keep installation, workload preparation, activation, and observation
   distinguishable even when one high-level command performs several steps.
9. Derive executable effect graphs from state transitions. The package
   dependency graph alone does not determine which operations must run.
10. Preserve independent package, configuration, and image generations, linked
    by transaction and binding records. Rollback is a newly validated
    transition, not unconditional reversal of past effects.
11. Generate explanations from the same contracts for CLI, Hub, documentation,
    editor tooling, previews, diagnostics, and generation comparisons.
12. Preserve hermetic builds, registry trust, secret handling, resource fencing,
    and the Crucible/QEMU process and licensing boundaries.

## Reading guide

- [Current model, problem, and goals](00-current-model-and-goals.md).
- [Abilities, handles, and typed dependency consumption](01-abilities-and-consumption.md).
- [Nix authoring and authenticated contracts](02-nix-authoring-and-contracts.md).
- [Static matching and registry-driven late binding](03-resolution-and-binding.md).
- [Structured activation, rollout, and rollback](05-structured-activation.md).

## Intended outcome

A user should be able to inspect an nginx deployment and trace:

```text
application configuration
  -> authorized nginx virtual-host contribution
  -> exact nginx configuration artifact
  -> validation and service reload request
  -> container-local systemd manager
  -> delegated runtime resources and credential bindings
```

The same model should explain why an ELF library is retained, why an initrd
cannot use a host-stage credential provider, why a container cannot satisfy a
kernel-management request, and why an older generation can or cannot be
reactivated. Ordinary users should receive concrete explanations rather than
having to understand the entire graph.

## Status discipline

Normative words describe requirements of the proposed implementation. They do
not claim that the baseline enforces them. Nix examples and proposed operation
names are illustrative until the corresponding versioned contracts are
implemented. Existing commands are identified separately from proposed command
extensions. This RFC records a coherent target architecture; implementation
must proceed through explicit compatibility and qualification gates.
