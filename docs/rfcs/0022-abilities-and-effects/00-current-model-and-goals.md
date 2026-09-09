# Current model, problem, and goals

## The initial problem

Installing a package does not establish that its runtime integration can work
in the selected environment. A web server's libraries may be present while
its configuration, credentials, writable directories, service manager, or
required isolation facilities are absent. A package name and a successful
store import cannot express those distinctions.

The official AOS OCI image currently initializes a daemonless local Nix store
database and user-profile state, then executes the requested command. It sets
`AOS_RUNTIME=container`, runs as root by default, and exposes the root user's
profile executables on `PATH`. Root identity does not change the APM scope.

The [runtime boundary](../../../crates/aos-package/src/runtime_boundary.rs)
rejects system-scope and host activation operations. The
[exposed-unit reconciler](../../../crates/aos-package/src/exposed_units.rs)
does nothing for non-system profiles. User installation can retain and validate
service artifacts without starting their services. Read-only environments
reject package mutations. This is intentional current behavior, not evidence
that every installed payload will execute successfully.

The problem extends beyond containers. Build dependencies, runtime libraries,
configuration contributions, unit dependencies, firewall requests, boot-stage
resources, and documentation ownership are described by different mechanisms.
Their relationships are often recoverable only by reading implementation code.

## Existing mechanisms to preserve

| Mechanism | Baseline responsibility | Extension point |
| --- | --- | --- |
| `buildDeps`, `runtimeDeps`, `propagatedDeps` | Construct build environments and retain dependency outputs | Typed consumption mechanisms and platform/phase information |
| `pkg.expose` | Companion artifact with units, permissions, and configuration metadata | Authenticated execution interfaces and effect mappings |
| `pkg.config` / `configModule` | Restricted package-owned Nix modules and interface metadata | Provider declarations, requests, scoped configuration contributions |
| `ownsRoots`, `contributes`, interface ABI | Shared-root ownership and authorized foreign writes | Exact provider/request/binding provenance |
| `providesCapabilities` / `SystemRoots` | Locally derived capability-provider metadata | Discovery input, without treating a declaration as a live grant |
| Systemd unit renderers | Typed unit generation and AOS sandbox integration | Provider-specific compilation from validated requests |
| Configuration evaluator | Bounded resolve/evaluate loop producing a manifest | Late provider binding and explicit deployment obligations |
| Graph compiler | Systemd fetch/render graph and degraded projection | Typed transition operations and dependency strength |
| Activation and profiles | Retained generations, configuration commit, recovery records | Bound-plan identity, operation journal, consumer state |
| OCI builders | Explicit userland closure and filesystem/runtime metadata | Selected environment providers and runtime requirements |
| Canonical documentation | Signed exact package documents and release-scoped indexes | Interface, consumption, plan, and outcome explanations |

Code anchors include [package construction](../../../pkgs/default.nix),
[configuration metadata](../../../pkgs/build-support/_config-module-renderer.nix),
[ownership resolution](../../../crates/aos-package/src/config_eval/system_roots.rs),
[module namespacing](../../../lib/namespacing.nix), and
[configuration graph compilation](../../../crates/aos-package/src/graph_compile/mod.rs).

The package topology is already flexible. nginx attaches its integration to
its payload. `k3s-worker` and related role packages consume a shared k3s payload.
Cilium contributes to the k3s configuration interface without being a
standalone APM-activated daemon. These shapes MUST remain supported; the new
model does not require a separate class of service packages.

## nginx as a concrete starting point

The [nginx package](../../../pkgs/networking/nginx.nix) declares a foreground
command, preparation and reload helpers, dynamic identity, runtime/state/log
directories, TLS credential declarations, and network/capability permissions.
Its [configuration module](../../../pkgs/networking/_nginx-config/module.nix)
owns `nginx.*`, validates virtual hosts, produces `nginx.conf`, and projects
configuration and credential bindings.

Several portable requirements are currently expressed through systemd fields.
The configuration also names systemd credential paths. These are concrete
integration points to adapt. They do not require replacing nginx's typed
configuration interface or inventing an alternative generic service language.

The package currently requests host networking and a low-port capability.
An implementation MUST NOT silently reinterpret that signed request as an
ordinary isolated network. More precise endpoint-oriented declarations require
an explicit metadata/interface migration.

## Goals

1. Explain how each dependency is consumed, including its binding phase and
   authority consequences.
2. Allow any package to provide and consume interfaces, with recursive
   composition and explicit bootstrap requirements.
3. Keep Nix as the authoring language and preserve package-owned configuration,
   systemd vocabulary, hermetic construction, and exact registry provenance.
4. Support both source-selected bindings and registry-driven late binding
   without diverging compatibility or authorization rules.
5. Distinguish a prepared artifact from a running, healthy, authorized workload.
6. Replace implicit orchestration with inspectable transition plans and durable
   recovery semantics, including rollout and rollback.
7. Make the contract useful across boot, services, policy, containers, images,
   libraries, documentation, and operator workflows.

## Non-goals

- Automatically translate arbitrary systemd units into arbitrary container
  runtimes, or run all AOS host operations inside every container.
- Replace systemd supervision, Kubernetes reconciliation, Nix realization, or
  the sandbox runtime's resource brokers with a competing controller.
- Infer complete effects from arbitrary Nix, shell, ELF, or application code.
- Make an in-process shared library an isolated security principal.
- Introduce deployment-time replacement of already-linked libraries as part
  of the first implementation.
- Promise atomicity across distributed systems or automatic reversal of
  application state changes.
- Convert every scalar option into an ability. Values such as a worker count
  remain typed configuration; crossing ownership, resource, or lifecycle
  boundaries introduces a consumption edge.

## Integration rather than replacement

The sandbox proposal in PR #232 already defines logical resource identities,
policy ceilings, brokers, leases, fencing, filesystem views, and typed effects.
This RFC supplies package/configuration declarations and composition above
those boundaries. Where a sandbox provider implements a requested ability, the
binding MUST use that provider's protocol and identities, not a second path to
the same privileged resources.

The baseline has real graph and transaction machinery; activation is not
entirely an unstructured script today. The proposed change makes individual
effects and their contracts explicit within that machinery. It preserves the
existing commit and recovery guarantees until a qualified replacement is
available.
