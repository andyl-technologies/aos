# Authoring recursively composed abilities

## The export includes an implementation contract

An exported ability is more than an option schema or a mapping into another
package's configuration tree. Its author declares the interface, the lower
interfaces it requires, and how authorized requests compose into requests to
those interfaces. Other packages supply the selected implementations. This
continues to trusted runtime operations; no hidden central nginx adapter should
be necessary to discover what its export means.

For example:

```text
application consumes nginx.virtual-host
  nginx provider composes its authorized virtual-host contributions
    -> managed-files.configuration provider
       -> authorized storage and publication operations
    -> systemd.service provider
       -> unit configuration through managed-files
       -> manager lifecycle operations through a scoped control connection
    -> credential-delivery provider
       -> authorized credential source and workload delivery
```

These are illustrative interface names. The actual package set may place
several interfaces in one package. A package is not required for every syscall.
The trusted systemd process implements much of its service interface itself;
its internal syscalls do not all become separately scheduled AOS graph nodes.

## Complete declaration responsibilities

| Facet | Author supplies | Trusted machinery checks |
| --- | --- | --- |
| Public interface | Versioned requests, outputs, guarantees, lifecycle | Schema and compatibility |
| Instance and aggregation | Contribution keys, merge rules, resource ownership | Authorized slots, conflicts, isolation |
| Requirements | Named lower interfaces, versions, scope relationships | Provider bindings and authority |
| Composition | Pure construction of typed child requests and result references | Expansion, typing, provenance, bounds |
| Transition | Desired/current comparison and operation subgraphs | Preconditions, ordering, effects, recovery |
| Leaf implementation | Registered handler/protocol when composition terminates | Handler identity, allowed operations, runtime scope |

The public interface and implementation are separable. Two providers may
implement one interface with different lower requirements. Provider selection
must account for the concrete implementation's requirements and guarantees.
An implementation cannot silently add a privileged requirement during execution.

## Illustrative Nix composition

An application declares a request, and deployment composition binds it to an
authorized provider instance. The application uses the provider's public
interface without inheriting its implementation handles:

```nix
abilities.imports.web = {
  interface = "nginx.virtual-host";
  abi = 1;

  request = {
    serverNames = ["app.example.com"];
    listen = [8080];
    locations."/".proxyPass = "http://127.0.0.1:9000";
  };
};

abilityBindings."my-app.web" = {
  provider = "nginx/edge.virtualHosts";
  slot = "my-app";
};
```

The request belongs to application source; the binding belongs to authorized
deployment source. The loopback example assumes a backend in the same network
context. Other topologies need an explicit endpoint binding and corresponding
rendering. Names above stand for exact instance-qualified identities, not
unrestricted global attribute paths.

The following is a proposed authoring shape, not executable against the current
AOS library. Type values and rendering functions denote package-owned schema
and pure rendering helpers. It shows the desired-state facet; credential
binding and transition operations follow below.

```nix
abilities.exports.virtualHosts = lib.abilities.define {
  interface = "nginx.virtual-host";
  abi = 1;
  requestType = virtualHostContributionType;
  resultType = virtualHostResultsType;

  aggregation = {
    scope = "provider-instance";
    key = "authorized-slot";
    conflicts = "reject";
  };

  requires = {
    configuration = {
      interface = "managed-files.configuration";
      abi = 1;
    };

    serviceManager = {
      interface = "systemd.service";
      abi = 1;
    };

    execution = {
      interface = "process.validation";
      abi = 1;
    };
  };

  compose = { requests, bindings, instance }: let
    configuration = lib.abilities.resultOf
      "configuration" "publishedConfiguration";
  in {
    requests.configuration = {
      through = bindings.configuration;
      parameters = {
        owner = instance.resourceOwner;
        files = renderVirtualHosts requests;
      };
    };

    requests.service = {
      through = bindings.serviceManager;
      parameters = {
        name = instance.serviceName;
        executable = "${nginx}/bin/nginx";
        configuration = configuration;
      };
    };

    outputs.virtualHosts = describeVirtualHosts requests;
  };
};
```

The service interface's full schema must retain required systemd semantics;
the small parameter set above is not a replacement workload schema. The
renderer must preserve store-reference provenance in artifact outputs.
`instance` and `bindings` are checked context supplied by the composition
engine, never package-authored evidence of authority.

`virtualHostContributionType` reuses native nginx field types with the
restrictions required by the caller's contribution contract. It is not an
alias granting the caller every native configuration escape hatch. For example,
syntax confinement of `extraConfig` does not prove that arbitrary contained
directives respect resource grants. Endpoint, path, and raw-directive uses need
explicit authorization or rejection at this interface boundary. `nginx` in
the example denotes the authenticated payload output allowed by the restricted
module environment.

The aggregate result above is projected back to individual callers according
to their authorized slots and the public result schema. Contributing one
virtual host does not grant access to other callers' private configuration.
An implementation may expose a separate authorized aggregate-inspection
interface when that is needed.

Deployment composition separately selects the implementation for each named
requirement. For example, nginx instance `edge` can bind `serviceManager` to
the systemd manager in container `web`, and `configuration` to that container's
configuration provider. A grant to host systemd does not follow from that
binding. Source deployments name those targets explicitly; registry
resolution supplies equivalent exact instance-qualified bindings.

The nginx author refers to interface aliases, not ambient package names or
unchecked global `config` paths. A binding may constrain an exact implementation
when its semantics are necessary. Adding `requires` does not import a module
from the network or authorize its use.

## Nix values and results have different phases

Composition returns data. It must not call a runtime provider while evaluating
Nix. Distinguish these result classes:

- Evaluation values, such as normalized server names or explicitly assigned
  ports, can participate directly in pure configuration.
- Immutable artifacts, such as rendered files, carry exact store identities
  and build/retention dependencies.
- Planned resource references identify a logical resource or future output.
  They are typed symbolic values, not live file descriptors or secret bytes.
- Runtime observations, such as health or an allocated endpoint, become
  available only after an operation and belong to execution state.

`resultOf` constructs a typed symbolic reference resolved in the current
composition scope. It MUST NOT coerce to an arbitrary string. Consumers must
accept that result type, or use an explicit authorized materialization step.
A file renderer requiring a runtime-assigned address runs after allocation,
or the deployment selects an address beforehand. Nix cannot synchronously
read a future runtime result to finish the same pure evaluation.

The engine checks result existence, type, phase, visibility, and lifetime. A
result port does not grant every operation supported by its underlying
resource. The consumer receives only the operations authorized by its binding.
Descendants cannot guess another scope's result name to obtain access.

## Aggregation is an explicit ownership boundary

The engine first validates individual contributions and then constructs the
canonical aggregate for one provider instance. The provider composes that
aggregate once for a desired revision. Independent requests cannot overwrite
the same nginx file or independently reload the shared service.

Aggregation does not erase provenance. Each virtual host remains attributed
to its consumer and grant. Global defaults, service enablement, and ownership
remain explicit. Removing a consumer recomputes the aggregate; it does not run
the inverse of that consumer's previous contribution script.

Two nginx instances use separate aggregation scopes even if their generated
bytes match. An instance's resource identity persists across configuration
revisions; content digests identify revisions, not resource owners. Stable
request identities distinguish replacement, deletion, and continued use.
Shared resources require an explicit lifetime and release contract.

## Composition includes transitions through lower abilities

Each mutable resource has one lifecycle controller. Declaring desired child
resources does not independently schedule their activation: the parent invokes
lower-provider methods, and those methods compose into suboperations. This
prevents duplicate publication/start/reload by both parent and child. Shared
provider instances use their declared aggregation/controller group as described
in the [implementation contract](implementation-contract.md#one-owner-schedules-each-transition).

The provider also owns a pure transition constructor. Given a validated old
and desired aggregate, exact bindings, and declared observation inputs, it
returns an operation subgraph. These operations invoke methods of the bound
interfaces; a provider cannot invent executable operation names in a flat
global namespace.

For nginx, the intended contract is:

| Step | Bound ability used | Result or condition |
| --- | --- | --- |
| Prepare candidate | Configuration provider | Immutable candidate and intended publication location |
| Prepare credentials | Credential-delivery provider | Scoped delivery references for validation and execution |
| Validate | Authorized execution provider | Candidate checked with intended nginx payload and credential view |
| Publish | Configuration provider | Committed configuration revision |
| Reload/start | Service-manager provider | Acknowledged operation against the exact managed instance |
| Observe | Readiness provider or service-specific probe | Defined readiness evidence for the new revision |

The manager may offer validation execution, or the provider may declare a
separate execution requirement. That choice must appear in the contract; it
cannot be an undeclared root command. A candidate-validation failure prevents
publication. A reload failure after publication records the new configuration
and a failed or uncertain service transition.

For an already-running instance whose configuration changes, an illustrative
transition constructor has this shape. It is another facet of the export
definition above; initial activation, deletion, and payload changes need their
own cases. Helper names and method schemas remain proposed API:

```nix
transition = { changes, resources, bindings, ... }:
  lib.effects.when changes.configuration (
    lib.effects.graph {
      candidate = lib.effects.invoke resources.configuration "prepare" {
        revision = changes.desiredRevision;
      };

      validate = lib.effects.invoke bindings.execution "validate" {
        executable = "${nginx}/bin/nginx";
        candidate = lib.effects.result "candidate" "configuration";
      };

      publish = lib.effects.after ["validate"] (
        lib.effects.invoke resources.configuration "publish" {
          candidate = lib.effects.result "candidate" "configuration";
        }
      );

      reload = lib.effects.after ["publish"] (
        lib.effects.invoke resources.service "reload" {}
      );

      ready = lib.effects.after ["reload"] (
        lib.effects.invoke resources.service "awaitReady" {
          revision = lib.effects.result "publish" "revision";
        }
      );
    }
  );
```

`resources` contains typed references to the resources from this instance's
child requests; it is not an ambient resource lookup. `invoke` checks the
selected interface method and allowed resource scope. `result` adds a typed
data dependency, and `after` requires successful completion rather than merely
scheduling one operation later. The operation implementations supply their
declared preconditions, retry, completion, and recovery semantics. The full
nginx implementation also supplies credential views, validation arguments,
and a readiness check that can establish the claimed revision; a manager's
reload acknowledgement alone is insufficient.

The transition constructor receives a bounded snapshot of inputs available at
planning time. A later health result is not a value Nix can read while building
that same plan. Runtime results flow through typed operation ports and declared
executor conditions; unexpected drift causes reconciliation or a new plan.
This avoids an implicit general-purpose Nix interpreter inside every operation.

The managed-files provider can itself compose staging, ownership checks, and
atomic publication through a storage provider. The systemd provider can compose
unit rendering through managed-files and manager calls through its authorized
control interface. Each provider retains its semantic commit boundary rather
than exporting an unrestricted low-level operation sequence.

Desired-state references and transition edges must agree: service activation
using a published configuration waits for that publication. They do not imply
that every future reload must republish unchanged files. Provider-specific
change classification selects reload, restart, or no operation, and is part
of the authenticated implementation.

## Expansion, fixed points, and termination

There are three different computations:

1. Provider selection resolves explicit interface constraints and chooses
   authenticated modules, outside the module fixed point.
2. Nix merges authorized contributions and purely composes concrete child
   requests. New requirements may trigger another bounded outer resolution
   pass before the complete plan is accepted.
3. The transition planner constructs a finite operation graph, which the Rust
   executor evaluates through trusted handlers at runtime.

No runtime effect occurs during the first two computations. Lazy Nix evaluation
is not a proof that recursive provider expansion terminates. Enforce depth,
node, evaluation-resource, and resolution-round limits; reject an expanding
cycle with its request trace. Cyclic runtime communication may be valid even
when recursive implementation expansion or initialization would not be.

Before executing, every required child request must reach an authorized
implementation or an explicit external deployment obligation. Obligations
must be discharged at admission. Terminal operations must be recognized by
the executor or an authenticated, authorized handler. An unknown leaf fails
validation; it is not converted into shell execution.

## Qualification of the authoring API

The shape above abbreviates the method schemas and helper signatures; the
detailed implementation and execution contracts fix their required semantics.
A vertical prototype must demonstrate schema agreement
between Nix and Rust, checked symbolic result references, multi-consumer
aggregation, conditional lower requirements, bounded expansion, provenance
through module merging, and provider-authored transition construction.

In particular, arbitrary Nix functions cannot be statically proven to implement
their declarations. Authenticated source, restricted evaluation, normalized
output validation, and runtime enforcement remain necessary. The API is ready
to stabilize only after one real nginx export composes through separately
authored configuration and systemd providers without hidden special cases.
