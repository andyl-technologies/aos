# Sandbox service assembly

This package owns the installed executable entry points. No role is selected by
its default feature set, and every binary has an explicit `required-features`
role. It constructs no signing key or verified grant on behalf of a domain.
Service names, process identities, credential paths, sockets, and systemd
confinement stay unchanged.

| Owner | Current responsibility |
| --- | --- |
| `aos-sandbox-services::controller` | Socket custody, root-only diagnostic acceptance, bounded registered TLS acceptance, HTTP registration and serving |
| `aos-sandbox-services::host` | Fixed-role session scheduling, fairness, guest-launch retention and sealed request-cycle composition |
| Role-selected binaries | Arguments, installed daemon composition and the existing selected startup recipes |
| `aos-sandbox-controller-runtime::controller_service` | Opaque authenticated API handlers, sole worker command channel, reconciliation, retained startup parent and readiness/terminal ordering |
| Session security and domain owners | Protected credentials, authentication, verified handoffs, replay/currentness and semantic/physical checks |

The Controller assembly contract accepts opaque handlers and a negative-only
terminal loan. Handler construction, public peer/capability validation, journal
access, readiness, and authority constructors stay private to their existing
owners. Associated listener/partial-startup fields stay in the same retained
runtime parent; assembly failures use that parent's terminal before releasing
partial originals.

The Host scheduler keeps its activation owner, three private authenticated
session slots, guest channel and fairness cursor in their original drop order.
Session security retains the opaque fixed-listener adapter, authenticated
handshake and Storage peer checks around each selected request cycle. Readiness
is descriptor observation only; it grants no authority. The scheduler composes
existing sealed receive/completion methods without exposing signing or raw
transport. Its VM broker fixture follows the scheduler into a separate explicit
`host,kernel-tests` executable; the Controller inventory client follows its complete Runtime owner.

The public port is a trusted application contract: arbitrary implementations
are not proof of authenticated transport or retained custody. The installed
binary selects the private fixed assembly; the opaque handler still performs
its existing public identity and admission checks.

The complete Controller integration now belongs to its Runtime crate above
Session Security; lower authentication and history have no dependency back to
Runtime. Closed sealed composition ports preserve the original custody and
fixed signing recipes. This is not the completed RFC-0021 security split:
Session Security still selects concrete domain implementations transitively,
and role features do not claim that its dependency closure is isolated.

Packaging builds and compiles package tests in separate role invocations,
including dependency artifacts. The Controller output package co-installs its
existing helper services, but does not unify their service role features in one
Cargo invocation. Online Nix owner selection is separate from the Controller's
online integration feature. The VM's registered TLS tests follow the listener
into this package and still use actual protected credentials and HTTP/2; their
test-only Discovery fixture issues no authority or readiness.

Before further extraction, inspect the selected Cargo graph with normal/build
edges and again with dev edges for each role. A workspace/all-features graph is
a development check and does not establish role isolation.
