# APM, APR, and Hub feature coverage

This inventory is the production-qualification ownership record for the public
APM, APR, `aos hub`, native `aos-hub`, and Hub ConnectRPC surfaces. The two JSON
manifests beside this document are executable inputs: Rust tests derive the
public command and RPC method sets from Clap and protobuf definitions and fail
when a feature is added, removed, duplicated, or left without evidence.
Every command also records the SHA-256 digest of its rendered long help, so
flags, positional arguments, defaults, conflicts, value vocabularies, and
user-facing semantics cannot change without an explicit inventory update.

## Coverage classes

- `native-fleet`: exercised through the clean native Hub production fleet with
  separate Hub, publisher, and consumer VMs.
- `fleet`: exercised across multiple real AOS VMs, but not necessarily through
  the native Hub production fleet.
- `vm`: exercised behaviorally in a focused AOS VM.
- `integration`: exercised through process, HTTP, ConnectRPC, repository, or
  storage integration tests.
- `unit-contract`: behavior and invariants are exercised below the process
  boundary.
- `parser-only`: the public command is enumerated and parse/help stability is
  checked, but executing it would be destructive to the test host or requires
  facilities unavailable in a hermetic test.
- `external-provider`: the command is enumerated and its local contract is
  tested, while final execution requires an external provider account.

The classification records the strongest representative layer, not the only
test that touches a feature. `parser-only` and `external-provider` entries are
visible qualification exceptions, never equivalent to behavioral production
coverage.

## Scope rules

The command manifest contains every non-hidden leaf below `apm`, `apr`,
`aos hub`, and `aos-hub`. Hidden activation/evaluation helpers are internal
implementation seams and remain covered by their package, configuration, and
system lifecycle tests. The API manifest contains every RPC declared by the
Hub v1 protobuf contract. HTTP delivery, browser, authentication, and machine
routes that are not ConnectRPC methods are owned by the Hub integration suites
referenced throughout the API manifest.
Each RPC entry fingerprints its normalized request/response declaration, so a
type or streaming-shape change also requires an explicit coverage review.

All evidence paths must exist. A path is intentionally used instead of a test
name because several large VM and integration files cover cohesive workflows
whose individual test names change more often than their ownership boundaries.

## Non-ConnectRPC HTTP surfaces

The native and Worker implementations share these HTTP feature families. They
are enumerated by their typed route builders and capability manifests rather
than duplicated as synthetic CLI entries.

| Feature family | Behavioral owner |
| --- | --- |
| Health, metrics, security headers, and body limits | `crates/aos-hub/tests/web.rs`, `crates/aos-hub/tests/hardening.rs` |
| Password, provisioning, device, refresh, and logout flows | `crates/aos-hub/tests/password.rs`, `crates/aos-hub/tests/auth.rs` |
| OIDC and organization identity-provider flows | `crates/aos-hub/tests/oidc.rs` |
| WebAuthn enrollment, assertion, replay, and origin checks | `crates/aos-hub/tests/webauthn.rs` |
| Authenticated console routes and static assets | `crates/aos-hub/tests/console.rs` |
| Registry browse, search, release, channel, and cache delivery | `crates/aos-hub/tests/web.rs`, `crates/aos-hub/tests/e2e.rs` |
| Git smart/dumb HTTP and static-origin interoperability | `crates/aos-hub/tests/git_interop.rs`, `crates/aos-package/tests/registry_e2e.rs` |
| Publication and multipart object transfer | `crates/aos-hub/tests/operations.rs` |
| Webhook delivery and signature behavior | `crates/aos-hub/tests/webhook.rs` |
| Mirror and pull-through delivery | `crates/aos-hub/tests/mirror.rs` |

## Deployment dimensions

| Dimension | Behavioral owner |
| --- | --- |
| Clean native Hub with separate publisher and consumer VMs | `tests/fleet/native-hub-apm-smoke.nix` |
| SQLite, PostgreSQL, and MySQL semantic parity | `crates/aos-hub/tests/dialect.rs`, `pkgs/tools/aos-hub-dialect-tests.nix` |
| Cloudflare Worker request and storage contract | `pkgs/tools/aos-hub-worker-do-e2e.nix` |
| Local filesystem, HTTP, S3, and SFTP registry/cache transports | `crates/aos-cache/tests/backend_matrix.rs`, `crates/aos/tests/apr_cache_cli.rs` |
| Public, internal, and private tenant visibility | `crates/aos-hub/tests/tenancy.rs`, `crates/aos-hub/tests/tenancy_read_authz.rs` |

## Explicit qualification exceptions

Only `apm gc` is parser-only: a real host-level Nix garbage collection can
collect the headless VM rootfs dependencies, so the VM exercises its help
contract while generation pruning and cache GC are tested behaviorally through
their safer scoped interfaces. The seven `aos-hub worker` commands require a
Cloudflare account for final execution; their local request, deployment, and
storage contracts are owned by the Worker end-to-end derivation. No other
public command or RPC is exempt from behavioral ownership.
