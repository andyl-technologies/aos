# aos-registry-authoring

Native creation, mutation, signing, staging, and publication of AOS package
registries. The APR command vocabulary and dispatcher live here; the umbrella
CLI applies its runtime admission policy before calling the dispatcher.

The authoring library reads existing registries through `aos-registry-client`
and shares wire contracts through `aos-registry-format`. It does not depend on
the package manager. Deployment artifact readers provide verified inputs for
publication without importing package installation or host-switch policy.

- `registry_ops` implements authoring workflows, signing, channels, release
  transactions, and publication commands.
- `registry::release` coordinates release materialization and evidence checks.
- `registry::staging` owns immutable local publication candidates.
- `registry::tuf` signs catalog metadata using portable TUF envelope contracts.
- `registry::pack` and the internal thin-pack encoder generate publication packs.
- `registry::transport` writes immutable objects and pointers; read transport
  remains in the client library.
- `registry::nixcache`, `static_upload`, `hub_publication`, and `webgen` prepare
  and distribute cache, static-origin, Hub, and registry website outputs.

Producer integration fixtures live in this crate's `tests/` directory. Reader
unit tests remain with the client, and package-download integration tests remain
with the package manager.
