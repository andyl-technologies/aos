# aos-registry-client

Native acquisition and verified reading of AOS package registries. The client
loads layered consumer configuration, refreshes registry clones and their
anti-rollback state, verifies signatures and provenance, and reads package,
channel, realization, and signed catalog records.

Portable schemas and validation belong to `aos-registry-format`. This crate
adds filesystem, Git, HTTP, trust-store, and native configuration access. It
does not depend on the package manager, deployment runtime, or registry
publication machinery.

- `config` and `types` discover native profiles and layered configuration.
- `registry` reads verified registry contents and transports them locally.
- `registry::mirrors` combines committed cache destinations with consumer
  overrides, preserving their priority ordering.
- `sync` refreshes configured registries and persists their verified state.
- `cleanup` removes writable registry overlays whose seed definitions vanished.
- `security`, `sshkey`, and `provenance` verify trust and package evidence.

`test-support` exposes shared registry fixtures for dependent crates' test
suites. Production consumers do not need that feature.
