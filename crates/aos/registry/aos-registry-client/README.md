# aos-registry-client

Native acquisition and verified reading of AOS package registries. The client
loads layered consumer configuration, refreshes registry clones and their
anti-rollback state, verifies signatures and provenance, and reads package,
channel, realization, and signed catalog records.

Portable schemas and validation belong to `aos-registry-format`. This crate
adds filesystem, Git, HTTP, trust-store, and native configuration access. It
does not depend on the package manager, deployment runtime, or registry
publication machinery or terminal presentation. Low-level transfers accept
`aos_transfer::progress::TransferObserver`; SDK callers can pass `NoopObserver`,
and CLI callers can pass their `Printer` through its presentation adapter.

- `config` and `types` discover native profiles and layered configuration.
- `registry` reads verified registry contents and transports them locally.
- `registry::mirrors` combines committed cache destinations with consumer
  overrides, preserving their priority ordering.
- `sync` defines neutral metadata refresh results and domain errors.
  `aos-package-manager::update` owns command selection, state persistence,
  aggregate diagnostics, JSON output, and command hints.
- `cleanup` removes writable registry overlays whose seed definitions vanished.
- `security` and `provenance` verify trust and package evidence.

`test-support` exposes shared registry fixtures for dependent crates' test
suites, including fixture-only key generation and signing. Production private-key
operations belong to `aos-registry-authoring`. Production consumers do not need
that feature.
