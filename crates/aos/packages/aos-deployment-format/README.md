# AOS deployment formats

`aos-deployment-format` owns portable data contracts consumed by package
installation, activation, and release-image verification. It performs no
filesystem, process, network, terminal, or platform-specific operations.

- `model`: package envelopes, resolved artifacts, and checked transactions.
- `input`: immutable evaluation descriptors and their structural validation.
- `resolution_lock`: exact dependency choices bound to authored requirements.
- `admission`: image-authenticated store-object catalogs.
- `inventory`: installed payload records used by profiles and image capture.
- `locator`: canonical Nix store locator validation.

The JSON schemas, signing identities, defaults, and field names remain the
existing public formats. Cargo package and module ownership do not version
those formats. Acquisition and execution live in `aos-deployment`; registry
resolution and package-profile publication remain caller policy.
