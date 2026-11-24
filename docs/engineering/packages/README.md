# Packages

These pages describe how AOS confines, attests, and documents the packages a
host runs. The model they build on, in which a package ships a module whose
operations are executed as checked effects, is described in
[runtime abilities](../abilities/README.md). Updating package versions in
this repository is covered by
[package maintenance](../package-maintenance/README.md).

| Page | Covers |
| --- | --- |
| [Package service sandbox](service-sandbox.md) | How a typed `serviceManagement` declaration becomes a systemd unit's confinement, resource groups, and preset-based enablement |
| [Package and generation attestation](attestation.md) | The PCR 15 event log, package measurement tuple, generation evidence, and `apm attest` |
| [Package documentation](package-documentation.md) | Generation of package reference documents, their signed publication, Hub indexing, and the shared readers |

Operator-facing behavior is in the user guides:
[packages](../../users/aos/packages.md),
[package runtime policy](../../users/aos/package-runtime-policy.md), and
[package authoring](../../users/aos/package-authoring.md).
