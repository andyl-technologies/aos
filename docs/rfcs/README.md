# RFCs — design records

Every substantial design lives here as a dated, numbered record. An RFC
explains *why* the system is shaped the way it is and tracks the
proposal's implementation status; the canonical docs elsewhere in
`docs/` describe *how it works today*. When the two disagree, the
canonical docs win — an RFC is history, and its code links reflect the
tree at the time of writing.

A design may start as a working doc (e.g. under [`docs/plans/`](../plans/))
and graduates here with the next number, a date, and a status header.
Once a design ships, the RFC body is not edited to track the system —
only its status header is maintained (Proposed → Accepted → Implemented,
or Superseded / Rejected, with partial/deferred notes as needed).

Single-file RFCs are `NNNN-slug.md`; larger designs are directories
`NNNN-slug/` whose `README.md` carries the status header and indexes the
topic files.

| RFC | Date | Title | Status |
| --- | --- | --- | --- |
| [0001](0001-package-sandboxing/README.md) | 2026-06-08 | AOS Package Sandboxing (`expose` manifests, per-unit sandboxing, preset enablement) | Implemented for exposed APM service packages; stronger microVM isolation remains deferred |
| [0003](0003-install-from-image.md) | 2026-06-12 | Installation from image (UEFI + Ignition first boot, CI-enforced) | Implemented (`checks.fleet.install-from-image`) |
| [0004](0004-registry-hub/README.md) | 2026-06-12 | `aos-registry-hub` — a multi-tenant registry management WebUI | Implemented through managed caches and the unified native/Worker runtime; topology rewrite proposed in RFC-0012 |
| [0005](0005-ca-trust-map.md) | 2026-06-12 | The `store/` realisation graph: content-addressed closure validation | Proposed |
| [0006](0006-secure-boot/README.md) | 2026-06-13 | Full Secure Boot integration — sign, measure, attest | Implemented (all phases CI-green) |
| [0009](0009-toolchain-ladder-stdenv.md) | 2026-06-15 | Coherent toolchain-ladder stdenv — per-tier mini-stdenv, manifest-driven packages, stock `make bootstrap` | Proposed |
| [0010](0010-crucible/README.md) | 2026-06-18 | Crucible — a hermetically deterministic multi-VM simulation harness | Proposed (design-only) |
| [0011](0011-on-host-config-eval/README.md) | 2026-06-25 | On-host, eval-only configuration — generations from downloaded Nix modules | Accepted; phased implementation plan and locked decisions |
| [0012](0012-hub-surface-topology/README.md) | 2026-08-03 | AOS Hub surface topology — multiple placements, simultaneous routes, and principled registry/cache relationships | Proposed; signed system-image distribution implemented and native/Worker E2E-tested |
| [0013](0013-recovery-uki/README.md) | 2026-08-17 | A/B-aware signed recovery UKIs and initrd fail-closed hardening | Proposed — phased plan in [`implementation.md`](0013-recovery-uki/implementation.md) |
| [0014](0014-signal-driven-fault-model/README.md) | 2026-08-18 | Signal-driven, cross-domain fault modeling for Crucible | Proposed; implementation in progress |
| [0015](0015-hermetic-cargo-artifacts.md) | 2026-08-21 | Hermetic Cargo artifact graphs and parallel Rust testing | Implemented |
| [0016](0016-package-documentation/README.md) | 2026-08-28 | Package documentation as authenticated Nix objects | Implemented and staged in PR #219 |

Numbering is chronological by the date the design entered the tree.
