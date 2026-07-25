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
| [0001](0001-package-sandboxing/README.md) | 2026-06-08 | AOS Package Sandboxing (`expose` manifests, per-unit sandboxing, preset enablement) | Proposed — phased plan in [`implementation-plan.md`](0001-package-sandboxing/implementation-plan.md) (14/19 decisions resolved; gated on the Decision 17 spike) |
| [0003](0003-install-from-image.md) | 2026-06-12 | Installation from image (UEFI + Ignition first boot, CI-enforced) | Implemented (`checks.fleet.install-from-image`) |
| [0004](0004-registry-hub/README.md) | 2026-06-12 | `aos-registry-hub` — a multi-tenant registry management WebUI | Implemented (phases 1–4 + managed caches); Phase 5 (unified async runtime + full Cloudflare parity) Proposed |
| [0005](0005-ca-trust-map.md) | 2026-06-12 | The `store/` realisation graph: content-addressed closure validation | Proposed |
| [0006](0006-secure-boot/README.md) | 2026-06-13 | Full Secure Boot integration — sign, measure, attest | Implemented (all phases CI-green) |
| [0007](0007-nix-evaluator/README.md) | 2026-06-15 | `aos-nix` - a state-of-the-art Nix evaluator in Rust | Proposed (design only) |
| [0009](0009-toolchain-ladder-stdenv.md) | 2026-06-15 | Coherent toolchain-ladder stdenv — per-tier mini-stdenv, manifest-driven packages, stock `make bootstrap` | Proposed |

Numbering is chronological by the date the design entered the tree.
