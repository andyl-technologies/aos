# RFC-0006 — Registry as the validation catalog

Phase 4. The fleet concern: give the registry a record of the Secure Boot
signing facts for every published component, so `apm` can validate a download
against them **before** the machine reboots into a UKI the firmware would then
reject — turning a boot-time brick into a download-time refusal — and so the
fleet has one place to revoke.

The hard rule, restated because it governs the whole design: **the registry
records facts about SB-signed artifacts; it never produces SB signatures.**
See [`key-custody.md`](key-custody.md) for why mixing the two collapses the
threat model.

## What this is (and isn't)

This is the [TUF](https://theupdateframework.io/) / sigstore-attestation
pattern: the registry is a signed **catalog of attestations** — "I recorded
that this UKI carries an Authenticode signature by cert X, SBAT generation N,
and will measure to PCR-11 = Y." It is **not**:

- a signer of boot material (the offline db key does that),
- a replacement for firmware verification (a lying registry is caught at boot
  by the enrolled db — defense in depth holds; the catalog is an *independent
  second check* plus a policy/early-detection layer),
- a new trust root (it reuses the existing signed-git-tag trust,
  `docs/registry/signing-and-trust.md`).

The catalog facts are covered by the registry's existing signature: per-package
metadata is TOML in the git tree, and the signed release tag covers the tree
state ([`current-state.md`](current-state.md) registry section). Adding fields
to that TOML makes them tamper-evident as registry data for free.

## Schema extension

`crates/aos-package/src/types.rs`. The natural home is `SysrootImageEntry`
(`:1267` — where a UKI/image already lives) for per-image facts, with a small
addition on `PackageMeta` (`:447`) for the signer identity. New optional
fields (optional so unsigned/legacy publishes still parse):

On `SysrootImageEntry` (per UKI/image):

```rust
/// Lowercase hex SHA-256 of the signer leaf cert in the PE's
/// Authenticode certificate table; the db cert this image must chain to.
pub sb_signer_cert_sha256: Option<String>,
/// SBAT component:generation pairs read from the PE `.sbat` section,
/// e.g. [("aos", 1), ("systemd", 1)]. Drives the revocation floor.
pub sbat: Vec<SbatEntry>,
/// ukify-predicted TPM PCR-11 value for this UKI (hex), for attestation
/// and for apm to surface what a machine *should* measure post-upgrade.
pub expected_pcr11: Option<String>,
```

On `PackageMeta` / registry root: a reference to the **active db cert set**
and the **SBAT revocation floor** (minimum acceptable generation per
component), modeled like the existing signing-key roster — `KeysToml` with
`active: Vec<RosterKey>` / `revoked: Vec<RevokedKey>`
(`crates/aos-package/src/registry/keys.rs:58-67`, the `[[keys]]` / `[[revoked]]`
file format) — so db-cert rotation reuses roster machinery that already
exists. (Not to be confused with `SigningConfig` at `types.rs:765`, which is
only the bootstrap anchor — `required` + `public_key` — or `signing_keys` at
`:679`, which holds the publisher's *local private-key references*.)

## `apr publish` — derive facts from the artifact

`crates/aos-package/src/registry_ops.rs` (the `--sysroot` path that already
records `[[images]]`). For each signed image, **extract the facts from the
real binary** rather than trusting hand-entry:

- signer cert → parse the PE certificate table (`sbverify --list`, sbsigntools
  already packaged) and hash the leaf.
- SBAT → read the `.sbat` PE section (objcopy/llvm-objcopy dump).
- expected PCR-11 → dump the assembled UKI's measured PE sections and feed
  them to `systemd-measure` (now in the build,
  [`measured-boot.md`](measured-boot.md)). The catalog records the final
  `enter-initrd:leave-initrd:sysinit:ready` prediction. RFC-0011 orders
  activation after `systemd-pcrphase.service`, so this value is byte-identical
  to PCR 11 in the generation quote; the measured-boot VM checks that equality.
  `/var` unlock instead consumes the signed multi-phase `.pcrsig` policy at
  `enter-initrd` and does not compare this scalar.

So the catalog is *derived from* the signed artifact at publish time; it
cannot disagree with what was actually signed without detection. A
publish-time check refuses to record an image whose embedded signature
doesn't verify against the declared db cert — the registry won't catalog a
component it can't itself verify is signed.

## `apm` — validate at download time

`crates/aos-package/src/sysroot.rs` `install_system` already walks: signed
tag → narinfo → download hash → NAR hash → store path
([`current-state.md`](current-state.md)). Add an SB-validation step **after**
the closure is verified, **before** activation/reboot:

1. signer cert is in the registry's **active** db-cert set (not retired),
2. every SBAT component generation ≥ the registry **revocation floor**,
3. (defense in depth) re-run `sbverify` of the downloaded UKI against the
   catalog's db cert.

On mismatch, refuse the upgrade with a clear message — *before* the machine
reboots into a UKI its firmware would reject. This is the headline benefit:
**SB failure moves from boot time (brick / fallback) to download time (clean,
recoverable refusal).**

## Centralized revocation

Two complementary layers:

- **Boot-time (firmware):** `dbx` + SBAT in the firmware/loader reject revoked
  binaries when they execute. Authoritative, but failure is discovered late
  (at boot).
- **Download-time (registry):** raising the registry's SBAT revocation floor
  (a signed metadata change pulled on `apm update`) makes `apm` refuse to
  install/upgrade to a below-floor component fleet-wide, *before* reboot. One
  place to revoke, enforced early.

The registry distributes the floor; it does not write firmware variables. A
privileged local agent applies any actual `dbx`/SBAT firmware update, which
must be KEK-signed ([`key-custody.md`](key-custody.md)) — again, the registry
transports an offline-signed payload, it doesn't authorize it.

## Trust-bootstrap symmetry

The SB **db cert (public)** can be delivered at install the same way the
registry trust anchor already is: `modules/base/apm-registries.nix` bakes
`/etc/apm/trusted-keys.d/<name>.pub` and the `[registry.signing] public_key`
anchor. A parallel `trusted-sb-certs.d/` (baked or via the metadata channel)
gives `apm` the db cert to validate catalog entries against. Distinct key,
same delivery mechanism, provisioned at install — mirroring the registry PKI
rather than inventing a new path.

## Boundary diagram

```text
release (offline)        registry (online catalog)      machine (apm)            firmware (boot)
─────────────────        ─────────────────────────      ─────────────         ──────────────
db key signs UKI    →    apr publish extracts &      →   apm verifies tag,  →  enrolled db verifies
PCR key signs .pcrsig    records signer/SBAT/PCR-11       closure, THEN          embedded sig;
                         into signed metadata             SB-validates vs        TPM unseals /var
                         (git-tag trust)                  catalog before reboot  iff PCR policy ok
                              │                                  │                      │
                              └─ records facts, never ───────────┴── catches bad ───────┘
                                 re-signs for boot                  upgrades early;
                                                                    firmware is the
                                                                    hard root
```
