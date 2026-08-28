# Runtime integrity & hardware-rooted attestation

A package's signature is verified at **install** time. That proves the bytes
came from the registry; it does **not** prove the bytes *running on a node right
now* are those bytes, and it gives a fleet controller **no cryptographic
evidence** of what a node actually runs. This doc closes that gap: it extends the
content-addressed + signed supply chain down into **runtime kernel-enforced
integrity** (dm-verity over package roots) and up into **hardware-rooted remote
attestation** (TPM measurement + quote), reusing the measured-boot substrate
already shipped in [RFC-0006](../0006-secure-boot/README.md).

The headline result: **AOS binds each package's content digest *and its signed
`[permissions]` manifest* into a TPM-attestable chain.** No other OS attests
per-package *privilege*. This is a state-of-the-art-leading capability, detailed
for the implementer below.

Siblings: [README.md](README.md) · [permissions.md](permissions.md) ·
[enforcement.md](enforcement.md) · [container-model.md](container-model.md) ·
[apm-integration.md](apm-integration.md) · [implementation-plan.md](implementation-plan.md).

## The three trust artifacts (do not conflate them)

A Nix store path is a **build-time, input-addressed hash** — it fingerprints the
*inputs that produced* an artifact. It is **not** re-checked against the on-disk
bytes at runtime, is not rooted in a hardware key, and is never measured into a
TPM. Closing the gap means three *distinct* artifacts, each with its own key and
its own enforcement point:

| # | Artifact | Question it answers | Key / root of trust | Enforced at |
|---|---|---|---|---|
| 1 | **Build provenance** (in-toto/SLSA attestation) | "Was this NAR + manifest produced by the expected build from the expected source?" | registry publication key (Ed25519) + transparency log | `apr publish` / `apm install` |
| 2 | **Runtime integrity** (dm-verity root hash + signature) | "Are the bytes on disk *now* the signed bytes?" | UEFI db cert in the `.platform` kernel keyring | kernel, on every block read |
| 3 | **Runtime attestation** (TPM quote over measured digests) | "Can a node *prove to a remote verifier* exactly which packages + privileges it runs?" | TPM EK→AK (hardware-fused) | fleet verifier, on demand |

The cardinal rule, inherited from [RFC-0006](../0006-secure-boot/README.md): **the
three keys are kept apart.** The registry publication key (artifact 1) is *not*
the verity/UEFI-db key (artifact 2) is *not* the TPM AK/EK (artifact 3).
Compromising one must not collapse the others.

## Artifact 2 — runtime integrity: dm-verity package roots

[container-model.md](container-model.md) keeps the non-verity package payload
as an immutable, content-addressed store path and uses it as the authenticated
lower layer of a per-service volatile overlay `RootDirectory=`. Distinct
upper/work/merged directories under `/run` absorb systemd-created mount points;
they do not replace the payload NAR digest as the package identity. The payload
is content-addressed but **not runtime-verified**: `/nix/store` is an ordinary
writable filesystem, and Nix has no fs-verity/dm-verity over it (upstream issue
open since 2021). Under the
[budget mandate](implementation-plan.md#budget-mandate) the verity path is
**in scope, not deferred**.

**Mechanism (implementer detail).**

- Materialize each package's root (or the consolidated package-set root — see
  below) as a **dm-verity image**: a read-only ext4/EROFS filesystem plus a
  Merkle hash tree, anchored by a single **root hash**. Build it hermetically
  with the existing `mkfs.ext4 -d`/EROFS + `veritysetup format` path (no host
  tools; see [migration.md](migration.md) build constraints).
- Consume it from the unit via systemd's image directives (verified, kernel-
  current): `RootImage=<image>`, `RootHash=<hash>`, `RootVerity=<verity-device>`,
  `RootHashSignature=<pkcs7>`. The signature is a **PKCS#7** (`.roothash.p7s`)
  over the root hash, validated by the kernel against the **`.platform`
  keyring** — which AOS populates from the **UEFI db certificates** enrolled by
  [RFC-0006](../0006-secure-boot/boot-chain.md). This is the explicit
  firmware→kernel→filesystem trust bridge (`veritysetup --root-hash-signature`,
  Linux ≥5.4): the same key custody that authenticates the UKI now authenticates
  package roots.
- **Kernel config:** include `CONFIG_DM_VERITY`,
  `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`, and
  `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING` via `pkgs.linuxWith`.
- **Consolidated vs per-package root.** AOS uses **per-package signed ext4
  dm-verity `RootImage=` roots** for the MVP. Each package image carries its own
  `root.img`, `root.verity`, `root_hash`, and `.roothash.p7s`, and the package
  measurement uses that package root digest. This matches the package-profile
  lifecycle: an exposed image is downloaded, gc-rooted, rolled back, and revoked
  with the package that references it. A consolidated composefs/EROFS digest per
  package generation remains a future size/dedup optimization, not the MVP
  integrity boundary.

`RootImage=` is loop-device backed and pulls `After=systemd-udevd.service`
(not early-boot), and must not combine with `PrivateDevices=yes`. AOS reconciles
that in the rendered unit contract: verity `RootImage=` workloads require
`After=`/`Requires=systemd-udevd.service` and `PrivateDevices=false`, while the
rest of the [enforcement.md](enforcement.md) hardening baseline still applies
per unit.

## Artifact 3 — runtime attestation: measure into the TPM, then quote

[RFC-0006](../0006-secure-boot/measured-boot.md) already measures the UKI into
**PCR 11**, the kernel command line into **PCR 12**, and seals `/var` to a signed
PCR policy. Package attestation **extends that event log**, it does not invent a
new mechanism.

**Mechanism (implementer detail).**

- **Measure the package set.** At the point the package-set root is activated
  (the install-at-boot/expose phase, [boot-activation.md](boot-activation.md)),
  extend a dedicated PCR — **PCR 15** is the systemd convention for "system
  identity / per-service" measurements; reserve **PCR 15 for the AOS package
  set** — with, for each enabled package: `H(name ‖ version ‖ root-digest ‖
  manifest-digest)`. Record the same tuples in a structured **event log**
  (`/run/log/aos-packages.cel`, AOS's JSONL CEL profile with monotonic
  `sequence_number`, PCR index, SHA-256 digest list, event size, and measured
  event content) so a verifier can replay them against the quoted PCR. The
  verifier also accepts the same event payloads wrapped as binary
  `TCG_PCR_EVENT2` records with SHA-256 digests, so external CEL/TPM log tooling
  can round-trip the package measurements without changing the measured word. The
  **manifest digest is measured** — this is the novel bit: the node's *declared
  and granted privilege* is now part of the attested state, not just its code.
- **Quote.** A node produces a TPM `TPM2_Quote` over {PCR 7, 11, 12, 15} with a
  verifier-supplied **nonce**, signed by an **Attestation Key (AK)** whose
  credential is bound to the **Endorsement Key (EK)** fused at manufacture. This
  is the standard Keylime/TPM2 quote; AOS ships the agent side as a small
  `aos-attest` unit using AOS-built `tpm2-tools`.
- **Verify.** A verifier replays the event log against the quoted PCR digests,
  checks the nonce and quote signature, matches the AK/EK identity against the
  verifier's trust catalog, and then checks **each measured tuple against the
  registry's golden catalog** (next section). Result: cryptographic proof that
  node X runs exactly package-set P, at versions V, with root digests D, under
  privilege manifests M — all chaining to hardware once the AK/EK identity has
  been enrolled. Reference verifier: Keylime-shaped (`TPM2_Quote` + IMA/CEL
  replay). AOS hosts this as the standalone
  `aos.services.attestationVerifier` role: it consumes delivered
  quote/event-log/catalog evidence and writes a verifier result, while the
  registry remains only the catalog/provenance plane (see custody below).
- **Enroll.** `apm attest enroll` populates the verifier trust catalog from a
  quote bundle after an operator has completed TPM credential activation, a
  privacy-CA certification, or an equivalent out-of-band TPM enrollment proof.
  The catalog stores the AK/EK public/name/qualified-name fingerprints plus the
  SHA-256 digest of that enrollment evidence. `apm attest verify` reports
  `ak_ek_trusted=true` only when the quote identity matches an enrolled anchor;
  a bare identity pin remains useful for continuity checks but reports
  `ak_ek_trusted=false`.

## How the AOS registry fits in

This is the load-bearing design question, and the answer is the **same pattern
the registry already plays for Secure Boot** ([RFC-0006](../0006-secure-boot/registry-catalog.md):
"the registry records and validates SB signing facts but is **never a signer** of
them"). The registry is the **catalog / policy / provenance plane — never a
runtime root of trust.** Concretely, across the three artifacts:

1. **Provenance host + publication anchor (artifact 1).** At `apr publish` the
   registry: binds `name → version → nar-hash → manifest-hash → root-digest`;
   **tag-signs** that binding (its existing Ed25519 tag-signature chain,
   name-binding + anti-rollback floor); **hosts** the in-toto/SLSA provenance
   attestation that ties the NAR + manifest to the build inputs (the `.drv` /
   source); and **appends the binding to the in-registry transparency hash
   chain** so clients following the same registry history can audit append
   consistency. Independent witness / Trustix / Rekor-style non-equivocation is
   future work. It is the layer that decides *what may be distributed*
   (publication policy) and *signs the catalog entry* — but it cannot know any
   host's local policy (the three-layer rule of [permissions.md](permissions.md)
   is unchanged).

2. **Source of the signed root hash (artifact 2).** The dm-verity
   `.roothash.p7s` for each package/generation root is a **registry-served
   artifact** (a new narinfo-adjacent field — see
   [apm-integration.md](apm-integration.md)). The registry *distributes* it; the
   **kernel enforces** it against the `.platform` keyring. The registry holds no
   verity key and performs no runtime check.

3. **Golden-measurements catalog + reference oracle (artifact 3).** This is the
   new role, and it is exactly the RFC-0006 SB-catalog role generalized. The
   registry records, per package/version, the **expected measurement tuple**
   `H(name ‖ version ‖ root-digest ‖ manifest-digest)` — the same value a node
   extends into PCR 15. The standalone fleet verifier answers: "node X quoted
   PCR 15 = D and presented event log E; is every tuple in E a registry-known
   package at a non-rolled-back version with a registry-known, policy-permitted
   manifest?" The registry is the **oracle of expected/golden values**, just as
   it records `expected_pcr11` for UKIs today. It never holds a TPM, never signs
   a quote, never is the hardware root of trust.

**Custody / separation of duties (mandatory).** The registry **publication key**
(catalog + provenance, artifact 1) is distinct from the **UEFI-db/verity key**
(runtime integrity, artifact 2, custody per [RFC-0006 key-custody](../0006-secure-boot/key-custody.md))
and from the **TPM AK/EK** (attestation, artifact 3, per-device, hardware-fused).
The registry is deliberately **not** a runtime root of trust: a registry
compromise lets an attacker publish a *new* signed package, but that package is
still constrained by policy + provenance checks, recorded in the same-history
transparency hash chain, and bounded by anti-rollback; the attacker **cannot
forge a TPM quote** or alter a node's measured state. This is the same
blast-radius containment RFC-0006 designed for SB, extended to packages.

```text
SOURCE ──hermetic build──► .drv ──► NAR (content-addressed)            [reproducible]
                                      │
                          apr publish │  registry: bind + tag-sign (name→ver→nar→manifest→root-digest),
                                      │            host in-toto/SLSA provenance, append to registry hash chain,
                                      ▼            record golden measurement tuple
                              REGISTRY CATALOG  ──serves──►  signed root hash (.roothash.p7s), provenance, golden values
                                      │
                           apm install│  verify tag-sig + nar-hash + provenance + manifest∩host-policy
                                      ▼
                          PACKAGE ROOT (dm-verity image)
                                      │  kernel enforces RootHashSignature against .platform keyring (UEFI db, RFC-0006)
                                      ▼
                       systemd measures H(name‖ver‖root-digest‖manifest-digest) ──► TPM PCR 15  (+ event log)
                                      │
                          TPM2_Quote  │  AK←EK (hardware), nonce
                                      ▼
                              FLEET VERIFIER  ──replay event log vs quoted PCRs, check each tuple vs REGISTRY golden catalog──►  PASS/FAIL
```

## Provenance & transparency (artifact 1, the supply-chain layer)

Promote the existing "audit against TUF, consider attestation" note in
[apm-integration.md](apm-integration.md) from *consider* to *build*:

- **in-toto / SLSA provenance.** Emit a DSSE-wrapped SLSA provenance
  attestation (current spec **v1.2**, with the Source Track) per package build,
  binding the NAR hash **and the `[permissions]` manifest hash** to the build
  inputs; serve it from the registry alongside the narinfo. The DSSE signature
  is made by an active `keys.toml` roster key and `apm install` verifies both
  the envelope signature and the builder id before accepting the statement.
  Packages that declare RFC-0001 expose, permission, or BPF-LSM policy
  metadata are fail-closed: their package metadata must declare provenance.
  Planned key retirement preserves the retired public key only for transparency
  entries below the recorded retirement sequence, so old entries remain
  verifiable without allowing new retired-key entries.
- **Transparency log.** Append every published binding to the in-registry
  `transparency/package-provenance.jsonl` hash chain. Publish validates that
  the staged log extends the committed prefix, that every provenance-bearing
  package has exactly one log entry, and that the logged artifact hash matches
  the DSSE envelope bytes that install will verify. This catches rewrites and
  unlogged changes for clients following the same registry history; independent
  witness or Rekor-style compromise resistance is future work.
- **TUF hardening.** Build the catalog against the TUF attack catalog (freeze,
  mix-and-match, fast-forward, key rotation) with committed `tuf/root.json`,
  `targets.json`, `snapshot.json`, and `timestamp.json` roles, role thresholds,
  expiry checks, and version floors. The anti-rollback semver floor AOS already
  enforces is the TUF "rollback" defense; the TUF metadata adds the remaining
  role separation and freshness checks.
- Caveat to record (not a blocker): cosign's OCI-1.1 *referrers* is selectable,
  not yet a hard default, and GHCR does not implement the referrers endpoint —
  relevant only if AOS ever mirrors attestations into an OCI registry.

## What this is not

- **Not a second package format.** Verity images wrap the *same* store-path
  closure; the manifest, the target sandbox, and the per-unit substrate are
  unchanged. Attestation is an integrity + evidence layer over them.
- **Not dependent on nspawn.** It is substrate-independent (the per-unit default
  of [container-model.md](container-model.md) carries `RootImage=`/verity
  natively).
- **Not the registry becoming a runtime authority.** The registry stays a
  catalog/policy/provenance plane; the hardware (UEFI db, TPM) is the runtime
  root of trust.
