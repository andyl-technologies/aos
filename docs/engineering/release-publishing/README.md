# Canonical release publishing

AOS publishes its canonical package and system catalog through a release
pipeline that is separate from ordinary registry publishing. A release is
planned, built hermetically, finalized and signed by role-separated external
authorities, published to a staging surface, qualified against the exact
staged bytes, published unchanged to a production surface, and rolled out
through signed channel partitions. This directory describes the model and the
code that enforces it. Operator procedures are in
[Canonical release coordinator](../../maintainers/canonical-releases.md), and
the registry protocol the pipeline writes is described in
[`../registry/`](../registry/README.md).

## Pages

| Page | What it covers |
|---|---|
| [release-model.md](release-model.md) | Registries and tiers, channel kinds, release classes and versions, surfaces and destinations, qualification profiles, rollout rings, fitness attestations, overrides, and the platform matrix. |
| [security-and-keys.md](security-and-keys.md) | Threat model, signer roles, TUF roles, the external signing protocol, and why the Hub is not a root of trust. |

## Flow

```text
protected source commit
        |
        v
plan (frozen destinations, gates, soak, rings) -> hermetic build on the maintainer host
        |
        v
finalize: external role-separated signing over a closed manifest -> signed bundle
        |
        v
staging surface -> exact-byte qualification under the destination profile
        |
        v
publish the same immutable objects to production, without rebuild or re-sign
        |
        v
production surface -> advance signed channel rings -> consumers
```

## Invariants

1. **One artifact, one identity.** Production receives the exact immutable
   bytes and digests that passed staging. Promotion never rebuilds, reconverts,
   or re-signs them.
2. **Build before signing.** Hermetic build steps cannot read private release
   keys. Signing is a separate finalization stage over a closed manifest.
3. **No key collapse.** Registry, TUF, Nix cache, Secure Boot, module, PCR
   policy, provenance, evidence, qualification, channel, and surface-receipt
   signatures come from separate roles; see
   [security-and-keys.md](security-and-keys.md).
4. **The Hub is not a root of trust.** A compromised Hub deployment or its
   storage cannot mint a release, a bootable UKI, a trusted NAR, or provenance.
5. **Immutable before mutable.** NARs, images, source objects, git objects, and
   release metadata are uploaded and read back before any channel pointer
   moves.
6. **Promotion is monotonic.** Release versions, TUF metadata versions,
   published git history, and consumer channel floors never decrease. A failed
   rollout is fixed forward with a higher version.
7. **Fail closed.** A missing check, signature, source artifact, authorization
   record, recovery artifact, fitness attestation, or public read-back blocks
   the transition.
8. **One publisher.** The designated maintainer host holds the sole authoring
   clone. Every mutating operation is serialized and recoverable from the
   hash-chained journal.

## Release journal

Every transition appends an entry to a hash-chained, per-release journal
(`crates/release/aos-release-format/src/state.rs`). One global lifecycle covers
the build; each planned destination then has its own lifecycle:

```text
global:          planned -> built -> finalized
destination d:   finalized -> published(d) -> rolling(d) -> ... -> complete(d)
failure:         any non-failed global state -> failed (terminal for the release)
```

Destinations interleave freely once the bundle is finalized, but a production
destination may be published only after a staging destination holds a
publication. Entries bind the plan and manifest digests and the previous entry
digest:

```json
{"schema_version":"aos.release.journal-entry/v1","sequence":5,
 "previous_entry_digest":"sha256:...","plan_digest":"sha256:...",
 "manifest_digest":"sha256:...","prior_state":"finalized",
 "new_state":"published","destination":"staging/edge",
 "operation_ids":["publish-1"],"evidence":[],"recorded_at":"..."}
```

`verify::verify_journal` recomputes each destination's state from the entries,
so a captured journal can be checked offline.

## Code map

| Component | Location | Role |
|---|---|---|
| Release contracts | `crates/release/aos-release-format` | Pure, I/O-free schemas and verification: canonical JSON and typed digests, the platform matrix, plans and destinations, manifests, evidence, qualification contract and admission, fitness, profile overrides, signing requests, journal, receipts, and TUF metadata. Shared by the producer, the Hub, native clients, Workers, and offline verifiers. |
| Coordinator | `crates/release/aos-release-coordinator` | Effectful coordination: bounded capture of untrusted inputs, publication layouts, anonymous read-back, durable journal output, operator configuration and credentials, and the external signing process protocol. |
| CLI | `aos maintain release` (`crates/cli/aos-cli/src/commands/release/`) | Porcelain and step commands that drive the coordinator. |
| Signer adapter | `crates/release/aos-release-signer` | File-backed `sign-exchange-v1` executable for deployments whose keys live in operator-owned files rather than an HSM. |
| Image finalizer | `crates/release/aos-image-finalizer` | Assembles and signs UKIs, recovery bundles, verity, and disk encodings through the external signer. |
| Qualification contract | `qualification/` | The Nix-evaluated destinations, profiles, and fitness requirements embedded in every plan. |
