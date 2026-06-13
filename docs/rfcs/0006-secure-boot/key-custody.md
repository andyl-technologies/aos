# RFC-0006 — Key custody

The central decision. Secure Boot only means something if the key that makes
a binary bootable is harder to obtain than the thing it protects. So the
governing question is not "how do we sign" — `ukify`/`sbsign` already do that
— but **where each key lives, and what it must never be able to do.**

## The keys

Full SB + measured boot introduces four key roles. They are separate keys
with separate custody on purpose.

| Key | Signs | Custody | In build closure? | Rotation |
|---|---|---|---|---|
| **PK** (Platform Key) | KEK updates | offline, deployment-owned | no | rare (re-own the platform) |
| **KEK** (Key Exchange Key) | db/dbx updates | offline, deployment-owned | no | rare |
| **db** (signature db) | UKI + sd-boot (Authenticode) | offline / HSM, signs at release | **no** | on compromise; dbx-revoke old |
| **PCR-policy key** | the UKI's `.pcrsig` section | offline, signs at release | **no** | on policy change |

Plus the two keys that already exist and are **not** SB keys:

- **registry git-tag key** (SSH Ed25519, `docs/registry/signing-and-trust.md`)
  — signs metadata *about* artifacts. Online-ish (signs on every publish),
  rotates in-band. **Must never gain the ability to sign a UKI.**
- **module-signing key** (deployment overlay, [`boot-chain.md`](boot-chain.md))
  — signs out-of-tree kernel modules under lockdown.

## The invariant the base already encodes

`pkgs/kernel/config/security.config:27-31` states it for the kernel, and it
generalizes to every SB key:

> Module signing belongs to deployments that own a non-public key, not the
> base image.

The public, reproducible base **owns no signing key**. If it did, the key
would ship in the closure (anything reachable from a derivation is
distributable), and bit-for-bit reproducibility would require everyone to
share one private key — self-defeating. Therefore:

**Every SB key is a deployment overlay.** The base produces *unsigned*
artifacts that are byte-reproducible; signing is a **post-build release step**
that a deployment performs with its own keys. This shapes the whole
implementation: `aos-uki` and the image builder must take signing keys as
*optional inputs* (absent → today's reproducible unsigned artifact; present →
signed release artifact), never bake them.

## Two custody tiers

### CI / development keys

Ephemeral keys generated at build time, used only to prove the mechanics in
`checks.fleet.*`. These **may** live in the build (they protect nothing real)
— but they must be generated fresh per test, never reused, and clearly named
so they cannot be mistaken for production material. They sign the test UKI,
get enrolled into the test OVMF_VARS, and are thrown away. This is what
unblocks phases 1–3 without waiting on production infrastructure.

### Production keys

Held **outside** the build entirely — HSM, airgapped host, or cloud KMS. The
signing interface must not assume a key file on disk:

- `ukify` supports `--signtool` and engine/PKCS#11 key URIs;
  `--secureboot-private-key` can be a PKCS#11 URI, not only a path.
- `sbsign` supports `--engine` for PKCS#11.

So the image-build → sign → publish pipeline calls a **signing service
abstraction** (key reference, not key bytes). Standing up that service (HSM
procurement, signing ceremony, audit log) is explicitly out of scope to
*implement* here; the RFC's job is to make sure nothing assumes a local key
so the service slots in cleanly.

## Why the registry key must stay walled off

It is tempting to "just sign UKIs with the registry key" since the registry
already signs releases. **No** — that collapses SB's threat model:

- The registry key is online-ish: it signs on every `apr publish`, lives near
  network-facing infrastructure, and rotates in-band via the signed roster
  (`KeysToml` active/revoked, `crates/aos-package/src/registry/keys.rs`).
- The db key's entire value is that compromising the network does **not**
  compromise boot — it's offline and the firmware roots trust in hardware.

If the registry key could mint boot-valid UKIs, then popping the (exposed,
frequently-used) registry key would let an attacker produce images the
firmware trusts — reducing the hardware-rooted guarantee to the registry's
threat model. So: **the registry records facts about SB-signed artifacts; it
never produces SB signatures.** See [`registry-catalog.md`](registry-catalog.md)
for how recording-without-signing stays safe.

## Enrollment: Setup Mode vs pre-enrolled

Getting PK/KEK/db *into* the firmware has two shapes:

- **CI / VMs**: inject keys into `OVMF_VARS.fd` offline with `virt-fw-vars`
  (no boot required) — the cleanest path for a hermetic, repeatable test.
  See [`boot-chain.md`](boot-chain.md).
- **Hardware**: two options.
  - *Ship in Setup Mode*, enroll PK on first boot via an ignition-ordered
    oneshot (Setup Mode lets an unauthenticated agent write PK once;
    enrolling PK flips to User Mode and SB begins enforcing). Pro: image is
    generic; con: a window before enrollment where SB isn't enforcing.
  - *Pre-enroll at image build* (write the vars into the image's firmware
    var store / ship a vendored varstore). Pro: enforcing from power-on; con:
    image is deployment-specific and firmware-var injection is platform-fiddly.

Recommendation: Setup-Mode + first-boot enroll for the generic image, with
pre-enroll available for locked-down deployments. The first-boot enroll hook
is the same kind of ignition-ordered oneshot the boot chain already uses
(GPT-relocate, growfs) — see [`boot-chain.md`](boot-chain.md) §enrollment.

## Recovery

Two ways an honest machine can lock itself out, each needing an escape hatch:

- **SB**: a db rotation that doesn't reach a machine before its next signed
  UKI → unbootable. Mitigation: keep the old db cert in `db` until every
  machine has the new one (additive enroll, revoke via dbx later), and a
  recovery path that re-enters Setup Mode (physical-presence or signed KEK
  update).
- **TPM-sealed `/var`**: a PCR change the signed policy doesn't cover →
  unsealing fails. Mitigation: a **recovery passphrase** enrolled alongside
  the TPM key (`systemd-cryptenroll` supports both), escrowed at provisioning.
  Detailed in [`measured-boot.md`](measured-boot.md).

These recovery paths are not optional polish — without them the first bad
rotation bricks the fleet, which is a worse failure than the attacks SB
defends against.
