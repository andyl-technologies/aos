# Trust, measured boot, and the secrets interface

This document specifies why the locally-computed manifest is trustworthy
without its own signature, the measured-vs-derived boundary and its one real
gap, how provisioning-input authenticity is established, the generation-attestation
record, and the secrets-out-of-manifest interface to the forthcoming
secret-management system.

## Trust root (terminology)

Trust is rooted at a **signed annotated git tag → blessed realization graph**,
not at the narinfo. `verify_tag_chain` (`crates/aos-package/src/registry/verify.rs:99`)
checks a chain of signed tags (channel → release → commit) against the trusted
key set with name-binding against replay. The narinfo is **explicitly
unauthenticated** (`crates/aos-package/src/verify.rs:1-24`); only
`verify_nar_blessed` re-roots the bytes against a blessed entry in the **signed
`store/` realization graph (RFC-0005)** that the tag covers. The chain is:
*signed tag → blessed realization graph → NAR bytes → store path*. RFC-0011
inherits this for `config` closures unchanged.

Trust anchors ride in the measured image: `modules/base/apm-registries.nix`
writes `/etc/apm/trusted-keys.d/<name>.pub` (registry tag key) and
`trusted-sb-certs.d/<name>.pem` (SB db cert). RFC-0011 adds
`trusted-config-keys.d/<op>.pub` (optional signed-mode configuration keys,
below). The same public anchors are included in the measured initrd when
signed-mode provisioning must be authorized before repart.

## The manifest needs no signature

The manifest is computed on the box; no party authors it. It is `f(inputs)`
where `f = lib.evalModules` in pure mode. A signature attests authenticity of
origin; the manifest has no origin to attest. The trust it needs is "derived
only from trusted inputs by the trusted function," established by:

```text
TRUSTED INPUTS                               DETERMINISTIC TRANSFORM      OUTPUT
base lib       (in the measured UKI)        ─┐
config modules (signed-tag-blessed NARs)    ─┼─► pure evalModules ──►   MANIFEST
host.nix       (policy-authenticated data) ─┘   (no I/O, no builds)     (content-addressed gen)
```

1. **Input authenticity.** config modules ∈ NARs that re-root to the signed
   realization graph; the **base lib and the evaluator live on the erofs root**
   (not in the UKI — see the boundary section below for how that root's
   integrity must be anchored, decision F1 in [`known-issues.md`](known-issues.md));
   `host.nix` is the one operator-authored input not pre-trusted (host.nix
   section); **instance facts are a second host-varying input** that must be
   recorded (facts section).
2. **Determinism.** `evalModules` under `--pure-eval` cannot read the clock,
   network, env, or `/` outside its inputs. Identical inputs ⇒ bit-identical
   manifest — the same property the repo already leans on for the byte-
   reproducible base. **"Inputs" here is the full tuple** `(base-lib, evaluator,
   config-module closure, host.nix, instance-facts)`; all five must be pinned for
   the re-derivation argument to hold.

⇒ **Reproducibility from authenticated, recorded inputs is sufficient and
strictly stronger than
a signature.** Signing the manifest would attest only that "some box ran the
eval" — which a verifier can re-derive — and would require a per-host online
signing key, exactly the anti-pattern `key-custody.md` forbids for the registry
key. The manifest is re-derivable and falsifiable: any verifier with the signed
inputs recomputes it and compares. The content-addressed generation id =
hash(manifest) is the integrity primitive.

## Measured vs derived boundary

> **Correction (review C1).** An earlier draft claimed the evaluator + base lib
> are "in the measured UKI." They are **not** — they are large store paths on the
> **erofs root**, consumed by the stage-2 `aos-eval.service`. Today that root has
> **no dm-verity/roothash**, and the `/var` seal binds only PCR-11 (UKI) + PCR-7
> (SB state), neither of which covers the root partition. So an offline attacker
> who rewrites the erofs root (swapping the evaluator or base lib) leaves the PCRs
> unchanged and `/var` still unseals — defeating "measure the producer." This is a
> **required hardening, decision F1** in [`known-issues.md`](known-issues.md).

- **Measured today (trust root):** the UKI = kernel + initrd + cmdline + baked
  trust anchors (PCR-11 signed policy); SB state pinned in PCR-7.
- **The producer the eval depends on (base lib + evaluator)** lives on the erofs
  root and **must be anchored to that measured boot to be trustworthy** — F1:
  dm-verity on the root with the roothash on the measured kernel cmdline (so root
  tampering moves PCR-11), or embed the evaluator+base-lib closure in the UKI
  initrd. Until F1 lands, the on-host-eval integrity guarantee is **only as
  strong as the `/var` seal + signed eval inputs**, not the producer's integrity.
- **Derived, not measured:** the manifest, the `/etc` composefs overlay, the
  downloaded config NARs, and the materialized generation in `/nix` (upper on
  `/var`). This is the config-generation.

The `/var` seal gives confidentiality + offline-tamper protection for everything
derived (LUKS2-sealed to the measured UKI). The *producer's* integrity, however,
requires F1 — it is not free today. **Measure the producer (UKI **and**, via F1,
the root carrying base-lib+evaluator); seal-protect the product (`/var`).**

### The one real gap

PCR-11 measures the *evaluator and base lib*, but **nothing measures which
config-module inputs / host.nix the evaluator consumed.** A box that booted a
good UKI and then evaluated a *different but validly-signed* config set, or a
malicious host.nix, produces a different generation the seal happily protects
and a naive PCR-11 quote cannot distinguish. The seal answers "did a good UKI
run?", not "did it derive config only from the inputs I expect?" Closing this is
the attestation record below.

## Provisioning and host.nix authenticity

`host.nix` is operator-supplied and per-host — an input to the trusted
computation but not in the image. It is delivered as literal Nix or as an exact
inline/pinned member of an `aos.provisioning/v1` bundle fetched by the
`aos metadata` agent (see [`provisioning.md`](provisioning.md)). Authentication
is selected by image policy:

- **`platform` (default)** treats successful delivery through the detected
  cloud metadata service or deployment-owned config drive as authorization.
  This is the zero-touch golden-image path: the cloud control plane already
  controls instance creation, disk attachment, and user-data.
- **`signed` (secure mode)** requires a detached SSHSIG over the exact
  provisioning-bundle bytes, verified against
  `trusted-config-keys.d/<op>.pub` via
  `security.rs::verify_payload_signature` + `TrustStore`.

The selected policy is measured boot configuration and cannot be supplied or
overridden by the provisioning bundle. `signed` never falls back to `platform`.
The public anchor set may be common to every copy of a golden image; only the
private signing key remains outside the image.

When a bundle contains a storage plan, authorization happens in initrd before
the plan is rendered or `systemd-repart` may mutate GPT. Signed-mode public
anchors are therefore copied into the measured initrd. Public verification keys
are safe to share across every deployment of one golden image; per-instance
secret injection is neither necessary nor desirable. The bundle authenticates
the storage plan and the `host.nix` content hash as one object.

Full Nix evaluation remains in stage-2. The evaluator consumes the exact
accepted `host.nix` bytes carried through `/run` and confirms their recorded
hash before eval. A platform-mode authorization failure or a signed-mode
missing/bad signature fails closed. For a declared storage plan this is an
initrd failure before disk mutation; for host configuration without an early
plan, no manifest is produced and the box stays on gen-0.

**Per-host config does not break attestation** — it breaks whole-image
attestation (no single golden manifest hash fleet-wide), but not
*input-set* attestation. A verifier expects not "host X's manifest == golden"
but "host X's manifest == eval(base-lib@v, config-modules@signed-tag,
host.nix@authenticated-hash-H, facts@facts-hash-F)."

## Instance facts are a recorded input (review M-facts)

`host.facts.*` (hostname, MAC→interface map, disk IDs, SSH authorized keys, any
metadata-delivered network config) is a **second host-varying eval input**,
gathered from **unauthenticated** IMDS (plain HTTP to the link-local). It
materially affects the manifest (networkd files, users), so the re-derivation
argument **fails unless it is recorded**. Therefore:

- The in-VM agent records a canonical **`facts_hash`** of the resolved
  `host.facts.*` tree (and retains the verbatim `facts.json`) in the manifest
  `inputs` and the `gen-attestation` record, so a verifier can reproduce the
  manifest from `(base-lib, evaluator, config-modules, host.nix, facts)`.
- Facts are **not** operator-authenticated (the platform supplies them), so the
  attestation states them as *"facts as supplied by platform P, hash F"* — a
  verifier trusts them only as far as it trusts the instance's platform binding,
  exactly as it would any IMDS-sourced fact. Facts must never carry security
  decisions that the operator did not authorize (see the gen-0 SSH-key fix in
  [`provisioning.md`](provisioning.md): no `authorized_keys` is seeded from this
  channel before the selected provisioning policy accepts the input).

The operator-authored input and the platform-facts input are distinct recorded
inputs. In `platform` mode both rely on the platform binding; in `signed` mode
the provisioning bundle has an independent signer while facts remain
platform-supplied.

## Generation-attestation record

Cheap because the inputs are already content-addressed. The box records a
TPM-quoted evidence bundle letting a remote verifier confirm "this generation
was derived only from trusted inputs":

```text
generation-attestation (extended into / quoted alongside PCR 7 + 11, e.g. app PCR 15):

  schema          = "aos.gen-attestation/v1"
  generation_id   = <content hash of the materialized config-generation>
  manifest_hash   = <sha256 of the canonicalized manifest>
  inputs:
    base_lib:
      pcr11_expected = <ukify-predicted PCR-11 for the booted UKI>   # ties to measured boot
      abi_hash       = <hash of the base-lib module API + module_abi>
    evaluator:
      store_path     = <store path of the eval binary>               # ⊂ measured UKI
    config_modules:
      registry       = <name>
      release_tag    = <semver>                  # verify_tag_chain target
      tag_signer_key = <trusted-keys.d fingerprint>
      realization    = <hash of the signed store/ graph subset consumed>
    host_nix:
      content_hash   = <sha256 of the operator config>
      bundle_hash    = <sha256 of the accepted provisioning bundle, if used>
      trust_mode     = <platform|signed>
      platform       = <aws|gcp|...>             # required for platform mode
      signer_key     = <config-key fingerprint>  # present only in signed mode
    instance_facts:
      facts_hash     = <sha256 of the canonical host.facts.* tree>   # M-facts: the 2nd host-varying input
      platform       = <aws|gcp|...>                                 # facts are platform-supplied, not signed
  eval_mode         = "pure-eval"                # asserts the determinism precondition
  quote             = <TPM2 quote over PCR 7,11(,15) + this record's hash>
```

A verifier confirms (a) PCR-7/11 match the registry's recorded `expected_pcr11`
(`registry-catalog.md:42-52`, reused — not a parallel value), (b) `release_tag`
is signed by a roster key and not revoked, (c) the recorded configuration trust
evidence satisfies the named policy (platform binding or trusted signed-mode
key), then optionally (d) **re-runs the pure eval on those
exact inputs and checks `manifest_hash`** — turning attestation into full
re-derivation. This extends RFC-0006's UKI-only "inputs" attestation
(`measured-boot.md:169-176`) to the config-eval inputs. `base_lib.abi_hash`
matters because the same host.nix against a different base-lib API yields a
different manifest; pinning it makes the input set complete.

## Threat model of on-host eval

On-host eval widens the threat model versus a fully pre-built image — a
Turing-complete interpreter now runs on the box fed operator input — but does
**not** weaken the measured-boot guarantee itself (UKI/evaluator stay measured,
`/var` stays sealed). Eval-only removes the arbitrary-process surface (no IFD,
no builders), but the interpreter must be sandboxed:

- **Impurity / exfiltration** (`readFile`, `getEnv`, `fetchurl`, `<nixpkgs>`
  lookups, `currentTime`) → `--pure-eval` + `--restrict-eval` with allowed paths
  = exactly {base lib, downloaded config-module store paths, host.nix} and
  `allowed-uris = []`. Pure-eval is doubly required: it is also the determinism
  precondition for the reproducibility argument and the `eval_mode` attestation
  field.
- **Resource exhaustion / denial-of-boot** (infinite recursion, memory bomb) →
  a hardened transient systemd unit: `MemoryMax`, `RuntimeMaxSec`/
  `TimeoutStartSec`, `TasksMax`, `MemoryHigh`, plus `ProtectSystem=strict`,
  `PrivateDevices=`, `NoNewPrivileges=`, a read-only bind of only the input
  paths, `SystemCallFilter`. On timeout/OOM, **fail closed** (keep the prior
  generation; never activate a partial manifest). See
  [`operability.md`](operability.md) for the budget.
- **Evaluator memory-safety bug** → the evaluator is itself measured (in the
  UKI), so its integrity is attested; the sandbox contains a compromise to an
  unprivileged, capped, fs-restricted process whose only output is a manifest
  still gated by downstream content-addressing + apm verify.

aos-nix (P2) improves this from a blunt OOM-kill to an in-engine timeout, and
opens a path to totality analysis that rejects divergent configs before running.

## Secrets — interface, not implementation

A full secret-management system is forthcoming as separate work. RFC-0011 does
**not** solve secrets; it fixes the boundary so secret material never enters the
value graph and the future system slots in. The seam already exists in code
(`CredentialMeta` has no plaintext field, `types.rs:690-708`); RFC-0011 names it
as an invariant and extends it to the module layer.

### The invariant

**Secret material must never appear in any value the evaluator produces.** The
manifest is content-addressed into the world-readable `/nix/store`, GC-rooted,
reproducible, and may be logged or pushed to a cache. Plaintext in the value
graph would be world-readable, deterministically hashed (the hash becomes an
oracle; identical secrets collapse to one cache object), and unrotatable without
changing the manifest. **TPM2/PCR-11-sealed ciphertext is permitted** (inert
without the host TPM in the right measured state); the ban is on plaintext, not
ciphertext.

### Credentials by handle

The manifest and a package's config module reference a credential by
name/handle + credstore path only. A `{pkg}.credentials.*` option is a thin
wrapper over the validated `CredentialMeta` contract:

```nix
options.services.web.credentials.join-token = {
  name      = mkOption { type = types.str; default = "join-token"; };           # systemd credential id (handle)
  encrypted = mkOption { type = types.bool; default = true; };                  # at-rest sealed
  source    = mkOption { type = types.str;                                      # credstore PATH, not a value
                         default = "/etc/credstore.encrypted/web/join-token"; };
  units     = mkOption { type = types.listOf types.str; default = [ "web.service" ]; };
};
```

This evaluates into `expose.config.credentials` → `CredentialMeta`, which the
renderer turns into `LoadCredentialEncrypted=join-token:/etc/credstore.encrypted/web/join-token`
on the unit. The evaluator sees a *path string and a name*; systemd places and
decrypts the bytes at activation (TPM2-unseal against PCR-11). The option type
**refuses a literal value** — there is no `value=`/`text=` constructor, mirroring
the renderer's `validateCredential` allowed-keys (no plaintext key). That is
type-level enforcement of the invariant.

### host.nix carries references, not values

Operators name credentials and point at where material *will* live; they never
inline the secret:

```nix
aos.host.credentials."web/join-token" = {
  ref    = "tpm2-credstore";                       # resolver selector, not a value
  source = "/etc/credstore.encrypted/web/join-token";
};
```

The material lives where it does today, all outside eval: vendored build-time-
sealed `encryptedFile` blobs; the `desired.toml [credentials]` reconciler
writing the credstore (`credential_artifact.rs`, encrypting via `systemd-creds`
against PCR-11); or `system-credential` pass-through from
`/run/credentials/@system/` (`desired.rs`).

### The future-system seam

RFC-0011 commits to exactly two things so the secret system slots in without
reshaping the manifest:

1. **An opaque `secretRef` type** whose only inhabitants are `{ name; source;
   encrypted; units; }` plus an optional `ref` discriminator naming a resolver
   (`tpm2-credstore`, `desired-toml`, `system-credential`, later `vault`,
   `aws-sm`, …). It is `Serialize`-compatible with `CredentialMeta`, so no
   manifest schema change. The value graph only ever contains `secretRef`s.
2. **A resolution contract at activation:** given a `secretRef`, before the
   consuming unit starts, place the bytes at `source` in the credstore (mode
   0600) or hand systemd an equivalent `LoadCredential*`/`ImportCredential`
   directive, then mark dependent `units` for restart. This is exactly what
   `credential_artifact.rs::reconcile_desired_credentials` already implements for
   the `desired.toml` resolver. **systemd credentials are the universal delivery
   interface**, so no package depends on which backend produced the bytes.

RFC-0011 **defers** to the future system: the secret store/backend
(Vault/KMS/SM), rotation, lease/TTL/revocation, multi-host distribution and
per-host derivation, operator UX for *entering* values (today's `desired.toml`
plaintext path is the marked stopgap resolver the future system replaces), and
key custody beyond the existing TPM2/PCR-11 mechanism.

**Determinism holds:** a `secretRef` contributes only stable identifiers
(`name`, `source`, `encrypted`, `units`, `ref`) to the hashed graph; rotating a
value changes bytes on disk but not the manifest store path.
