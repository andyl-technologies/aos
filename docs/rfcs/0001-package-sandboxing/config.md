# Configuration delivery to packages

Status: RESOLVED (direction)

> **DECISION: RESOLVED — layered, three tiers.** Config has three distinct
> needs, and the answer is one per need, not one channel for all:
> - **Secrets → TPM2-sealed systemd credentials** (signed-PCR-11/UKI policy) —
>   **signed off** (2026-06). This rides RFC-0006's measured-boot/TPM2 substrate
>   and satisfies the original "do not settle on credstore" caution: it is
>   *TPM-sealed*, not the bare host-key credstore that caution was about. See
>   *Recommended direction* below for the mechanism.
> - **Structured config → an apm config artifact validated against a
>   manifest-declared schema** before the service starts.
> - **Simple / non-secret → `EnvironmentFile=` + Ignition `storage.files`**
>   (k3s's pattern), the zero-ceremony tier.
>
> The other options below remain documented as the alternatives this was chosen
> against. **Hot reload** is built (D25): the manifest declares reload support; a
> config change runs `systemctl reload-or-restart`.

This is one of the package docs. Siblings:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[activation.md](activation.md), [open-questions.md](open-questions.md).

> **Unified model.** Every service package exposes a target plus generated
> systemd units; what differs is *privilege*, declared in a signed
> `[permissions]` manifest (see [permissions.md](permissions.md)). Config
> delivery crosses a package-owned systemd boundary, not necessarily an nspawn
> boundary. k3s is a high-privilege package (host network, host paths), which is
> why its simple config naturally arrives through `EnvironmentFile=`.

## Summary

A "package" is the registry-installable unit (`apm install`); service packages
expose an `aos-pkg-<name>.target` handle plus generated units (see
[container-model.md](container-model.md)). Every such package needs
configuration — non-secret settings (node IP, feature flags, a join URL) and
secrets (a join token, a TLS key) — delivered to the workload. This doc surveys
seven delivery mechanisms against six criteria
(boundary crossing, reloadability, secret-safety, per-instance override,
introspection, maturity), grounds each in what AOS ships today, and records the
chosen layered model.

## What we have today (the k3s baseline)

The current, working config path for k3s is plain and worth stating exactly,
because every option below is measured against it.

k3s reaches config via a systemd `EnvironmentFile`, and the file is written
by Ignition at first boot. From `pkgs/kubernetes/_k3s-expose-package.nix`:

```nix
units."k3s.service".serviceConfig.EnvironmentFile = "/etc/rancher/k3s/k3s.env";
```

and a preflight service guards it so a missing file fails cleanly rather than
producing a confusing k3s error:

```nix
unitConfig.ConditionPathExists = "/etc/rancher/k3s/k3s.env";
```

The file itself is delivered as instance metadata. From
`tests/fleet/k3s-control-plane-worker.nix`:

```nix
instanceMetadata.config.storage.files = [
  { path = "/etc/rancher/k3s/k3s.env";
    mode = 384;          # 0600
    contents.source = "data:,K3S_TOKEN=...%0AK3S_URL=https://controlplane:6443"; }
  { path = "/etc/rancher/k3s/config.yaml";
    mode = 420;          # 0644
    contents.source = "data:,node-ip: 192.168.50.10%0Aflannel-iface: eth0"; }
];
```

So the baseline chain is:

```
Ignition storage.files  →  host /etc file  →  systemd EnvironmentFile  →  service env
```

Two properties of the baseline matter throughout:

- **Read-once.** `EnvironmentFile` is parsed at service start. Editing the
  file later does nothing until `systemctl restart`. There is no hot-reload.
- **Plaintext at rest.** The env file lives unencrypted in the `/etc` overlay
  (it lands in `/var/etc/...`, the read-write layer of the 3-layer overlay —
  see [boot-activation.md](boot-activation.md)). `mode = 0600` is the only
  thing standing between the token and other local processes.

Relevant AOS surfaces, for grounding:

- `lib/modules/systemd/lib.nix` has an `assertKeyIsSystemdCredential` helper
  that validates fields marked `@<credential-name>`, but AOS does **not** yet
  expose systemd's credential system as a general first-class module option.
  The exposed-package renderer can emit `LoadCredential=` /
  `LoadCredentialEncrypted=` for service units, including fail-closed
  `name:/path` imports from systemd credstore directories, and
  `SetCredentialEncrypted=` for signed inline encrypted payloads. Inline
  package-time payloads are produced by `apm credential encrypt`, which invokes
  `systemd-creds encrypt --with-key=tpm2 --tpm2-public-key-pcrs=11 --pretty` and
  prints either the inline ciphertext or a Nix `expose.config.credentials`
  snippet. Package-time `encryptedFile` credential declarations vendor already
  encrypted blobs,
  serialize only the generated
  `/run/credstore.encrypted/aos/<package>/<name>` source path in the manifest,
  and `apm` projects those blobs into the live runtime credstore before package
  targets start. For install-at-boot desired files,
  `credentials.<package>.<name>` entries now provision signed package-declared
  `/etc/credstore*` or `/run/credstore*` sources. Encrypted desired credentials
  use `[settings].credential_pcr_public_key` or the measured-boot default
  `/etc/aos/pcr-sign.pem`; desired values may reference
  `{ system-credential = "<name>" }` so first-boot secrets come from
  `/run/credentials/@system/<name>` instead of `desired.toml`.
  `/usr/lib/credstore*` remains package/vendor-owned.
- `pkgs/system/systemd.nix` controls the systemd build flags. The credential
  substrate is verified by `checks.systemd-credentials`: `systemd-creds`, signed
  PCR TPM2 encryption flags, credstore tmpfiles entries, `systemd-measure`, TPM2
  setup units and generator, and the cryptsetup TPM2 token plugin are present.
- Ignition's files stage writes to `/run/etc/ignition-<gen>/etc/` in initrd,
  then those land under `/var/etc/*` in stage 2
  (`modules/services/ignition.nix`).

## Future nspawn boundary analysis

The selected MVP does not require a container boundary: per-unit services read
host config artifacts or credentials directly. The historical nspawn design
below is retained to document how the same tiers would cross a full-init
container boundary if nspawn returns. In that future path the workload's PID1 is
`systemd-nspawn`'s child, in its own mount namespace, and the config has to
cross from the host into that namespace. Concretely a host unit launches the
container roughly as:

```ini
[Service]
ExecStart=/usr/lib/systemd/systemd-nspawn --image=/var/lib/machines/<pkg>.img ...
```

and config can cross that line by exactly three transport shapes:

1. **Bind mount** a host path into the container (`--bind` / `--bind-ro`).
2. **Pass a credential** host→container (`--load-credential=` →
   `/run/credentials/...` inside).
3. **Bake it into the container image** (no crossing; it was there at build).

Everything below reduces to one of these three at the boundary. Whether a
mechanism is "good across nspawn" is mostly whether its natural shape is a
clean bind or a credential, versus something that doesn't translate (a kernel
cmdline is inherited but read-only and global; a registry fetch can happen
host-side then bind in, or be re-done inside the container).

## The options

Each option is described, then scored against the criteria in the matrix. The
selected layered model uses Option 1T for secrets, Option 3 for structured
config, and Option 2 for simple/non-secret config; the others remain as recorded
alternatives.

### Option 1 — systemd credentials / credstore / `--load-credential`

systemd ≥254 credentials: a unit declares `LoadCredential=name:/path` (or
`ImportCredential=name`), and systemd exposes the value to the service as a
file under `$CREDENTIALS_DIRECTORY` (a per-service tmpfs, `noexec`).

- **Boundary crossing:** clean — `systemd-nspawn --load-credential=name:src`
  passes the value into the container, where the container's own PID1 systemd
  re-exposes it via `ImportCredential=`. This is the one mechanism designed
  for the host→container handoff. **Caveat:** it presumes the container runs
  systemd as PID1 (full-init container, not single-service `--image` running a
  bare binary).
- **Reloadability:** snapshot at service start; a changed credential needs
  `systemctl restart`. No hot-reload.
- **Secret-safety:** best on isolation — `$CREDENTIALS_DIRECTORY` is tmpfs,
  per-service, not world-readable. **But** the *source* still has to live
  somewhere; without a sealed backend that source is plaintext under
  `/etc/credstore/`. AOS now has a measured-boot/TPM2 substrate (RFC-0006) and a
  credstore-capable systemd build verified by `checks.systemd-credentials`;
  package-level encrypted credential production is wired through
  `apm credential encrypt`, `encryptedFile`, and desired-file provisioning.
- **Per-instance override:** Ignition writes per-instance source files at first
  boot. One file per credential; systemd treats the content as opaque bytes.
- **Introspection:** `systemctl show -p LoadCredential <unit>`; `ls
  /etc/credstore`. No audit trail of which service read which credential.
- **Maturity:** recent; not yet widely trodden in production, and the nspawn
  credential handoff specifically is thinly documented. Untyped in AOS modules.

### Option 2 — `EnvironmentFile` + Ignition `storage.files` (status quo)

The baseline above, generalized: Ignition writes a file, a unit reads it with
`EnvironmentFile=`.

- **Boundary crossing:** good — the host file is bind-mounted into the
  container (`--bind-ro=/etc/rancher/k3s`), and the in-container unit reads the
  same path. Plain and well-understood.
- **Reloadability:** read-once at start; edit + `systemctl restart`. No
  hot-reload.
- **Secret-safety:** fair — plaintext on disk, `mode 0600` plus mount-namespace
  isolation are the only guards. If the host dir is bind-mounted rw, the
  container sees the same plaintext.
- **Per-instance override:** native — each machine's Ignition config carries
  its own values; this is exactly how k3s tokens differ per node today.
- **Introspection:** `systemctl show -p EnvironmentFile <unit>`; `cat` the
  file. Ignition writes are visible in `journalctl -u ignition-files.service`.
- **Maturity:** classic, deeply documented, already in production use in AOS.
  Encoding caveat: Ignition `data:` URLs need URI-encoding (the test harness
  has a `uriEncode` helper that is not yet a public lib function).

### Option 3 — apm-managed config: registry-declared schema + per-instance overrides

A package declares a config schema in its registry metadata; `apm` validates a
per-instance override against it at install time and materializes a config
artifact the package consumes (see [apm-integration.md](apm-integration.md)).
Sketch of the registry-side declaration:

```toml
[config]
required = ["k3s_token"]
optional = ["k3s_url", "k3s_node_name", "k3s_node_ip"]
```

Instance overrides arrive as Ignition-written JSON (e.g.
`/etc/aos/apm/packages/<pkg>.json`); `apm install <pkg>` validates and emits
`/etc/aos/<pkg>/config.env` (or `.json`/`.yaml`).

- **Boundary crossing:** good — the emitted artifact is a host file, bind-mounted
  into the container like Option 2.
- **Reloadability:** baked at install; changing config means re-running an apm
  operation (`apm install`, or a future `apm config-reload`). No automatic
  hot-reload.
- **Secret-safety:** fair, with a twist — per-package isolation is clean (each
  package gets its own artifact dir), and apm could *enforce* `mode 0600` for
  fields the schema marks sensitive. Still plaintext at rest absent a backend.
- **Per-instance override:** native and **schema-checked** — the one option
  besides registry-hosted config that can reject a malformed/missing field
  *before* the workload starts.
- **Introspection:** `apm show <pkg> --schema`; `cat /etc/aos/<pkg>/config.*`;
  potentially `apm status <pkg>`.
- **Maturity:** AOS-specific; no ecosystem. New code in `crates/aos-package`
  (a schema/validation module) plus an Ignition→apm bridge.

### Option 4 — kernel cmdline / SMBIOS / fw_cfg

Encode config into the boot environment: kernel command line
(`/proc/cmdline`), SMBIOS DMI fields (`/sys/class/dmi/...`), or QEMU/Firecracker
`fw_cfg` (`/sys/firmware/qemu_fw_cfg/...`).

- **Boundary crossing:** cmdline is inherited into the container read-only and
  is globally visible; SMBIOS is per-host (container sees the host's DMI);
  fw_cfg generally does **not** pass into nspawn. Read-only, global, awkward.
- **Reloadability:** none — fixed at boot; change requires reboot (cmdline) or
  host action (SMBIOS/fw_cfg).
- **Secret-safety:** bad — `/proc/cmdline` is world-readable to every process;
  SMBIOS likewise. **Not for secrets.**
- **Per-instance override:** awkward for cmdline (bootloader drop-ins);
  unusual for SMBIOS/fw_cfg. No schema.
- **Introspection:** `cat /proc/cmdline` is trivial; `dmidecode` for SMBIOS
  (vendor-specific format). No audit trail.
- **Maturity:** the kernel/firmware interfaces are ancient and reliable, but
  using them for app config is unusual and brittle. Fit only for a small,
  non-secret, rarely-changed flag (e.g. a deployment-mode selector).

### Option 5 — registry-hosted config + apm download

Config (public and/or secret) lives on a registry/config server; `apm`
downloads it per-instance at install time (and potentially polls for updates).

- **Boundary crossing:** host downloads to a host path, then bind-mounts in
  (or the container runs its own apm and fetches independently). Two-step.
- **Reloadability:** the only option with a plausible **push/poll** story — a
  server can serve new config and apm can re-fetch on a timer/webhook. Still
  not zero-restart, but it is the closest to fleet-wide live config.
- **Secret-safety:** transport can be authenticated (only *your* instance sees
  *its* secrets); at-rest storage is the same plaintext-on-disk problem.
  Introduces a new trust boundary (the config server).
- **Per-instance override:** server-side per-instance config keyed by an
  instance ID supplied via Ignition. Operationally heavier (server HA, auth).
- **Introspection:** `cat` the downloaded file locally; richer history/audit
  lives in the server, not on the host.
- **Maturity:** AOS-specific; **breaks air-gapped/offline installs** because it
  needs the server reachable at install time. Scope creep relative to "registry
  serves packages."

### Option 6 — per-package config overlay in `/etc` (ConfigMap-like)

Generalize the baseline with per-package namespacing: Ignition (or apm)
materializes `/etc/aos/<pkg>/config.{env,yaml,json}`; the unit reads it; the
container bind-mounts `/etc/aos/<pkg>/`.

- **Boundary crossing:** good — clean, per-package bind
  (`--bind-ro=/etc/aos/<pkg>:/etc/aos/<pkg>`).
- **Reloadability:** same as `EnvironmentFile` — read-once, restart to apply.
- **Secret-safety:** fair — per-package directory limits accidental
  cross-package reads; still plaintext, still perms-dependent.
- **Per-instance override:** native via Ignition; format is per-package
  (the package decides env vs YAML vs JSON), with **no** schema enforcement
  (that is Option 3's distinguishing feature).
- **Introspection:** `ls /etc/aos/`, `cat /etc/aos/<pkg>/config.*`, and the
  unit's `EnvironmentFile=`/working dir.
- **Maturity:** classic mechanisms (bind mounts, symlinks, env files), just
  organized by package. No new systemd or apm infrastructure required.

### Option 7 — systemd-confext: config as a signed `/etc` extension image

`systemd-confext` (the `/etc` twin of `systemd-sysext`, in core systemd — *not*
behind the disabled `portabled`) merges dm-verity-protectable extension images
into `/etc` as an overlay; `systemd-confext refresh` atomically
merges/unmerges. Config ships as a small **signed image** rather than loose
files — the mechanism Flatcar and the UAPI-group ecosystem use for exactly
this. The option the original survey missed.

- **Boundary crossing:** host-side merge; the merged paths are bind-mounted
  into the container like Options 2/6 (or a full-init container runs its own
  confext against an image bound in).
- **Reloadability:** `refresh` swaps the merged view atomically, but units
  still read at start — restart-to-apply, same as the local options.
- **Secret-safety:** the only local option with **signed, verity-protected
  config at rest** — *integrity*, not secrecy (the image is signed, not
  encrypted; the at-rest plaintext gap below still applies).
- **Per-instance override:** an image per instance or fleet-ring; heavier to
  mint than an Ignition-written file — needs hermetic image-mint tooling.
- **Introspection:** `systemd-confext status`; merged files are plainly
  visible in `/etc`.
- **Maturity:** recent but in-core and actively used by the
  sysext/confext ecosystem. **Verified: NOT built today** —
  `pkgs/system/systemd.nix` sets `-Dsysext=false` and no confext flag
  (default off). This option therefore costs a systemd build-flag change plus
  hermetic image-mint tooling, and the composition of a confext overlay with
  AOS's own 3-layer `/etc` overlay is untested.

## Option matrix

Scoring: ✓ good · △ partial / caveated · ✗ poor. These are *relative*
positions to aid discussion, **not** a scorecard that names a winner.

| Criterion | 1 Credentials | 1T creds+TPM2 (signed-PCR) | 2 EnvFile+Ignition | 3 apm schema | 4 cmdline/SMBIOS | 5 registry-hosted | 6 /etc overlay | 7 confext |
|---|---|---|---|---|---|---|---|---|
| Boundary crossing (host→nspawn) | △ (needs systemd PID1) | △ (needs systemd PID1) | ✓ | ✓ | △ (RO/global) | △ (2-step) | ✓ | ✓ |
| Reloadability (no restart) | ✗ | ✗ | ✗ | ✗ | ✗ | △ (push/poll) | ✗ | ✗ |
| Secret-safety | ✓ (tmpfs/iso) | ✓✓ (TPM-bound at rest + tmpfs/iso) | △ | △ | ✗ | ✓ (transport) | △ | △ (signed/verity at rest; integrity, not secrecy) |
| Per-instance override | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | △ (image mint) |
| Schema enforcement | ✗ | ✗ | ✗ | ✓ | ✗ | ✓ | △ | ✗ |
| Introspection | ✓ | ✓ | ✓ | ✓ | ✓ | △ | ✓ | ✓ |
| Offline / air-gapped | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Maturity / ecosystem | △ | ✓ (current SOTA) | ✓ | ✗ | ✓ | ✗ | ✓ | △ |

Two honest patterns fall out of the matrix and are worth stating plainly:

- **Nobody hot-reloads.** Under today's systemd model every local option is
  read-once-then-restart. Only the registry-hosted option (5) has even a
  partial reload story, and it pays for it with a network dependency and a new
  trust boundary. If live config without restart is a requirement, **none of
  these options satisfies it as-is** — it becomes its own workstream (a
  watch-file reloader, or a registry push path).
- **At-rest secrecy is unsolved by the *plain* options.** "Secret-safe" for
  options 1–7 above is mostly about *runtime* isolation (who can read the live
  value), not *at-rest* encryption. Those options store secrets as plaintext on
  `/var` and lean on file permissions and mount namespaces. (Option 7 adds
  at-rest *integrity* — signed/verity config images — but not secrecy.)
  **However**, this gap is no longer "AOS has no backend": RFC-0006 shipped a
  measured-boot/TPM2 substrate (see
  [../0006-secure-boot/README.md](../0006-secure-boot/README.md)), which the
  column **1T** above exploits to seal secrets at rest to attested boot state.
  That is the basis for the recommended direction below.

## Recommended direction: TPM2-sealed systemd credentials

> This is the **decided** secrets path (signed off 2026-06): the upstream SOTA
> for exactly this problem *and* already underpinned by infrastructure AOS has
> shipped (RFC-0006).

The earlier "do not settle on credstore" caution (top of this doc) rested on a
specific, now-closed gap: *AOS had no credential backend (TPM/sealed/LUKS)*. That
is no longer true. **RFC-0006 shipped a measured-boot + TPM2 substrate** (UEFI
Secure Boot, UKI measurement into PCR 11, unattended `/var` LUKS unlock via a
TPM2-bound key — see [../0006-secure-boot/README.md](../0006-secure-boot/README.md)).
With that substrate in place, the SOTA answer to "deliver a secret to a service
on an immutable, measured system" is **systemd credentials encrypted to the
TPM2**, and it is the recommended resolution for *workload* (isolated) packages.

This is the column **1T** in the matrix above — Option 1's transport
(`$CREDENTIALS_DIRECTORY`, host→nspawn `--load-credential`) upgraded with an
*at-rest* seal, which is precisely the dimension the plain options leave open.

### How secrets are shipped

Two ship vectors, both immutable-image-friendly (no plaintext in the read-write
overlay, nothing for an operator to hand-edit):

1. **Inline in the signed unit** via `SetCredentialEncrypted=`. The ciphertext
   lives directly in the (signed, read-only) unit file, so the secret travels
   and is integrity-protected with the unit itself:

   ```ini
   [Service]
   SetCredentialEncrypted=k3s-token: \
           k6iUCUh0RJCQyvL8k8q1UyAAAAABAAAADAAAABAAAAASfFsh7VNUUw4...
   ExecStart=/usr/bin/k3s server
   ```

2. **As encrypted blobs in the credstore**, dropped at
   `/usr/lib/credstore.encrypted/<name>` (the immutable, vendor/image-owned
   credstore — distinct from the mutable `/etc/credstore.encrypted/`), consumed
   by name with `ImportCredential=` / `LoadCredentialEncrypted=`.

Both are pre-produced outside the package build in a host/runtime sealing
context with `systemd-creds encrypt`. Crucially the *plaintext* never lands on
the target's writable disk: the artifact that ships is already ciphertext,
decryptable only on a host whose TPM2 satisfies the sealing policy.
For inline signed-unit metadata, `apm credential encrypt <name> <plaintext>
--expose-nix` owns the helper path and emits a pasteable
`expose.config.credentials` entry.

### How secrets are sealed (the policy that matters)

Encrypt with the TPM2 as the sealing authority:

```text
# host+TPM2 (default when a TPM2 is present and /var is persistent):
systemd-creds encrypt --name=k3s-token \
    --with-key=host+tpm2 plaintext.txt k3s-token.cred

# signed-PCR policy (RECOMMENDED for fleets + software updates):
systemd-creds encrypt --name=k3s-token \
    --with-key=tpm2 \
    --tpm2-public-key=/etc/aos/pcr-sign.pem \
    --tpm2-public-key-pcrs=11 \
    plaintext.txt k3s-token.cred
```

- `--with-key=host+tpm2` is the default when a TPM2 is present and persistent
  state exists; it mixes a host-local secret with a TPM2 seal. Good for the
  single-machine case.
- **`--tpm2-public-key` + `--tpm2-public-key-pcrs` (signed-PCR policy) is the
  recommended fleet path.** Instead of binding the secret to *literal* current
  PCR values (brittle — any legitimate kernel/UKI/firmware update changes the
  measurement and **bricks unsealing**), it binds to a **signature** over the
  expected PCR policy. The expected PCR value (`--tpm2-public-key-pcrs` defaults
  to **PCR 11 = the UKI measurement**, the same register RFC-0006 attests) is
  signed offline with a private key; at unseal time systemd accepts any PCR
  state for which it holds a valid signed policy. So a new signed UKI ships its
  own signed PCR-11 policy and the secret keeps unsealing across software
  updates, while a *tampered* boot (unmeasured/unsigned state) still cannot
  release it. This is the same shape RFC-0006 uses to keep `/var` unlocking
  across UKI updates.

The result: secret release is **tied to attested boot state** (a machine booted
into a non-AOS/unsigned/tampered image cannot decrypt the credential) **and
survives legitimate software updates** — the property that makes direct-PCR
binding unusable in a fleet.

### How the service consumes it

The unit declares its appetite with `LoadCredentialEncrypted=` (from a credstore
blob or path) or `ImportCredential=` (by name, with `SetCredentialEncrypted=`
inline); systemd decrypts at service start and surfaces the plaintext under
`$CREDENTIALS_DIRECTORY`:

```ini
[Service]
LoadCredentialEncrypted=k3s-token:/usr/lib/credstore.encrypted/k3s-token
# service reads ${CREDENTIALS_DIRECTORY}/k3s-token
Environment=K3S_TOKEN_FILE=%d/k3s-token
```

`$CREDENTIALS_DIRECTORY` is a **per-service `ramfs`/tmpfs** (non-swappable, so
the decrypted secret never hits disk or swap), mounted **owner-only** (`0400`,
the service's user), and is **not inherited down the process tree** and
**invisible to other services**. `%d` is the unit specifier for it.

### Why this beats the status-quo `EnvironmentFile=` / `/etc` secrets

The baseline (Option 2) and the `/etc`-overlay variants (Option 6) leak in ways
the credential path closes:

- **At rest:** `EnvironmentFile=` / `/etc` secrets land as *plaintext* in the
  `/var/etc` overlay and can be paged to **swap**. Encrypted credentials are
  ciphertext at rest (TPM-sealed) and the decrypted form lives only in
  non-swappable tmpfs.
- **Process-tree leakage:** values from `EnvironmentFile=` become the service's
  environment, readable by anyone who can see `/proc/PID/environ` and
  **inherited by every child/exec** in the tree. Credentials are *not* environment
  and are *not* inherited — only the owning service sees its
  `$CREDENTIALS_DIRECTORY`.
- **Path-holder exposure:** any process that can read the `/etc` file (or that
  the mode/ACL accidentally exposes) gets the secret; the credentials dir is
  owner-only and per-service.

### Why it fits AOS specifically

- **Immutable-image-friendly.** Ciphertext ships inside signed units or the
  vendor credstore; nothing requires a writable, hand-edited plaintext secret in
  the `/etc` overlay. Aligns with the read-only/signed-image direction.
- **Works in initrd.** `systemd-creds` and credential import are available in the
  initrd (`auto-initrd`), so early-boot secrets (e.g. a `/var` unlock helper, a
  remote-attestation token) are covered with the same mechanism rather than a
  bespoke initrd path.
- **Reuses RFC-0006.** No new trust root: the TPM2, the PCR-11 UKI measurement,
  and the offline signing key are exactly what RFC-0006 already established.

### First-boot / VM provisioning of the *sealing inputs*

Sealed credentials answer at-rest secrecy, but a freshly provisioned instance
still needs its *per-instance* plaintext (or a bootstrap token) to seal in the
first place. The SOTA path for injecting **system credentials** at first boot is
**SMBIOS OEM strings**, not the kernel cmdline:

```text
# QEMU / Firecracker: inject a system credential at boot
-smbios type=11,value=io.systemd.credential:vmm.notify_socket=...
-smbios type=11,value=io.systemd.credential.binary:k3s-token=<base64>
```

systemd reads `type=11` strings prefixed `io.systemd.credential:` (text) or
`io.systemd.credential.binary:` (base64) as **system credentials**, visible to
PID 1 and passable to units. **Prefer SMBIOS over the kernel cmdline** for this:
the cmdline (`/proc/cmdline`) is **world-readable to every process**, so a secret
placed there leaks immediately; SMBIOS OEM strings are not exposed in the same
world-readable surface. For non-VM hardware, Ignition still writes the
per-instance plaintext to a path that is then sealed at first boot, or ships the
already-sealed ciphertext keyed to that machine's TPM2.

### Residual work (so this is honest, not done)

The systemd substrate is verified by `checks.systemd-credentials`: AOS exposes
`systemd-creds`, `systemd-measure`, credstore tmpfiles entries, TPM2 setup units
and generator, signed-PCR TPM2 encryption flags, and the cryptsetup TPM2 token
plugin.

- **AOS module surface.** Exposed-package credential metadata now renders
  `LoadCredentialEncrypted=<name>` or `LoadCredential=<name>` into consuming
  service units. When the metadata declares a credstore `source`, it renders
  `name:/path` with `ConditionPathExists=` so missing blobs fail closed; bare-name
  imports remain an appetite/import declaration. Inline encrypted payload
  metadata is generated by `apm credential encrypt` and renders
  `SetCredentialEncrypted=<name>:<ciphertext>` in signed unit text.
  Package-time helpers now vendor already encrypted
  `credstore.encrypted/aos/<package>/<name>` expose-artifact blobs from
  `encryptedFile` declarations without serializing those build inputs into
  `manifest.json`, and `apm` projects them under
  `/run/credstore.encrypted/aos/...` before starting package targets. Desired
  files now provision `/etc` and `/run` credstore sources, can read plaintext
  from `/run/credentials/@system/<name>` via
  `{ system-credential = "<name>" }`, and encrypt encrypted credentials with the
  signed-PCR-11 policy. System-credential references keep plaintext out of
  `desired.toml`; the eventual at-rest form still follows the package's signed
  credential metadata.
- **nspawn handoff.** The host→container `--load-credential` path for full-init
  containers (the Option 1 caveat: container must run systemd as PID 1) still
  needs an end-to-end test; k3s, being a nominal/host-privileged container, is
  *not* the target for this path (see below).

## Where this does not fit: k3s

The boundary framing assumes config flows *into an isolated workload boundary*.
k3s violates the premise. As [container-model.md](container-model.md) spells
out, k3s is an **infrastructure** package: it wants the host network namespace,
host cgroups, host `/sys`, and global kernel modules. Its package target is
therefore high-privilege by design.

For config that means k3s's natural shape is **host paths shared with the
service**, not config injected across an isolation boundary:

- `/etc/rancher/k3s/k3s.env`, `/etc/rancher/k3s/config.yaml` are written on the
  host by Ignition and consumed by the package service — i.e. Option 2/6 in
  their simplest form.
- systemd credentials (Option 1) are still an awkward fit here: they shine for
  isolated workloads, which is exactly *not* what k3s is. Using them for k3s
  would be ceremony without the isolation payoff.

So k3s keeps the plain Ignition-file + host-path path. A single mechanism need
not serve both "isolated workload" and "host-privileged infrastructure"
packages equally well, and the design should not pretend otherwise. The current
package spike validated the high-privilege per-unit shape; a future nspawn path
would need its own bind-set check.

## Decision criteria

The chosen layered model should continue to be judged against these criteria as
the first real packages exercise it:

1. **Clean boundary crossing.** Does config reach the container PID1 without
   special-casing per package? (Favors a clean bind or a credential.)
2. **Offline / air-gapped.** Must installs work with no config server
   reachable? If yes, Option 5 is out as a *primary* path.
3. **Secret handling.** What's the bar — runtime isolation only, or at-rest
   encryption too? AOS now has the TPM2-backed substrate for the latter, while
   credential lifecycle and audit remain follow-up questions.
4. **Per-instance override ergonomics.** All the Ignition-based options give
   this; the differentiator is whether overrides are schema-checked (Option 3)
   or free-form (Options 2/6).
5. **Schema / pre-boot validation.** Do we want to reject a bad config before
   the workload starts? Only apm-schema (3) and registry-hosted (5) offer it.
6. **Reloadability.** Is restart-to-apply acceptable for v1? If hot-reload is
   required, it is a separate workstream regardless of mechanism.
7. **Introspection / debuggability.** Can an operator answer "where is this
   service's config coming from?" with local commands? Most local options do;
   the registry-hosted option pushes this to the server.
8. **Implementation cost / maturity.** Reuse classic systemd surfaces
   (Options 2/6) vs. build new apm/registry machinery (Options 3/5) vs. adopt a
   recent, thinly-trodden systemd feature (Option 1).

## Follow-up questions

1. **Sealing-key custody.** Desired-file `/etc` and `/run` credstore
   provisioning, inline metadata from `apm credential encrypt`, and
   package-time `encryptedFile` declarations all use the signed-PCR-11 policy.
   TPM2 sealing itself still requires target/runtime key material. How is
   sealing-key custody surfaced for fleet operators?
2. **Credential provisioning.** Desired-file provisioning covers host-authored
   plaintext and system-credential references consumed by `apm` and sealed into
   credstore payloads. The first-boot SMBIOS/system-credential ingress path is
   now `credentials.<package>.<name> = { system-credential = "<name>" }`, read
   from `/run/credentials/@system/<name>` without persisting plaintext in
   `desired.toml`; plaintext persistence after that depends on whether the
   package declares a plaintext or encrypted credstore source. Is one-time
   consumption / deletion needed after `apm` has sealed the secret?
3. **Credential read audit.** Do we need to log which process read which
   secret? systemd credentials don't provide it natively; a registry/apm path
   could.
4. **Future nspawn config-share shape.** If nspawn returns to scope, should
   host `/etc/rancher/k3s` stay host-shared, move into a copied isolated
   `/etc`, or use a distinct path? (Ties to
   [container-model.md](container-model.md).)
5. **apm config schema format**, if Option 3: JSON Schema (standard, heavy),
   TOML with simple types (AOS-native, limited), or Nix types (eval-time
   safe, non-portable)?
6. **Ignition enrichment.** Should AOS extend its Ignition handling to mark
   files secret (force `0600`), declare a schema, or pull config from a
   registry without baking it into instance metadata?
7. **Registry scope.** Does the registry stay packages-only, or grow to serve
   config schemas (Option 3 partial) or per-instance config + audit (Option 5)?
8. **Backward compatibility.** k3s expects `/etc/rancher/k3s/k3s.env` today.
    If the model shifts, keep the old path as a fallback, migrate to a
    per-package path, or support both? (Ties to [activation.md](activation.md).)

---

**DECISION: RESOLVED (direction) — signed off 2026-06.** Secrets for **workload
(isolated) packages** use **TPM2-sealed systemd credentials** with a **signed-PCR
(PCR 11 / UKI) policy** (see *Recommended direction*), provisioned at first boot
via SMBIOS OEM strings rather than the cmdline. The earlier "do not settle on
credstore" caution was about not foreclosing *while AOS lacked a credential
backend* — that backend now exists (RFC-0006), so the caution is satisfied. k3s
and other **host-privileged infrastructure** packages keep the plain
Ignition-file + bind-mount path (Option 2/6); a single mechanism need not serve
both shapes. Structured config rides an apm artifact + manifest-declared schema;
simple/non-secret config stays on `EnvironmentFile=`.

Remaining follow-up work (not decisions): complete the full-init nspawn handoff
test if nspawn returns to scope, decide whether credential read audit is needed,
and keep [apm-integration.md](apm-integration.md),
[container-model.md](container-model.md), and the TPM substrate in
[../0006-secure-boot/README.md](../0006-secure-boot/README.md) aligned as the
first packages exercise the model.
