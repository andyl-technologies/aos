# Provisioning without Ignition: systemd-native substrate + the `aos metadata` agent

This document specifies the removal of Ignition and its replacement by
(a) systemd-native substrate provisioning (`systemd-repart`, `systemd-cryptenroll`/
`cryptsetup`, `systemd-tmpfiles`, `systemd-sysusers`), (b) an `aos metadata`
agent that owns cross-cloud user-data acquisition, and (c) a clean separation of
**idempotent** (reconciled every activation) from **one-shot** (run-once,
destructive) operations. The provisioning *orchestration* — compiling the eval
output into a systemd unit graph — is in [`orchestration.md`](orchestration.md).

## Why Ignition can go

Ignition does two separable jobs, and systemd already does all but one of them:

- **Substrate provisioning** (disks/filesystems/LUKS/mount) and **host config**
  (files/units/users/networking) — every one of these has a systemd-native
  equivalent, several of them strictly better for an image-based A/B system.
- **Cross-cloud user-data/metadata acquisition** — the *only* capability
  Ignition uniquely brings, and the `aos` CLI can own it.

Grounding: in `modules/services/ignition.nix`, **only four units actually shell
out to the Ignition binary** — `ignition-fetch`, `ignition-disks`,
`ignition-mount`, `ignition-files`. Everything else in the chain (`mount-var`,
`nix-overlay-setup`, `etc-overlay-setup`, `aos-machine-id`, `aos-seed-profiles`,
`aos-growfs`, `aos-gpt-relocate`, `run-etc-setup`, `cryptswap`, the whole
`aos-var-crypt` LUKS path in `modules/base/secure-boot.nix`) is already
hand-written systemd. So removing Ignition is **deleting four shell-outs plus
the JSON config engine**, not a rewrite. The LUKS `/var` seal (RFC-0006) is
already `systemd-cryptenroll`/`systemd-cryptsetup` and is untouched.

## Action mapping: Ignition → systemd-native

| Ignition action (today) | systemd-native replacement | Lifecycle |
|---|---|---|
| Carve `root-b`/`swap`/`var`, wipe table | **`systemd-repart`** `repart.d/*.conf` | **idempotent** — adds only missing partitions, grows growable |
| Filesystem creation on new partitions | repart `Format=` | **idempotent** — formats only freshly-created partitions |
| `aos-growfs` (ext4 grow) | repart `SizeMaxBytes` + `resize2fs` | **idempotent** — recomputed every boot; **delete `aos-growfs`** |
| `aos-gpt-relocate` (`sgdisk -e`) | repart rewrites GPT incl. backup header on grow | **idempotent** — **delete `aos-gpt-relocate`** |
| `storage.files` (`/etc/*`, links) | eval → manifest → composefs `/etc` lower + `systemd-tmpfiles` | **idempotent** — per-gen overlay swap; tmpfiles convergent |
| dirs/symlinks/perms | `systemd-tmpfiles` (`d`/`L`/`z`) | **idempotent** |
| `passwd` (users/groups) | `systemd-sysusers` (substrate) + manifest-rendered `/etc/passwd` | **idempotent** — sysusers adds missing only |
| hostname/locale | manifest-rendered `/etc/hostname` (preferred) or `systemd-firstboot` | **guarded-one-shot** (firstboot) / **idempotent** (rendered) |
| LUKS format + key for `/var` | **already** `aos-var-crypt` + `systemd-cryptenroll`/`cryptsetup` | **guarded-one-shot** format/enroll; **idempotent** unlock |
| encrypted swap | **already** `cryptswap.service` | **idempotent** unlock |
| **fetch** user-data | **`aos metadata` agent** + networkd DHCP | **idempotent** fetch |
| platform detect | `aos metadata detect` (absorbs `aos-platform-detect`) | **idempotent** |

### Build changes this requires

- `pkgs/system/systemd.nix`: flip `-Drepart=disabled → enabled` and
  `-Dfdisk=disabled → enabled` (repart links `libfdisk` from the already-built
  `util-linux`). `-Dsysusers`/`-Dtmpfiles` are already `true`; tpm2/cryptsetup
  already wired.
- `modules/base/_initrd-builder.nix:651`: remove `systemd-repart` from the
  initrd strip-list (leave `systemd-firstboot` stripped unless adopted for
  hostname).
- Delete the units `ignition-{fetch,disks,mount,files}`, `aos-growfs`,
  `aos-gpt-relocate`, and the closure entries `pkgs.ignition`, `pkgs.butane`,
  `lib/formats/ignition.nix`.

## The idempotent / one-shot principle

State it as a hierarchy, in order:

1. **Prefer convergent tools.** `systemd-repart`, `systemd-tmpfiles`,
   `systemd-sysusers`, and `cryptsetup` *attach* are idempotent **by
   construction**: they compute the delta between declared and observed state
   and apply only what is missing. A unit built on them needs **no guard** —
   running it twice equals running it once. This is the default and covers ~90%
   of substrate (all partition carving, all filesystem growth, all
   dir/perm/symlink creation, all user/group seeding).

2. **Guard only genuinely-destructive, genuinely-once operations** — a
   `luksFormat` that wipes a partition, an initial `mkfs`, a TPM enrollment that
   consumes a bootstrap key — because re-running them *destroys data*. Guard so
   they physically cannot re-run, **preferring a state probe over a marker**
   (a probe interrogates real on-disk state; a marker is a fallible proxy):
   - a **destructive-op probe** (`cryptsetup isLuks`, `blkid || mkfs`,
     `mountpoint -q`) — this is what `aos-var-crypt` already does and is the
     load-bearing guard;
   - `ConditionFirstBoot=yes` for substrate-identity ops (sysusers/firstboot);
   - `ConditionPathExists=!/var/lib/aos/.provisioned-<x>` only when no natural
     probe exists;
   - `RemainAfterExit=yes` so the oneshot is not re-run within a boot.

3. **Never guard a convergent op.** `ConditionFirstBoot=` on `systemd-repart` or
   `systemd-tmpfiles` is an anti-pattern — it defeats reconciliation (a disk
   that should grow later, an `/etc` dir to recreate after a tmpfs reset, a
   partition added by a later image would never appear). Convergent ops *want*
   to run every boot.

The canonical guarded-destructive unit (mirroring `aos-var-crypt`):

```ini
[Unit]
Description=Initialize /var filesystem (first time only)
DefaultDependencies=no
After=systemd-repart.service          # repart carved the partition (idempotent)
Before=mount-var.service
ConditionPathExists=/dev/disk/by-partlabel/var   # cheap pre-filter only
[Service]
Type=oneshot
RemainAfterExit=yes
# The load-bearing guard is the self-probe, not the Condition:
ExecStart=/bin/sh -c 'blkid /dev/disk/by-partlabel/var >/dev/null 2>&1 || mkfs.ext4 -qF -L var /dev/disk/by-partlabel/var'
```

### How a Nix module represents each class

A config module **never imperatively performs** an operation; it declares
**desired state**, and the materializer renders it to a systemd unit whose guard
encodes the lifecycle:

- **One-shot/destructive** (a privileged substrate-owning module):
  `storage.disks."nvme0n1".partitions = [ … ]` / `storage.luks."data" = { … }`
  → renders a `repart.d` drop-in (idempotent) **plus** any destructive step as
  `Type=oneshot` + `RemainAfterExit` + a state-probe/`ConditionFirstBoot` guard,
  **outside** the per-activation reconcile set. Re-running activation never
  re-formats.
- **Idempotent** (a normal config option): `nginx.virtualHosts."x".root = …`
  → renders into `manifest.etc["nginx/nginx.conf"]` + `manifest.units["nginx.service"]
  = { action = "reload"; }`, **inside** the reconcile loop, diffed and applied on
  **every** activation by `activate.sh.in` (re-applying an unchanged manifest is
  a byte-identical no-op).

This is exactly the existing `activate.sh.in` model: it already treats the
`/etc` swap + daemon reconcile as idempotent and never touches disks.

## Convention substrate — zero-config cloud VM

The common cloud VM (boot disk grown to volume size, ext4 or TPM-LUKS `/var`,
swap) needs **zero per-host input**. Ship baked-in `repart.d` drop-ins in the
image/initrd (`/usr/lib/repart.d/`):

```ini
# 50-var.conf — create /var and GROW it to fill the disk
[Partition]
Type=var                 # GPT 'var' type, auto-discovered by the /var mount
Label=var
SizeMinBytes=4G
Weight=1000              # soak up all remaining space (grow-on-boot)
# Non-measured boot: Format=ext4 here (convergent).
# Measured boot: OMIT Format= — leave raw so aos-var-crypt does the LUKS2
#   signed-PCR-11-policy seal (RFC-0006); repart only carves+grows.
```

repart's `Weight=` grow makes `var` expand to whatever disk the image was
`dd`'d onto — replacing both `aos-growfs` *and* `aos-gpt-relocate` — and runs
every boot idempotently (no-op once at target size). The image still ships only
ESP + root-a (`modules/image/_builder.nix:260-262`); repart carves the rest on
first boot with no operator config and no user-data.

**First-boot substrate is image-only; host.nix cannot drive it (review
M-repart-order / M-repart-locus).** `systemd-repart` runs in the **initrd**
(everything downstream — mount-var → nix-overlay → seed → switch_root — needs
`/var` carved first), but `host.nix` is fetched transport-only in initrd and only
**evaluated in stage-2**, *after* substrate. So operator `repart.d` fragments
derived from `host.nix` can neither be verified nor even be present in time for
the first-boot repart run. Two consequences, both required:

- **First boot carves only the image-baked `/usr/lib/repart.d` convention**
  (idempotent, no operator input, no unverified destructive partitioning).
- **Custom topologies are a two-boot flow:** the stage-2 eval persists
  operator-declared `repart.d` fragments to a known location on `/var`; on the
  *next* boot the initrd repart run reads them (now operator-signed-and-verified,
  since they came from a verified `host.nix`). Genuinely exotic layouts (ZFS) use
  a dedicated guarded-one-shot unit. **A custom partition layout never takes
  effect on first boot, and destructive substrate never runs from unverified
  input.**

## The `aos metadata` agent

The one Ignition-unique capability — reading cross-cloud user-data + instance
metadata — moves to an `aos metadata` agent (a Rust subcommand + an initrd
systemd service). The user-data **payload is the operator's literal `host.nix`**
(plus a detached signature), not Ignition JSON.

### Transport-only in initrd; trust deferred to stage-2

The `trusted-config-keys.d` operator keys (RFC-0011 D14) live in the **measured
`/etc` that is only assembled in stage-2**, not initrd. Therefore the initrd
agent is **transport-only**: it fetches and stashes the *untrusted* bytes, and
**signature verification happens in stage-2 `aos-eval.service`** where the trust
anchors and the existing `apm verify` machinery are natively available. This
preserves the measured-consumer property (a failed/missing signature ⇒ no
`/run/aos-eval/host.nix` ⇒ `aos-eval` falls through to gen-0-only config — the
failure-safe path).

```text
aos metadata detect    # DMI/SMBIOS → /run/aos-metadata/platform.env (+ need-network)
aos metadata fetch     # platform → /run/aos-metadata/{host.nix, host.nix.sig, facts.json}
```

Stash contract (a child of initrd `/run`, surviving `mount --move /run /sysroot/run`):
`/run/aos-metadata/{platform.env, host.nix, host.nix.sig, facts.json,
.metadata-result.json}`, then staged into the evaluator root `/run/aos-eval/`.

Reuses: `aos-net` (HTTP/IMDS, retry) for fetch; `aos-package/src/security.rs`
`verify_payload_signature` (SSHSIG) + `TrustStore` (pointed at
`trusted-config-keys.d`) for the stage-2 check; `aos-package/src/sshkey.rs`.

### Literal-Nix payload + URL-pointer

user-data is **either** the inline `host.nix` source **or**, when it exceeds the
platform cap (AWS 16 KB), a tiny pointer `{ host_nix_url, sha256, sig_url }`. The
agent fetches the URL, checks the `sha256` content-pin (integrity before
authenticity), and stashes payload + detached SSHSIG. The two checks are
independent: the pin defends the fetch, the signature defends authenticity
(verified in stage-2).

### Platform parity surface (the honest cost)

The offline/local transports are small and AOS already owns half of them; the
real surface is the cloud IMDS zoo:

| Platform | user-data | quirk |
|---|---|---|
| AWS | IMDSv2 token `PUT` → `GET /latest/user-data` | **token dance mandatory**; 16 KB cap → pointer |
| GCP | `…/attributes/user-data`, header `Metadata-Flavor: Google` | header mandatory |
| Azure | OVF ISO `CustomData` **and** IMDS `/compute/userData`; wireserver "ready" | **dual-channel; heaviest** |
| OpenStack | config-drive `config-2` ISO **or** IMDS | `network_data.json` is metadata-delivered net |
| DigitalOcean | IMDS `/metadata/v1/user-data` (plain) | static IP often via metadata, not DHCP |
| Hetzner/Vultr/Scaleway/Oracle | per-vendor IMDS paths (Oracle needs `Bearer`) | bespoke endpoints |
| NoCloud/config-drive | ISO `cidata`/`config-2`: `user-data`+`meta-data` | **closest to AOS's `aos-metadata` ISO** |
| QEMU fw_cfg | `/sys/firmware/qemu_fw_cfg/.../opt/com.coreos/config` | already used by AOS fleet |
| bare-metal/PXE | kernel cmdline `…config.url=` | the pointer escape hatch |

### Instance facts → `host.facts.*`

Instance facts (SSH authorized keys, hostname, MAC→interface map, disk IDs) flow
in **only** as typed `host.facts.*` declared inputs (D9), rendered from
`facts.json` into `/run/aos-eval/host-facts.nix` — they land in the manifest,
are typed/assertable, and keep eval a pure function of `(modules + host.nix +
facts)`. Facts are a **recorded but unauthenticated** input (`facts_hash` in the
manifest `inputs` + the attestation record — see
[`trust-and-secrets.md`](trust-and-secrets.md)); they must never carry a security
decision the operator did not authorize. The agent does **not** write
`/etc/hostname` or `authorized_keys` imperatively; those are manifest outputs so
they participate in generations/rollback.

> **No pre-verification SSH keys from the facts channel (review M-gen0key).** An
> earlier draft seeded `host.facts.ssh_authorized_keys` into `/var/etc` in initrd
> for gen-0 reachability. That is **removed**: those keys come from
> *unauthenticated* IMDS and would be applied *before* the stage-2 `host.nix`
> signature check — letting an attacker who can answer IMDS plant a login key.
> Gen-0 reachability, if required before the first config-gen activates, comes
> **only** from an image-baked key or one carried in the operator-signed
> `host.nix` (verified before use), never from the platform facts channel.

**Networking on DHCP-less clouds (review M-static-ip).** On clouds with no DHCP
server, where networking is delivered as metadata (DigitalOcean static/anchor
IPs, OpenStack `network_data.json`), the gen-0 DHCP seed gets no lease, so stage-2
would have **no route to the registry** and eval could never fetch the config
modules — a permanent deadlock. So the **initrd `aos metadata` agent parses the
platform network config and seeds a minimal static `networkd` config into the
gen-0 `/var/etc` lower** (a substrate fact, like the IP itself — not operator
config), giving stage-2 a route without DHCP. The operator's *declared* network
config in `host.nix` still takes effect at the first `activate.sh.in` swap and
supersedes the seed.

### Implementation: reuse surface

The agent is **not** a 1:1 Go→Rust port of Ignition. Ignition's fetch code is
~90% generic plumbing (HTTP, retry, encoding, signature, label/mount) wrapping a
thin per-platform knowledge layer (endpoint, header, label, format). The
plumbing already exists in aos crates; the knowledge layer is re-encoded from
each provider's documented spec, not translated from Ignition source.

| Capability | Verdict | Where |
|---|---|---|
| HTTP GET/**PUT** + custom headers + plain-`http://` to IMDS | **reuse** | `aos-net` `TransferEngine` (`transfer.rs:61`) + `HttpProtocol` (`protocol/http.rs:26`), `TransferRequest::with_header` (`types.rs:218`); general, not registry-specific |
| Retry / backoff | **reuse** | `aos-net/retry.rs` `RetryConfig` + `with_retry` (exponential + jitter); engine auto-retries transient errors |
| Detached SSHSIG over `host.nix` | **reuse** | `security.rs:639` `verify_payload_signature` + `KeyStore` (`:73`) + `sshkey.rs`; point a `KeyStore` at `trusted-config-keys.d` (stage-2) |
| base64 / gzip / JSON / TOML | **reuse** | `base64 0.22`, `flate2`, `serde_json`, `toml` already in `Cargo.lock` |
| CLI + initrd-service wiring | **reuse pattern** | clap variant in `crates/aos/src/cli/mod.rs`, impl `commands/metadata.rs`, dispatch in `main.rs`; `boot.initrd.systemd.services` |
| **Config-drive mount** (`blkid -L`, ISO9660/vfat: `cidata`/`config-2`/`aos-metadata`) | **BUILD — the one real gap** | no Rust today; existing logic is Nix shell handling only the single `aos-metadata` label (`pkgs/boot/aos-platform-detect.nix:51`). Shell out to `pkgs.util-linux` `blkid`/`mount` or bind libblkid |
| YAML (`meta-data`, cloud-config) | **BUILD (vendor)** | no YAML crate in the lock — vendor one |
| Request timeout | **BUILD (shim)** | `aos-net`'s client is a process-wide singleton with only a 10s `connect_timeout` and `HttpProtocol::with_client` isn't wired through the engine; wrap IMDS calls in `tokio::time::timeout` |
| DMI/SMBIOS + fw_cfg detection | **reuse knowledge, thin reader** | the vendor/asset-tag→platform table already exists (`pkgs/boot/aos-platform-detect.nix:64-123`) — verbatim port into `std::fs` reads |
| Per-platform fetchers | **BUILD (thin)** | AWS IMDSv2 PUT-token→GET, GCP `Metadata-Flavor`, Azure `Metadata:true`+base64, OpenStack/DO/Oracle — thin orchestration over `TransferEngine`+`with_header`+`RetryConfig`, behind a `PlatformFetcher` trait, recorded-fixture tested off-box |

**Genuinely-new code** is therefore small and bounded: the config-drive mount
helper (the only capability with no aos primitive), a vendored YAML crate, a
`tokio::time::timeout` shim, and the per-platform fetchers (facts-from-docs over
existing plumbing). Phase B (offline channels) is mostly the mount helper + the
DMI port; Phase C (cloud IMDS) is the per-platform fetchers — neither blocks the
other.

**Not reusable (registry-specific — do not chase):** `AuthStore::refresh_token`
(OAuth2 for registry tokens, `auth.rs:219`) and `AuthStore`'s per-domain model
(use per-request `with_header` for IMDS); the git-object signature paths
(`verify_commit_signature`/`verify_tag_signature`/`check_downgrade`); the S3/SFTP
protocol handlers (scheme dispatch ignores them).

## Phasing (do not big-bang; keep an Ignition-compat fallback)

- **Phase A — keep Ignition for fetch, change the payload.** Land the stage-2
  on-host eval (the novel part) with Ignition still fetching, but its config
  does nothing but `storage.files` the operator's `host.nix` + sig into
  `/run/aos-metadata/`. The literal-Nix model works immediately through
  Ignition's `file` write.
- **Phase B — `aos metadata` for the channels AOS already exercises.** Ship
  `aos metadata detect` (pure win — already AOS code) + `fetch` for the
  offline/local transports AOS tests (the `aos-metadata` ISO, NoCloud,
  config-drive, fw_cfg). Run alongside Ignition; use its payload if present,
  else fall back. De-risks the cutover with a fleet-green gate.
- **Phase C — cloud IMDS in `aos metadata`; retire Ignition.** Implement AWS
  IMDSv2, GCP, DigitalOcean, OpenStack-IMDS behind per-platform fetcher traits
  with recorded-fixture tests. Keep Azure-OVF, VMware-guestinfo, and the
  long-tail vendors as the last Ignition fallback until each has a native
  fetcher + a real test. Remove `pkgs.ignition`/`pkgs.butane`/
  `lib/formats/ignition.nix` only when the fallback is unused.

Rationale: the eval engine is the RFC's actual novelty and risk; Ignition's
fetch layer is mundane but broad. Decoupling them (payload-change → transport-swap
→ per-platform-incremental) means an untested IMDS path never blocks the eval
work, and the parity cost (AWS token dance, Azure dual-channel) is paid down
incrementally behind a working fallback.
