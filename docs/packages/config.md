# Configuration delivery to packages (OPEN design)

Status: planning

> **DECISION: TBD.** This document does **not** pick a config-delivery
> mechanism. It surveys the option space, maps each option against a fixed
> set of criteria, and records the open questions. **Do not read a winner
> into this doc.** In particular, do **not** treat systemd credentials /
> credstore as the chosen path — it is one option among several, with real
> gaps (no credential backend exists in AOS today).

This is one of the package docs. Siblings:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[migration.md](migration.md), [open-questions.md](open-questions.md).

> **Unified model.** Every package is a systemd-nspawn container; what differs is
> *privilege*, declared in a signed `[permissions]` manifest (see
> [permissions.md](permissions.md)). So config delivery **always** crosses the
> nspawn host→container boundary — there is no "host-gated, not a container"
> shape. k3s is a high-privilege container (host network, host paths), which is
> why its config naturally arrives as host paths bound into a nominal container
> rather than injected across an isolation boundary.

## Summary

A "package" is the registry-installable unit (`apm install`); some packages
additionally expose a systemd-nspawn container and an `aos-pkg-<name>.target`
handle (see [container-model.md](container-model.md)). Every such package
needs configuration — non-secret settings (node IP, feature flags, a join
URL) and secrets (a join token, a TLS key) — delivered to the workload, and
for containerized packages that delivery must **cross the nspawn host→container
PID1 boundary**. This doc surveys six delivery mechanisms against six criteria
(boundary crossing, reloadability, secret-safety, per-instance override,
introspection, maturity), grounds each in what AOS ships today, and is honest
about where nothing fits well yet (hot-reload is uniformly weak; k3s wants
host-shared paths, not isolation). The decision stays open.

## What we have today (the k3s baseline)

The current, working config path for k3s is plain and worth stating exactly,
because every option below is measured against it.

k3s reaches config via a systemd `EnvironmentFile`, and the file is written
by Ignition at first boot. From `modules/roles/kubernetes/k3s-worker.nix`
(soon `modules/packages/...`, see [migration.md](migration.md)):

```nix
serviceConfig.EnvironmentFile = "/etc/rancher/k3s/k3s.env";
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
  expose systemd's credential system as a first-class module option. needs
  verification of exact scope.
- `pkgs/system/systemd.nix` controls the systemd build flags; whether
  credstore is compiled in **needs verification** before any credentials-based
  option can be costed.
- Ignition's files stage writes to `/run/etc/ignition-<gen>/etc/` in initrd,
  then those land under `/var/etc/*` in stage 2
  (`modules/services/ignition.nix`).

## The boundary that makes this hard

For a non-containerized package, config delivery is "write a file on the host,
point a unit at it" — the baseline. For a **containerized** package the
workload's PID1 is `systemd-nspawn`'s child, in its own mount namespace, and
the config has to cross from the host into that namespace. Concretely a host
unit launches the container roughly as:

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

Each option is described, then scored against the criteria in the matrix.
None is endorsed.

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
  `/etc/credstore/`. AOS has **no credential backend** (TPM/sealed/LUKS) today.
  needs verification of whether systemd here is even built with credstore.
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
  (a schema/validation module) plus an Ignition→apm bridge. needs design.

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

## Option matrix

Scoring: ✓ good · △ partial / caveated · ✗ poor. These are *relative*
positions to aid discussion, **not** a scorecard that names a winner.

| Criterion | 1 Credentials | 2 EnvFile+Ignition | 3 apm schema | 4 cmdline/SMBIOS | 5 registry-hosted | 6 /etc overlay |
|---|---|---|---|---|---|---|
| Boundary crossing (host→nspawn) | △ (needs systemd PID1) | ✓ | ✓ | △ (RO/global) | △ (2-step) | ✓ |
| Reloadability (no restart) | ✗ | ✗ | ✗ | ✗ | △ (push/poll) | ✗ |
| Secret-safety | ✓ (tmpfs/iso) | △ | △ | ✗ | ✓ (transport) | △ |
| Per-instance override | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Schema enforcement | ✗ | ✗ | ✓ | ✗ | ✓ | △ |
| Introspection | ✓ | ✓ | ✓ | ✓ | △ | ✓ |
| Offline / air-gapped | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ |
| Maturity / ecosystem | △ | ✓ | ✗ | ✓ | ✗ | ✓ |

Two honest patterns fall out of the matrix and are worth stating plainly:

- **Nobody hot-reloads.** Under today's systemd model every local option is
  read-once-then-restart. Only the registry-hosted option (5) has even a
  partial reload story, and it pays for it with a network dependency and a new
  trust boundary. If live config without restart is a requirement, **none of
  these options satisfies it as-is** — it becomes its own workstream (a
  watch-file reloader, or a registry push path).
- **At-rest secrecy is unsolved.** "Secret-safe" above is mostly about
  *runtime* isolation (who can read the live value), not *at-rest* encryption.
  AOS has no sealed/TPM/LUKS credential backend today, so every option stores
  secrets as plaintext on `/var` and leans on file permissions and mount
  namespaces. That gap is independent of which delivery mechanism wins.

## Where this does not fit: k3s

The boundary framing assumes config flows *into an isolated namespace*. k3s
violates the premise. As [container-model.md](container-model.md) spells out,
k3s is an **infrastructure** package: it wants the host network namespace,
host cgroups, host `/sys`, and global kernel modules. Its container is nominal.

For config that means k3s's natural shape is **host paths shared into a
nominal container**, not config injected across an isolation boundary:

- `/etc/rancher/k3s/k3s.env`, `/etc/rancher/k3s/config.yaml` are written on the
  host by Ignition and bind-mounted (rw or ro) into the nominal container —
  i.e. Option 2/6 in their simplest form.
- systemd credentials (Option 1) are an awkward fit here: they shine for an
  isolated full-init container with its own PID1, which is exactly *not* what
  k3s is. Using them for k3s would be ceremony without the isolation payoff.

So whatever the eventual decision for **workload** packages, k3s likely keeps
the plain Ignition-file + bind-mount path. A single mechanism may not serve
both "isolated workload" and "host-privileged infrastructure" packages equally
well, and the design should not pretend otherwise. needs verification of the
exact bind set k3s requires once the nominal container exists.

## Decision criteria

When the decision is eventually made, weigh options against these, roughly in
priority order. The right answer depends on which of these are hard
requirements vs. nice-to-haves — that prioritization is itself open.

1. **Clean boundary crossing.** Does config reach the container PID1 without
   special-casing per package? (Favors a clean bind or a credential.)
2. **Offline / air-gapped.** Must installs work with no config server
   reachable? If yes, Option 5 is out as a *primary* path.
3. **Secret handling.** What's the bar — runtime isolation only, or at-rest
   encryption too? The latter needs a backend AOS does not yet have, and is
   arguably orthogonal to the delivery choice.
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

## Open questions

1. **One mechanism or two?** Does AOS pick a single config path for all
   packages, or explicitly allow workload packages (isolated, maybe credentials)
   and infrastructure packages (k3s, host-shared files) to differ?
2. **Hot-reload — in scope for v1?** If yes, which shape: watch-file reloader,
   registry push, or a systemd reload path? If no, document restart-to-apply as
   the contract.
3. **Secrets at rest — required, and at which layer?** LUKS on `/var`,
   systemd sealed credentials (needs a backend), or app-level encryption in
   apm? This is potentially decoupled from the delivery mechanism.
4. **Is systemd built with credstore?** Verify `pkgs/system/systemd.nix` build
   flags before Option 1 can be seriously costed.
5. **Credential read audit.** Do we need to log which process read which
   secret? systemd credentials don't provide it natively; a registry/apm path
   could.
6. **nspawn config-share shape for k3s.** Host `/etc/rancher/k3s` bind-mounted
   rw into the nominal container, a copied-in isolated `/etc`, or a distinct
   path? (Ties to [container-model.md](container-model.md).)
7. **apm config schema format**, if Option 3: JSON Schema (standard, heavy),
   TOML with simple types (AOS-native, limited), or Nix types (eval-time
   safe, non-portable)?
8. **Ignition enrichment.** Should AOS extend its Ignition handling to mark
   files secret (force `0600`), declare a schema, or pull config from a
   registry without baking it into instance metadata?
9. **Registry scope.** Does the registry stay packages-only, or grow to serve
   config schemas (Option 3 partial) or per-instance config + audit (Option 5)?
10. **Backward compatibility.** k3s expects `/etc/rancher/k3s/k3s.env` today.
    If the model shifts, keep the old path as a fallback, migrate to a
    per-package path, or support both? (Ties to [migration.md](migration.md).)

---

**DECISION: TBD.** No option is selected. The next phase should pick the hard
requirements from the criteria above, resolve the open questions (especially
#1, #2, and #3, which can be decided independently of delivery), and only then
choose. Cross-link the outcome back into
[apm-integration.md](apm-integration.md) and
[container-model.md](container-model.md).
