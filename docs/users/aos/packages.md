# Manage packages with APM

`apm` consumes signed registry metadata and manages generation-based package
profiles. User packages, machine-wide runtime packages, configuration
generations, and A/B image generations are separate scopes. The distinction is
important: `--system` does not simply make a normal user install global.

## Configure a trusted registry

Obtain the registry's Ed25519 trust key over an independent trusted channel,
then add and synchronize it in the system scope used by supported host
operations:

```sh
apm registry --system add https://packages.example.com/index \
  --name acme \
  --trust-key 'acme:Ed25519:BASE64_KEY'

apm update --system --registry acme
apm search nginx --system --registry acme
apm show nginx --system --registry acme
apm info nginx --system --permissions
apm policy nginx --system
```

When a registry's package closures are served from a separate binary-cache
route, declare that bootstrap endpoint with the registry in image policy or
authenticated `host.nix`. This makes the cache available during the same
configuration transaction that first selects packages from the registry:

```nix
{
  aos.apm.registries.acme = {
    url = "https://packages.example.com/index";
    trustKeys = ["acme:Ed25519:BASE64_KEY"];
    caches = [
      {
        url = "https://cache.example.com";
        priority = 100;
      }
    ];
  };
}
```

The bootstrap list supplements the signed `[caches]` stack committed in
`registry.toml`; normal cache selection merges and de-duplicates both sources.

Signature verification fails closed by default. `--no-verify` exists for local
registry development; do not use it in normal installation or upgrade
procedures.

## Understand verification and attestation boundaries

Secure Boot, package admission, and runtime attestation are connected trust
layers, not one signature check:

1. APM verifies the registry's signed release and walks its `store/`
   realisation graph. Every member of the selected Nix closure must match a
   blessed NAR hash. The Hub or cache transports bytes but is not trusted to
   choose their content.
2. Secure and measured boot cover the firmware state, UKI, boot inputs, and the
   dm-verity root hash of the immutable image through PCRs 7, 11, and 12. A
   package fetched after that image was built is not retroactively part of PCR
   11.
3. When APM activates the machine-wide exposed package set, it extends PCR 15
   for every explicitly installed package with `expose` metadata using
   `H(name || version || root-digest || manifest-digest)`. A TPM quote over
   PCRs 7, 11, 12, and 15 therefore binds that activated package identity and
   privilege manifest to the measured boot state. The verifier replays
   `/run/log/aos-packages.cel` and checks each tuple against the signed registry
   catalog.

This PCR-15 path does not emit one event for every object that happens to be in
`/nix/store`. User-profile packages, downloaded but inactive packages, and
implicit closure members are not individually measured package identities;
their downloaded bytes remain covered by the signed realisation graph. For
block-by-block runtime integrity, an exposed workload must use its signed
dm-verity `RootImage=`. A non-verity store-backed workload has authenticated
admission and an attested package identity, but not dm-verity enforcement of
its live payload bytes.

See [Secure an AOS host](security.md#understand-verified-boot-status) for the
image and generation chain, and
[Verify runtime attestation evidence](cli.md#verify-runtime-attestation-evidence)
for quote verification.

Registry configuration is layered:

| Path | Purpose |
| --- | --- |
| `/etc/apm` | Read-only registry and trust seed built into the image |
| `/var/lib/apm/config` | Writable machine-wide overlay |
| `~/.config/apm` | Per-user overlay with highest precedence |

Use `apm registry --system ...` for machine-wide changes. A registry seeded in
`/etc/apm` can be disabled at runtime. To remove its effective definition, a
trusted host configuration can materialize an empty higher-precedence
`registries.d/<name>.toml` during generation activation; rebuilding without the
seed is the other option.

User and system scopes load different writable configuration. A user-scope
registry does not configure machine-wide packages, configuration generations,
or image generations.

## Manage user packages

User scope is the default; there is no `--user` flag. Stock images do not yet
provision writable per-user APM configuration, a per-user profile directory, or
unprivileged Nix-store mutation. The commands in this section require an
account whose writable XDG directories and
`/var/lib/profiles/per-user/$USER` have been provisioned by the operator. Use
the system-scope desired-package workflow on a stock host.

```sh
apm install nginx --registry acme --dry-run
apm install nginx --registry acme

apm list --installed
apm files nginx
apm depends nginx
```

Installed executables are under:

```text
/var/lib/profiles/per-user/$USER/current/bin
```

That directory is not added to the default shell `PATH`. Invoke a binary by its
full path or configure the profile path in the user's shell environment:

```sh
export PATH="/var/lib/profiles/per-user/$USER/current/bin:$PATH"
```

Refresh metadata before checking for upgrades:

```sh
apm update
apm list --upgradable
apm upgrade --dry-run
apm upgrade
```

`apm update` synchronizes metadata; it does not install packages. `apm upgrade`
uses the already-synchronized metadata and does not update it implicitly.

Remove a package after reviewing the dependency plan:

```sh
apm remove nginx --dry-run --autoremove
apm remove nginx --autoremove
```

Hold and unhold keep a package out of ordinary upgrade selection:

```sh
apm hold nginx
apm unhold nginx
```

Install, remove, and upgrade create numbered profile generations. Rollback
repoints `current` to an existing generation:

```sh
apm rollback --list
apm rollback --generation N --dry-run
apm rollback --generation N
```

## Manage machine-wide packages

Ordinary machine-wide packages are reconciled from an authoritative desired
file. Create `desired.toml`:

```toml
packages = ["nginx", "curl"]
```

Preview and apply the complete set:

```sh
apm update --system
apm install --system --from ./desired.toml --dry-run
apm install --system --from ./desired.toml --yes
```

The explicit update makes the preview predictable: dry-run never refreshes
metadata. When applying additions, reconciliation also attempts an update and
falls back to cached metadata with a warning if that update fails. A change
with no additions does not refresh metadata.

The list is declarative. Explicit packages omitted from the next file are
removed during reconciliation, including packages made unreachable by that
change. To remove `nginx`, delete it from `packages` and run the same command
again. There is no `apm remove --system` command.

The desired format can also carry package configuration and credential input.
APM checks those inputs before mutating the package profile. Prefer systemd
system-credential references; if a separately managed desired file contains
bytes, protect it as secret state. Evaluated `host.nix` contains only opaque
`secretRef` handles, never those bytes.

Machine-wide runtime package generations are stored separately from the OS:

```text
/var/lib/profiles/system-packages
```

Prune old machine-wide package and configuration generations together with:

```sh
apm clean --system --generations --keep 3
apm gc
```

The latest keep window and the active generation of each independent profile
are retained. Image generations are not affected.

## Understand service confinement

Runtime confinement applies to systemd services that a package publishes
through its `expose` contract. A package without `expose` has no APM-managed
service to activate, and directly running an executable from a package profile
does not place that process in the service sandbox.

For an exposed service, an empty or omitted permission manifest selects the
least-privilege defaults: a package-private root and temporary directories, a
private network and user identity, an empty capability set, restricted devices
and system calls, and the generated Landlock and systemd hardening policy.
Requested permissions widen that boundary. Root-equivalent grants such as
`CAP_SYS_ADMIN`, privileged users, or writable system locations cause APM to
label the package `unconfined` instead of presenting it as sandboxed.

Inspect the signed declaration and the host-policy decision before activation:

```sh
apm info PACKAGE --system --permissions
apm policy PACKAGE --system
```

Confinement limits what an activated service can do; it does not establish that
the package or its registry is trustworthy. Registry signatures authenticate
the authorized publisher and exact content, not whether that content is benign.
Bootstrap and operate registry trust independently as described in
[Manage registry trust and incidents](../registry/trust.md).

## Distinguish a sysroot install

This command has a narrower meaning than its spelling suggests:

```sh
apm install aos --system --registry acme
```

It selects exactly one registry package marked `sysroot = true`, verifies its
authenticated OTA payload, and stages it as the next A/B image generation. It
is not the command for installing an ordinary package globally, and it does not
replace the running root before reboot.

Always preview a selected sysroot install:

```sh
apm install aos --system --registry acme --dry-run
apm install aos --system --registry acme --yes
```

Image and configuration state are separate:

```text
/var/lib/profiles/image    A/B image generations
/var/lib/profiles/system   configuration generations
```

For ordinary OS rollout, use the controlled update and rollback procedure in
[Upgrade and roll back a host](upgrades.md).

## Confirmation and safety controls

Install, remove, and user-package upgrade operations prompt before mutation
unless `--yes`, `[settings].assume_yes`, or `--dry-run` applies. System upgrade
and rollback have their own behavior; lead automation with `--dry-run` rather
than relying on a prompt.

The sysroot lock prevents a runtime package from diverging from dependencies
owned by the active OS. `--ignore-sysroot-lock` bypasses that protection and is
for targeted recovery, not routine package management. Prefer a specific
package name over the `all` form when a recovery procedure requires it.

## Default state and cache paths

| State | User scope | System scope |
| --- | --- | --- |
| Profile | `/var/lib/profiles/per-user/$USER` | Runtime packages: `/var/lib/profiles/system-packages`; configuration: `/var/lib/profiles/system`; image: `/var/lib/profiles/image` |
| Registry clones | `~/.local/share/apm/registries` | `/var/lib/apm/registries` |
| Synchronized metadata | `~/.local/share/apm/remote` | `/var/lib/apm/remote` |
| NAR and cache data | `~/.cache/apm` | `/var/lib/apm/cache` |
| Writable trust pins | `~/.config/apm/trusted-keys.d` | `/var/lib/apm/trusted-keys.d` |

Use `apm --json ...` when consuming package results in automation. Normal
human-facing output is not a stable machine interface.

User XDG paths honor the corresponding `XDG_*` variables. Test and recovery
environments can also redirect roots with `AOS_ROOT`, `AOS_PROFILE_ROOT`, and
the documented system-config override.
