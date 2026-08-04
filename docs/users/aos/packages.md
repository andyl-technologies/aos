# Manage packages with APM

`apm` consumes signed registry metadata and manages generation-based package
profiles. User packages, machine-wide runtime packages, and the OS sysroot are
separate scopes. The distinction is important: `--system` does not simply make
a normal user install global.

## Configure a trusted registry

Obtain the registry's Ed25519 trust key over an independent trusted channel,
then add and synchronize the registry:

```sh
apm registry add https://packages.example.com/index \
  --name acme \
  --trust-key 'acme:Ed25519:BASE64_KEY'

apm update --registry acme
apm search nginx --registry acme
apm show nginx --registry acme
apm info nginx --permissions
apm policy nginx
```

Signature verification fails closed by default. `--no-verify` exists for local
registry development; do not use it in normal installation or upgrade
procedures.

Registry configuration is layered:

| Path | Purpose |
| --- | --- |
| `/etc/apm` | Read-only registry and trust seed built into the image |
| `/var/lib/apm/config` | Writable machine-wide overlay |
| `~/.config/apm` | Per-user overlay with highest precedence |

Use `apm registry --system ...` for machine-wide changes. A registry seeded in
`/etc/apm` can be disabled at runtime, but removing it requires rebuilding the
image seed.

User and system scopes load different writable configuration. Before using the
same registry for machine-wide packages or OS generations, add it to system
scope unless the image already seeds it:

```sh
apm registry --system add https://packages.example.com/index \
  --name acme \
  --trust-key 'acme:Ed25519:BASE64_KEY'
apm update --system --registry acme
```

## Manage user packages

User scope is the default; there is no `--user` flag.

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

The desired format can also carry package configuration and credentials. APM
checks those inputs before mutating the package profile. Treat the file as
deployment configuration and protect any credentials it contains.

Machine-wide runtime package generations are stored separately from the OS:

```text
/var/lib/profiles/system-packages
```

## Distinguish a sysroot install

This command has a narrower meaning than its spelling suggests:

```sh
apm install aos --system --registry acme
```

It selects exactly one registry package marked `sysroot = true`, installs it as
an OS generation, and activates that generation. It is not the command for
installing an ordinary package globally.

Always preview a selected sysroot install:

```sh
apm install aos --system --registry acme --dry-run
apm install aos --system --registry acme --yes
```

The sysroot profile is:

```text
/var/lib/profiles/system
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

## State and cache paths

| State | User scope | System scope |
| --- | --- | --- |
| Profile | `/var/lib/profiles/per-user/$USER` | Runtime packages: `/var/lib/profiles/system-packages`; OS: `/var/lib/profiles/system` |
| Registry clones | `~/.local/share/apm/registries` | `/var/lib/apm/registries` |
| Synchronized metadata | `~/.local/share/apm/remote` | `/var/lib/apm/remote` |
| NAR and cache data | `~/.cache/apm` | `/var/lib/apm/cache` |
| Writable trust pins | `~/.config/apm/trusted-keys.d` | `/var/lib/apm/trusted-keys.d` |

Use `apm --json ...` when consuming package results in automation. Normal
human-facing output is not a stable machine interface.
