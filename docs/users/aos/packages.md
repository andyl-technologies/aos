# Manage packages with APM

Use `apm` to find, install, update, and remove software on your AOS host. Give
it package names; APM downloads the packages and installs the dependencies
they need to work.

## Personal packages

By default, `apm` manages packages for your own account. Each user has a
separate package profile, so installing, upgrading, or removing your packages
does not change another user's selection. Users can keep different package
versions when needed.

Package builds and their dependencies live in the shared `/nix/store`. Users
and the machine-wide profile reuse identical store paths instead of keeping
separate installed copies. Different versions or builds can coexist; each
profile selects the packages available in its environment. Registry metadata
and download caches remain separate for each scope.

Before using personal installs, ask your administrator to enable the multi-user
Nix daemon, authorize the package signing keys it accepts, and provision your
writable XDG directories and `/var/lib/profiles/per-user/$USER` profile. The
following commands assume that account setup is complete.

You do not need `sudo` for personal installs. APM asks the daemon to import
signed packages into the protected shared store, then updates your own profile.
The daemon checks signatures against administrator-configured keys; adding a
personal registry does not authorize its signing keys for the whole machine.
See [Enable personal package installs](#enable-personal-package-installs) for
administrator setup.

## Find packages

First refresh the package lists so APM knows what is available:

```sh
apm update
```

This downloads package information from your configured registries. It does
not install or upgrade anything.

Search by name or description, then inspect a package:

```sh
apm search curl
apm show curl
```

Use `apm policy curl` to see available versions and their registries.
To add a registry or select a different source, see
[Configure package registries](registries.md).

## Install packages

Install a package by name:

```sh
apm install curl
```

You can install several packages in one command:

```sh
apm install curl jq
```

APM shows the planned changes and asks for confirmation. Dependencies are
installed automatically. Installing named packages keeps unrelated packages
already installed in your profile.

To review the plan without making changes, add `--dry-run`:

```sh
apm install curl --dry-run
```

To choose a particular registry, add `--registry NAME`. For unattended use,
`--yes` skips the confirmation prompt; review the plan before using it.

Installed programs are available on the login session's `PATH`, with your
personal packages ahead of machine-wide packages. To inspect
what is installed and which files a package supplies:

```sh
apm list --installed
apm files curl
apm depends curl
```

For packages that expose services, see
[Understand the package sandbox](package-sandbox.md) and the package's generated
configuration reference, available through `apm docs` and `apm options`.

## Upgrade packages

Refresh the package lists, check which packages have newer versions, then
upgrade:

```sh
apm update
apm list --upgradable
apm upgrade --dry-run
apm upgrade
```

`upgrade` uses the package lists you last downloaded; it does not refresh them
itself. To upgrade only selected packages, supply their names:

```sh
apm upgrade curl jq
```

To keep a package at its installed version during ordinary upgrades, hold it.
Remove the hold when you are ready to upgrade it:

```sh
apm hold curl
apm held
apm unhold curl
```

These commands update runtime packages. To update the operating-system image,
use `apm image upgrade` as described in
[Upgrade and roll back a host](upgrades.md).

## Remove packages

Remove packages by name:

```sh
apm remove curl
```

APM checks whether installed packages still need them and shows the removal
plan before asking for confirmation. Dependencies are kept unless you ask to
remove those that are no longer needed:

```sh
apm autoremove
```

You can combine both operations:

```sh
apm remove curl --autoremove
```

Removing a package changes the active package set. Older package generations
retain their files so that you can roll back. See
[Clean up old packages](#clean-up-old-packages) to reclaim their disk space.

## Reinstall or roll back packages

To download and install a package again:

```sh
apm reinstall curl
```

Package changes are recorded as numbered generations. List earlier package
sets and preview a rollback:

```sh
apm rollback --list
apm rollback --generation N --dry-run
```

Replace `N` with a generation from the list, then apply it:

```sh
apm rollback --generation N
```

Without `--generation`, APM selects the previous package generation. Rollback
restores the package set, not application data such as databases. It does not
replace the running OS image or roll back host configuration.

## Clean up old packages

Keep the latest three personal package generations and the active generation:

```sh
apm clean --generations --keep 3
```

To reclaim unreferenced files from the shared store:

```sh
apm gc
```

Garbage collection works across the shared store. Files still referenced by
another user's profile or a retained generation remain available.

## Manage machine-wide packages

Administrators can add `--system` to manage packages for everyone on the
machine. Stock hosts support this workflow without personal account setup.
Find and install packages by name:

```sh
apm update --system
apm search nginx --system
apm install --system nginx curl --dry-run
apm install --system nginx curl
apm list --system --installed
```

The same package commands work in this scope:

```sh
apm upgrade --system --dry-run
apm upgrade --system
apm hold --system nginx
apm unhold --system nginx
apm remove --system nginx
apm autoremove --system
apm reinstall --system curl
apm rollback --system --list
apm rollback --system --generation N --dry-run
apm rollback --system --generation N
```

Run commands that change machine-wide packages as an administrator. These
operations change the runtime package set; use `apm image` for OS images and
`apm config rollback` for host configuration.

To clean machine-wide package and host configuration generations, then collect
unreferenced store files and clean machine-wide registry overlays:

```sh
apm clean --system --generations --keep 3
apm gc --system
```

The active generations are retained. OS-image generations are not pruned, and
store garbage collection still covers the shared store.

## Enable personal package installs

An administrator must install and enable the `nix-daemon` package before
regular accounts can import new packages into the shared store. Configure its
`settings.allowed-users` for the accounts permitted to connect and
`settings.trusted-public-keys` with the Nix package-signing public keys of your
approved caches. Keep `settings.require-sigs` enabled. Ordinary package users
need daemon access; they do not need membership in `settings.trusted-users`.

The daemon's client configuration selects it for new login shells. After setup,
log in again before using the personal commands above. The administrator must
also create each account's writable profile directory and XDG directories.
See `apm docs show nix-daemon --system` and
[Configure an AOS host](configuration.md) for package configuration.

## Apply a complete package set from a file

For repeatable provisioning, `apply` sets the complete desired package
set from a TOML file. This is optional; use `install` for everyday additions.

For example, save this as `desired.toml`:

```toml
packages = ["nginx", "curl"]
```

Preview and apply it as an administrator:

```sh
apm update --system
apm apply --system --from ./desired.toml --dry-run
apm apply --system --from ./desired.toml
```

The file is the complete set of explicitly requested machine-wide packages.
APM installs missing packages and their dependencies, removes explicitly
installed packages omitted from the file, and removes dependencies that are
no longer needed. Packages supplied by the base OS are managed separately.
If you are editing an existing file, preserve every package you want to keep.

Reconciliation keeps an already-installed package rather than selecting a new
version. Use `apm upgrade --system` to upgrade installed packages. A dry run
uses cached package lists. When applying additions, reconciliation attempts a
refresh and warns if it must use cached metadata instead.

The desired file can also carry package configuration and credential inputs.
APM validates them before changing the package profile. Prefer systemd
system-credential references; protect any file containing credential bytes as
secret state. See [Manage secrets](secrets.md) and
[Configure an AOS host](configuration.md) for configuration and provisioning.

## Package state and trust

APM verifies packages against signed registry metadata before installation.
See [Configure package registries](registries.md) for sources and trust, and
[Secure Boot and package trust](secure-boot.md) for measured-boot hosts.

The sysroot lock keeps runtime packages compatible with dependencies supplied
by the active OS image. Use `--ignore-sysroot-lock` only when a specific
recovery procedure requires it.

| State | Personal packages | Machine-wide packages |
| --- | --- | --- |
| Profile | `/var/lib/profiles/per-user/$USER` | `/var/lib/profiles/system-packages` |
| Registry clones | `~/.local/share/apm/registries` | `/var/lib/apm/registries` |
| Package lists | `~/.local/share/apm/remote` | `/var/lib/apm/remote` |
| Download cache | `~/.cache/apm` | `/var/lib/apm/cache` |
| Writable trust pins | `~/.config/apm/trusted-keys.d` | `/var/lib/apm/trusted-keys.d` |

Personal paths honor the corresponding `XDG_*` variables. Use `apm --json ...`
for automation; human-readable output is not a stable machine interface.

Host configuration has its own history under `/var/lib/profiles/system`,
managed with `apm switch` and `apm config rollback`. OS images have their own
history under `/var/lib/profiles/image`, managed with `apm image`. See
[Upgrade and roll back a host](upgrades.md) for those operations.
