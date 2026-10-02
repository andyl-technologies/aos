# Manage packages with APM

Use `apm` to find, install, update, and remove software on your AOS host. Give
it package names; APM downloads the packages and installs the dependencies
they need to work.

The examples below install packages for everyone on the machine. Run commands
that change machine-wide packages as an administrator. To manage packages for
your own account, omit `--system`; see [Personal packages](#personal-packages).

## Find packages

First refresh the package lists so APM knows what is available:

```sh
apm update --system
```

This downloads package information from your configured registries. It does
not install or upgrade anything.

Search by name or description, then inspect a package:

```sh
apm search nginx --system
apm show nginx --system
```

Use `apm policy nginx --system` to see available versions and their registries.
To add a registry or select a different source, see
[Configure package registries](registries.md).

## Install packages

Install a package by name:

```sh
apm install --system nginx
```

You can install several packages in one command:

```sh
apm install --system nginx curl
```

APM shows the planned changes and asks for confirmation. Dependencies are
installed automatically. Installing named packages keeps unrelated packages
already installed on the machine.

To review the plan without making changes, add `--dry-run`:

```sh
apm install --system nginx --dry-run
```

To choose a particular registry, add `--registry NAME`. For unattended use,
`--yes` skips the confirmation prompt; review the plan before using it.

Installed programs are available on the login session's `PATH`. To inspect
what is installed and which files a package supplies:

```sh
apm list --system --installed
apm files nginx --system
apm depends nginx --system
```

For packages that expose services, see
[Understand the package sandbox](package-sandbox.md) and the package's generated
configuration reference, available through `apm docs` and `apm options`.

## Upgrade packages

Refresh the package lists, check which packages have newer versions, then
upgrade:

```sh
apm update --system
apm list --system --upgradable
apm upgrade --system --dry-run
apm upgrade --system
```

`upgrade` uses the package lists you last downloaded; it does not refresh them
itself. To upgrade only selected packages, supply their names:

```sh
apm upgrade --system nginx curl
```

To keep a package at its installed version during ordinary upgrades, hold it.
Remove the hold when you are ready to upgrade it:

```sh
apm hold --system nginx
apm held --system
apm unhold --system nginx
```

These commands update runtime packages. To update the operating-system image,
use `apm image upgrade` as described in
[Upgrade and roll back a host](upgrades.md).

## Remove packages

Remove packages by name:

```sh
apm remove --system nginx
```

APM checks whether installed packages still need them and shows the removal
plan before asking for confirmation. Dependencies are kept unless you ask to
remove those that are no longer needed:

```sh
apm autoremove --system
```

You can combine both operations:

```sh
apm remove --system nginx --autoremove
```

Removing a package changes the active package set. Older package generations
retain their files so that you can roll back. See
[Clean up old packages](#clean-up-old-packages) to reclaim their disk space.

## Reinstall or roll back packages

To download and install a package again:

```sh
apm reinstall --system nginx
```

Package changes are recorded as numbered generations. List earlier package
sets and preview a rollback:

```sh
apm rollback --system --list
apm rollback --system --generation N --dry-run
```

Replace `N` with a generation from the list, then apply it:

```sh
apm rollback --system --generation N
```

Without `--generation`, APM selects the previous package generation. Rollback
restores the package set, not application data such as databases. It does not
replace the running OS image or roll back host configuration.

## Personal packages

Omit `--system` to manage packages for your own account:

```sh
apm update
apm install curl jq
apm list --installed
apm upgrade
apm remove curl
```

The same package commands, including `hold`, `reinstall`, and `rollback`, work
in this scope. Personal packages do not change the machine-wide package set.

An administrator must provision writable XDG directories, the account's
`/var/lib/profiles/per-user/$USER` directory, and access to install into the
local store before personal installs can be used. Stock hosts support the
machine-wide commands above without that account setup.

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

## Clean up old packages

Keep the latest three generations and the active generation, then reclaim
unreferenced files:

```sh
apm clean --system --generations --keep 3
apm gc --system
```

With `--system`, generation cleanup covers both machine-wide package and host
configuration generations. It does not prune OS-image generations. Omit
`--system` to clean your personal package generations. Garbage collection
reclaims unreferenced files across the shared store; `gc --system` also cleans
machine-wide registry overlays.

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
