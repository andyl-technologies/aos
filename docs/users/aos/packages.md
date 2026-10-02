# Manage packages with APM

`apm` is the AOS package manager. Use it to find software, install and remove
packages, and update the packages you use.

Start by finding a package, then install it by name. Use `--system` for
machine-wide packages; omit it for packages belonging to your account.

## Find a package

APM gets its list of available packages from registries. AOS comes with the
`andyl` registry configured; your administrator may have added others.

First, fetch the latest package lists:

```sh
apm update --system
```

`update` tells APM which packages and versions are available. It does not
install or upgrade anything.

Search by name or description, then inspect a result:

```sh
apm search nginx --system
apm show nginx --system
```

`search` lists matching package names, versions, and descriptions. `show`
provides details about one package. Use the package name from the results
when installing it.

If a package is available from more than one registry, check its versions and
sources:

```sh
apm policy nginx --system
```

To search a particular registry, add `--registry`:

```sh
apm search nginx --system --registry andyl
```

See [Configure package registries](registries.md) to add or change sources.

For your account's packages, use the same commands without `--system`.

## Manage machine-wide packages

### Install packages by name

Run machine-wide package commands as an administrator. To install `nginx`,
fetch the package lists, preview the install, then apply it:

> **Implementation status:** The name-based system installation examples below
> describe the intended APM interface. The current CLI routes these commands to
> OS-image installation and cannot yet install ordinary system packages by name.
> Until that gap is fixed, the package-list method below is the supported way
> to install ordinary machine-wide packages.

```sh
apm update --system
apm install --system nginx --dry-run
apm install --system nginx
```

APM should install `nginx` and its dependencies: other packages it needs to
work. This adds the requested package to the existing machine-wide set without
requiring you to list the packages already installed.

Install several packages by supplying their names:

```sh
apm install --system nginx curl
```

To select a particular configured registry, add `--registry`:

```sh
apm install --system nginx --registry andyl
```

### Check installed packages

```sh
apm list --installed --system
apm files nginx --system
apm depends nginx --system
```

`list --installed` shows the installed packages. `files` lists the files a
package provides. `depends` shows the store references making up the package
and its dependencies. Installed commands are available in new login sessions
through the machine-wide package directory on `PATH`.

### Manage a package list

For provisioning or keeping several hosts on the same package set, you can
instead maintain a TOML file. For example, save this as `desired.toml`:

```toml
packages = ["nginx", "curl"]
```

**This is the complete list of packages you want APM to manage for the
machine.** If the host already has such a file, edit that file to preserve its
other packages. Applying a shorter list removes packages omitted from it.
Packages supplied by the base OS are managed separately.

Refresh the package lists, preview the complete change, and apply it:

```sh
apm update --system
apm install --system --from ./desired.toml --dry-run
apm install --system --from ./desired.toml
```

Review additions and removals before confirming. Add `--yes` to accept the
confirmation prompts automatically.

To add a package, add its name to the file. To remove `nginx` while keeping
`curl`, change the list to `packages = ["curl"]`. Preview and apply the file
again. APM also removes dependencies that are no longer needed.

A dry run uses the package lists already fetched. Applying a list with
additions also attempts an update, falling back to cached lists with a warning
if that update fails. Reapplying the list adds and removes packages; it does
not upgrade packages already present.

The file can also carry package configuration and credential inputs. See
[Supplement host.nix at runtime](configuration.md#supplement-hostnix-at-runtime).
Prefer systemd credential references; protect any file containing secret
values as secret state.

### Update the operating system

`apm upgrade --system` currently updates the OS image. For OS updates and
rollback, follow [Upgrade and roll back a host](upgrades.md).

## Manage user packages

### Install packages

Install one or more packages by name. You do not need to write a package-list
file:

```sh
apm install curl jq
```

The current CLI installs these packages for your account. On stock images,
an administrator must first enable personal package installs by providing
writable APM directories and access to the package store.

Preview the install, then apply it:

```sh
apm install curl --dry-run
apm install curl
```

APM also installs dependencies: other packages the program needs to work.
It asks for confirmation before making changes; add `--yes` to accept the
prompt automatically. If you need a package from a particular configured
registry, add `--registry NAME` to the install command.

New AOS login sessions include your package directory on `PATH`. If an
existing shell cannot find an installed command, start a new login session or
add the directory to that shell:

```sh
export PATH="/var/lib/profiles/per-user/$USER/current/bin:$PATH"
```

Inspect what you have installed:

```sh
apm list --installed
apm files curl
apm depends curl
```

`list --installed` shows your packages. `files` lists the files a package
provides. `depends` shows the store references making up the package and its
dependencies.

### Upgrade packages

Fetch the latest package lists and check which installed packages have updates:

```sh
apm update
apm list --upgradable
```

Preview and apply the upgrades:

```sh
apm upgrade --dry-run
apm upgrade
```

`upgrade` uses the lists fetched by `update`; it does not fetch new lists itself.
To upgrade just one package, supply its name:

```sh
apm upgrade curl
```

To keep a package at its current version during ordinary upgrades, put it on
hold. Remove the hold when you are ready to upgrade it again:

```sh
apm hold curl
apm unhold curl
```

### Remove packages

```sh
apm remove curl --dry-run
apm remove curl
```

Removal keeps dependencies by default. To also remove dependencies that are
no longer needed, preview and apply with `--autoremove`:

```sh
apm remove curl --autoremove --dry-run
apm remove curl --autoremove
```

### Undo a package change

APM saves a numbered version of your installed package set each time you
install, remove, or upgrade packages. These saved sets are called generations.
You can return to a previous generation if a change causes problems.

List the saved generations and preview the one you want:

```sh
apm rollback --list
apm rollback --generation N --dry-run
```

Replace `N` with a generation number from the list, then apply it:

```sh
apm rollback --generation N
```

This changes your account's installed package set. For host configuration and
OS rollback, use [Upgrade and roll back a host](upgrades.md).

## Free disk space

Old generations keep packages available for rollback. To retain the latest
three user-package generations and the active generation, then reclaim
unreferenced store data:

```sh
apm clean --generations --keep 3
apm gc
```

For machine-wide packages, run as an administrator:

```sh
apm clean --system --generations --keep 3
apm gc
```

The system command prunes both machine-wide package and host-configuration
generations, keeping the latest three and the active generation of each. It
does not remove OS image generations. Pruned generations are no longer
available for rollback.

To remove cached package downloads without pruning generations, use `apm clean`
for your account or `apm clean --system` for the machine.

## Get help

Use `--help` to see the options for a command:

```sh
apm --help
apm install --help
```

For scripts, use `apm --json ...` to request structured results. The normal
terminal output is intended for people and is not a stable interface for scripts.

If APM refuses an install because it conflicts with a package supplied by the
OS, see [Troubleshoot a host](troubleshooting.md). The
`--ignore-sysroot-lock` option bypasses this check and belongs in targeted
recovery procedures.

For registry verification failures, see
[Troubleshoot registry verification](troubleshooting.md#apm-cannot-verify-a-registry).
For service permissions, see [Understand the package sandbox](package-sandbox.md).
For the signing and boot verification model, see
[Secure Boot and package trust](secure-boot.md).
