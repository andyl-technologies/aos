# Manage packages with APM

`apm` consumes signed registry metadata and manages generation-based package
profiles. User packages, machine-wide runtime packages, configuration
generations, and A/B image generations are separate scopes. The distinction is
important: `--system` does not simply make a normal user install global.

## Establish package policy first

Before installing a package, configure and verify its source as described in
[Configure package registries](registries.md). Registry signatures and the
signed store graph authenticate the publisher and exact closure bytes; they do
not establish that a program is benign.

For packages that contribute services, inspect the signed package contract and
selected resources described in [Understand native package runtime
policy](package-sandbox.md). [Secure Boot and package trust](secure-boot.md)
explains how image-baked registry anchors connect package admission to the boot
chain.

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

Machine-wide package selection is part of the authenticated host configuration
fixed point. Add the package names to `host.nix`:

```nix
{
  aos.apm.desiredPackages = ["nginx" "curl"];
}
```

Preview and apply the complete configuration:

```sh
apm update --system
apm switch --from ./host.nix --dry-run
apm switch --from ./host.nix
```

The explicit update makes the preview predictable: dry-run does not refresh
registry metadata. The package list is declarative. Removing `nginx` from
`aos.apm.desiredPackages` removes it from the next configuration generation and
stops its selected services. Package configuration and opaque credential
references belong in the same module transaction; secret bytes never enter
evaluated `host.nix`.

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
