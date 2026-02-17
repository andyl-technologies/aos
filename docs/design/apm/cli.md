# APM CLI Specification

## Design Principle

The `apm` CLI mirrors `apt` as closely as possible. A Debian/Ubuntu user should
be able to use `apm` with near-zero learning curve. Where `apm` diverges from
`apt`, it is because the underlying model requires it (Nix store vs dpkg, TOML
vs control files, HTTP bundles vs HTTP indices). Dependencies are closure-based
--- no constraint language, no SAT solver.

## Invocation

`apm` is implemented as `aos package` — a subcommand of the `aos` Rust CLI.
The `apm` binary is a symlink to `aos` installed in the same Nix package.
When `aos` detects `argv[0]` is `apm`, it implicitly prepends the `package`
subcommand.

```
# These are identical:
aos package install curl
apm install curl
```

All examples below use the `apm` shorthand. Substitute `aos package` anywhere
you see `apm`.

### Rust CLI Structure (clap)

```
aos
├── build ...
├── test ...
├── fmt ...
├── package              ← apm alias targets here
│   ├── install
│   ├── remove
│   ├── autoremove
│   ├── reinstall
│   ├── update
│   ├── upgrade
│   ├── full-upgrade
│   ├── search
│   ├── show
│   ├── list
│   ├── depends
│   ├── rdepends
│   ├── policy
│   ├── files
│   ├── hold
│   ├── unhold
│   ├── held
│   ├── clean
│   ├── gc
│   ├── verify
│   ├── source
│   ├── rollback
│   └── registry
│       ├── list
│       ├── add
│       └── remove
├── shell ...
└── ...
```

## Command Summary

### Package Management

| Command | Description |
|---------|-------------|
| `apm install [--system] <pkg>...` | Install one or more packages |
| `apm remove [--system] <pkg>...` | Remove packages (keep deps) |
| `apm autoremove [--system] [--dry-run] [-y]` | Remove orphaned dependency packages |
| `apm reinstall <pkg>...` | Re-download and reinstall packages |

### Package Queries

| Command | Description |
|---------|-------------|
| `apm search <pattern>` | Search package names and descriptions |
| `apm show <pkg>` | Show detailed package information |
| `apm list [--installed]` | List packages (all or installed) |
| `apm depends <pkg>` | Show closure tree (store references) |
| `apm rdepends <pkg>` | Show reverse dependencies |
| `apm policy <pkg>` | Show available versions and registry origins |
| `apm files <pkg>` | List files installed by a package |

### Registry Management

| Command | Description |
|---------|-------------|
| `apm update` | Fetch latest registry metadata |
| `apm upgrade [--system]` | Upgrade all installed packages to latest |
| `apm full-upgrade [--system] [--dry-run] [-y]` | Upgrade with dependency resolution changes |
| `apm registry list` | List configured registries and priorities |
| `apm registry add <url> [--priority=N]` | Add a registry |
| `apm registry remove <name>` | Remove a registry (fails if packages still installed) |

### System Maintenance

| Command | Description |
|---------|-------------|
| `apm clean [--generations] [--keep=N]` | Remove cached NAR downloads (and optionally old generations) |
| `apm gc` | Run Nix garbage collection on unreachable paths |
| `apm verify <pkg>` | Verify installed package against registry hash |
| `apm source <pkg>` | Show/fetch the source derivation for a package |
| `apm rollback` | Roll back to the previous profile generation |

### Hold/Pin Management

| Command | Description |
|---------|-------------|
| `apm hold <pkg>` | Prevent a package from being upgraded |
| `apm unhold <pkg>` | Remove upgrade hold |
| `apm held` | List held packages |

---

## Detailed Command Reference

### `apm install`

```
apm install [OPTIONS] <PACKAGE>...
```

Install one or more packages from configured registries. All runtime
dependencies are resolved and installed automatically.

By default, packages are installed to the user profile (non-root). Use
`--system` to install to the system profile (requires root).

**Options:**

| Flag | Description |
|------|-------------|
| `--system` | Install to the system profile (requires root) |
| `--dry-run` | Show what would be installed without doing it |
| `--download-only` | Download NARs but don't install |
| `--reinstall` | Reinstall even if already at target version |
| `--no-deps` | Skip automatic dependency installation |
| `-y, --yes` | Assume yes to all prompts |
| `--registry=<name>` | Force install from a specific registry |

**Version selection:**

Each package name has at most one version per registry. `apm install`
selects the version from the highest-priority registry that offers the
package. Use `--registry=<name>` to install from a specific registry.

**Behavior:**

1. Resolve package and version from registries (highest priority first)
2. Verify registry `store_dir` matches local store root
3. Walk `references` fields transitively to compute full closure (all references resolve from the same registry as the parent package)
4. Diff closure against local store — identify missing paths
5. Display transaction summary (paths to download, closure size)
6. Prompt for confirmation (unless `-y`)
7. Download NARs from mirrors (parallel, with progress)
8. Verify download hashes and NAR hashes against registry metadata
9. Import NARs into Nix store
10. Create GC roots in profile's `usr/{hash}` for each closure path
11. Write per-path metadata JSON to profile's `meta/{hash}.json` (includes `apm.registry` for provenance)
12. Rebuild profile — build new generation with merged FHS symlinks, atomic-switch `current`
13. Display completion summary

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Package not found |
| 3 | Download/network error |
| 4 | Hash verification failure |
| 100 | User cancelled |

### `apm remove`

```
apm remove [OPTIONS] <PACKAGE>...
```

Remove packages by deleting their GC roots. The actual store paths remain until
garbage collection runs.

**Options:**

| Flag | Description |
|------|-------------|
| `--system` | Remove from the system profile (requires root) |
| `--dry-run` | Show what would be removed |
| `--autoremove` | Also remove orphaned dependencies |
| `-y, --yes` | Assume yes to all prompts |

**Behavior:**

1. Verify packages are installed
2. Check reverse dependencies (warn if other installed packages depend on this)
3. Display removal summary
4. Prompt for confirmation
5. Remove GC root symlinks
6. Optionally run `autoremove` for orphaned deps
7. Optionally trigger `aos gc --collect`

### `apm update`

```
apm update [OPTIONS]
```

Synchronize local registry metadata with remote sources. Equivalent to
`apt update`. The transport depends on the configured URI scheme (see
[registry.md](registry.md)).

**Options:**

| Flag | Description |
|------|-------------|
| `--registry=<name>` | Update only this registry |

**Behavior (HTTP bundle transport):**

1. For each configured registry, fetch `bundle-list.toml` from the mirror
2. Download and apply new snapshot/delta bundles (skip already-applied bundles
   via `creation_token`)
3. Verify bundle SHA-256 against manifest, `git bundle verify` for pack
   integrity
4. Verify commit signatures (if signing is configured)
5. Enforce fast-forward from `last_commit` (downgrade protection)
6. Parse updated TOML package files
7. Report number of new/updated/removed packages per registry

**Behavior (git transport):**

1. For each configured registry, `git fetch` the latest refs
2. Validate the git signature (if signing is configured)
3. Enforce fast-forward from `last_commit`
4. Parse updated TOML package files
5. Report number of new/updated/removed packages per registry

**Output example:**

```
Fetching registry 'aos-core' ... done (143 packages, 12 updated)
Fetching registry 'aos-extra' ... done (891 packages, 47 updated)
23 packages can be upgraded. Run 'apm upgrade' to upgrade them.
```

### `apm upgrade`

```
apm upgrade [OPTIONS] [PACKAGE...]
```

Upgrade installed packages to their latest available versions. If specific
packages are named, only those are upgraded. Otherwise, all installed packages
are upgraded.

**Options:**

| Flag | Description |
|------|-------------|
| `--system` | Upgrade the system profile (requires root) |
| `--dry-run` | Show what would be upgraded |
| `-y, --yes` | Assume yes |
| `--exclude=<pkg>` | Skip specific packages |

### `apm search`

```
apm search [OPTIONS] <PATTERN>
```

Search package names and descriptions across all registries.

**Options:**

| Flag | Description |
|------|-------------|
| `--names-only` | Search only package names |
| `--installed` | Search only installed packages |
| `--registry=<name>` | Search only this registry |

**Output example:**

```
openssl/aos-core 3.2.0 - TLS/SSL and general-purpose cryptography library
lib-ssh2/aos-extra 1.11.0 - Client-side SSH2 library
```

### `apm show`

```
apm show <PACKAGE>
```

Display detailed information about a package.

**Output example:**

```
Package: openssl
Version: 3.2.0
Registry: aos-core
Description: TLS/SSL and general-purpose cryptography library
Homepage: https://www.openssl.org
License: Apache-2.0
Platform: x86_64-linux
Installed: yes
Store path: /var/lib/store/abc123...-openssl-3.2.0
NAR size: 14.2 MiB
Dependencies: zlib, cacert
Source drv: /var/lib/store/def456...-openssl-3.2.0.drv
Maintainer: aos-team
```

### `apm policy`

```
apm policy <PACKAGE>
```

Show all available versions of a package across registries, indicating which
registry would be selected and why.

**Output example:**

```
openssl:
  Installed: 3.2.0
  Candidate: 3.2.0
  Version table:
 *** 3.2.0  500  aos-core
     3.2.0  400  aos-extra
```

### `apm list`

```
apm list [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--installed` | Only installed packages |
| `--upgradable` | Only packages with available upgrades |
| `--held` | Only held packages |
| `--registry=<name>` | Only from this registry |

### `apm source`

```
apm source [OPTIONS] <PACKAGE>
```

Show or fetch the source derivation for reproducible build verification.

**Options:**

| Flag | Description |
|------|-------------|
| `--show-drv` | Print the source derivation path |
| `--fetch` | Download the source derivation and all source inputs |
| `--verify` | Rebuild from source and compare hash with installed binary |

### `apm rollback`

```
apm rollback [--generation=N]
```

Roll back to a previous profile generation. Without `--generation`, rolls back
to the immediately previous generation. This atomically switches the profile
symlink — no downloads or store changes needed.

**Options:**

| Flag | Description |
|------|-------------|
| `--generation=N` | Roll back to a specific generation number |
| `--system` | Roll back the system profile (requires root) |
| `--dry-run` | Show what the rollback would change |

**Behavior:**

1. Identify the target generation (previous, or `N` if specified)
2. Verify the target generation still exists
3. Atomic-switch the profile symlink to the target generation
4. Display the diff between current and rolled-back package sets

Because profiles are symlink trees pointing at store paths that are still
rooted by their GC roots, rollback is instantaneous. No downloads, no store
mutations.

### `apm depends`

```
apm depends <PACKAGE>
```

Walk store references from the package's closure. Display as a tree with
package names resolved via the registry's hash index. Unnamed store paths
are shown as raw hashes.

### `apm rdepends`

```
apm rdepends <PACKAGE>
```

Scan installed packages for closures that include the given package's store
path. Lists every installed package that transitively depends on the target.

### `apm autoremove`

```
apm autoremove [OPTIONS]
```

Find `meta/` entries with `apm.explicit = false` that are not in any explicit
package's closure. Remove their GC roots.

**Options:**

| Flag | Description |
|------|-------------|
| `--system` | Operate on the system profile (requires root) |
| `--dry-run` | Show what would be removed without doing it |
| `-y, --yes` | Assume yes to all prompts |

### `apm files`

```
apm files <PACKAGE>
```

List files in the package's store path.

### `apm clean`

```
apm clean [OPTIONS]
```

Remove cached NAR downloads. Optionally remove old profile generations.

**Options:**

| Flag | Description |
|------|-------------|
| `--generations` | Remove old profile generations (keeps last 3 by default) |
| `--keep=N` | Number of generations to retain (default: 3, used with `--generations`) |

---

## apt Comparison Table

| apt command | apm equivalent | Notes |
|-------------|---------------|-------|
| `apt install pkg` | `apm install pkg` | Identical |
| `apt remove pkg` | `apm remove pkg` | Identical |
| `apt purge pkg` | `apm remove pkg` | No purge distinction (per-user, no service state) |
| `apt autoremove` | `apm autoremove` | Identical |
| `apt update` | `apm update` | HTTP bundles (default) or git fetch |
| `apt upgrade` | `apm upgrade` | Identical |
| `apt full-upgrade` | `apm full-upgrade` | Identical |
| `apt search foo` | `apm search foo` | Identical |
| `apt show pkg` | `apm show pkg` | Identical |
| `apt list --installed` | `apm list --installed` | Identical |
| `apt-cache depends pkg` | `apm depends pkg` | Subcommand, not separate tool |
| `apt-cache rdepends pkg` | `apm rdepends pkg` | Subcommand, not separate tool |
| `apt-cache policy pkg` | `apm policy pkg` | Subcommand, not separate tool |
| `apt-mark hold pkg` | `apm hold pkg` | Simpler — direct subcommand |
| `apt-mark unhold pkg` | `apm unhold pkg` | Simpler — direct subcommand |
| `apt-mark showhold` | `apm held` | Lists all held packages |
| `apt-get download pkg` | `apm install --download-only pkg` | Flag, not separate command |
| `apt-get source pkg` | `apm source pkg` | Shows source derivation chain |
| `apt clean` | `apm clean` | Clears NAR cache |
| `dpkg -L pkg` | `apm files pkg` | No separate dpkg tool needed |

**Where apm diverges from apt:**

1. **Part of `aos`** — `apm` is `aos package`, a subcommand of the unified
   AOS CLI. The `apm` symlink provides the familiar standalone feel.

2. **No `apt-get` / `apt-cache` / `dpkg` split** — Everything lives under
   `aos package` (or equivalently `apm`) with subcommands.

3. **No `.deb` files** — Packages are Nix store paths delivered as NARs.
   There is no `dpkg -i` equivalent; all installs go through registries.

4. **No `dist-upgrade`** — AOS doesn't have distribution releases in the
   Debian sense. `apm full-upgrade` handles dependency-changing upgrades.

5. **No architecture suffixes** — The flat namespace already scopes to a
   platform. Cross-platform packages use separate registries.

6. **Source verification** — `apm source --verify` has no apt equivalent.
   This leverages Nix's reproducible build properties.

7. **Registry management** — `apm registry add/remove/list` replaces manual
   editing of `sources.list`.

8. **Rollback** — `apm rollback` instantly switches to a previous profile
   generation. No apt equivalent exists.

9. **Verification** — `apm verify` checks installed store paths against
   registry hashes. apt has `debsums` but it is a separate package.

---

## Configuration

APM configuration exists at two levels:

| Scope | Config dir | Registry dir | Used by |
|-------|-----------|--------------|---------|
| System | `/etc/apm/apm.conf` | `/etc/apm/registries.d/` | System profile, fallback for user profiles |
| User | `~/.config/apm/apm.conf` | `~/.config/apm/registries.d/` | User profile |

**Lookup order:** When operating on the **user profile** (default), `apm` reads
the user config first, then falls back to the system config for any values not
set. When operating on the **system profile** (`--system`), `apm` reads only
the system config at `/etc/apm/`.

This means default registries can be provisioned in `/etc/apm/registries.d/`
via cloud-init at boot time. Users inherit those registries automatically but can
override priorities or add their own in `~/.config/apm/registries.d/`. A
user-level registry file with the same `name` as a system-level one overrides
it entirely.

### System config: `/etc/apm/`

```
/etc/apm/
├── apm.conf                    ← system-wide defaults
└── registries.d/
    ├── aos-core.toml           ← provisioned via cloud-init
    └── aos-extra.toml
```

`/etc/` is an overlay over the immutable root filesystem, configured via
cloud-init at boot and immutable once the system is running. This provides
the default registries for all users and is the sole config source for
`apm install --system`.

### User config: `~/.config/apm/`

```
~/.config/apm/
├── apm.conf                    ← user overrides
└── registries.d/
    └── company-internal.toml   ← user-added registry
```

### Config file format

```toml
[settings]
# Assume yes to prompts (like apt -y)
assume_yes = false

# Maximum parallel NAR downloads
parallel_downloads = 4

# Automatically run autoremove after remove
auto_autoremove = false

# Automatically run gc after autoremove
auto_gc = false
```

### Registry source format

Each file in `registries.d/` defines one registry. The URI scheme determines
the transport — `https://` uses HTTP bundles (default), `git+https://` or
`git://` uses native git:

```toml
# /etc/apm/registries.d/aos-core.toml  (system-level)
# ~/.config/apm/registries.d/aos-core.toml  (user-level override)
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"    # https:// = HTTP bundles
priority = 500
enabled = true
```

See [registry.md](registry.md) for full details including git transport
configuration and pinning.

---

## Output Modes

| Flag | Mode | Description |
|------|------|-------------|
| (default) | Human | Colored, formatted for terminals |
| `--quiet` | Quiet | Minimal output (errors only) |
| `--json` | Machine | JSON output for scripting |

All commands support `--json` for machine-parseable output. JSON output includes
the same information as human output but structured for programmatic use.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `APM_CONFIG` | Path to config file (default: `~/.config/apm/apm.conf`) |
| `AOS_ROOT` | AOS state root (default: `/var/lib`) |
| `APM_CACHE_DIR` | Override NAR cache directory |
| `APM_YES` | If set, assume yes to all prompts |
| `APM_NO_COLOR` | Disable colored output |
| `NO_COLOR` | Standard no-color convention (also respected) |
