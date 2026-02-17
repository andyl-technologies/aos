# APM System Integration

## Overview

APM installs packages into the Nix store via GC roots. But store paths are not
directly usable -- they are buried deep in `/var/lib/store/{hash}-pkg-ver/` and
invisible to users. Users need `curl` on their `$PATH`, man pages discoverable
by `man`, and libraries linkable by `pkg-config`.

This document describes how APM bridges the gap between immutable store paths
and a usable system via **profiles** -- merged symlink trees that expose
`bin/`, `sbin/`, `lib/`, `share/`, `include/`, and `etc/` from all installed
packages under a single directory. Profiles exist at two scopes: system-wide
(requires root) and per-user (non-root, default).

---

## Profile Mechanism

### Why a profile?

Each store path (e.g., `/var/lib/store/{hash}-curl-8.5.0/bin/curl`) is buried
in the store. Users need `curl` on their PATH without knowing the hash. Nix
solves this with "profiles" -- merged symlink trees that collect all installed
packages' outputs into a single directory hierarchy. APM does the same.

### Profile locations

Profiles live under `/var/lib/profiles/` with two scopes:

| Scope | Path | Privilege |
|---|---|---|
| System | `/var/lib/profiles/system/` | Requires root |
| User | `/var/lib/profiles/per-user/$USER/` | Non-root (default) |

Both scopes share the same generation structure. The `current` symlink always
points to the active generation directory. Each generation is both the merged
symlink tree **and** the GC root directory (unified):

```
/var/lib/profiles/per-user/dylan/
├── current -> gen-42                <- atomic symlink
├── state.json                       <- generation counter + metadata
├── gen-41/                          <- previous (rollback target)
└── gen-42/                          <- current generation
    ├── usr/
    │   └── {hash} -> /var/lib/store/{hash}-curl-8.5.0   <- GC roots
    ├── src/
    │   └── {hash} -> /var/lib/store/{hash}-curl-8.5.0.drv  <- source roots
    ├── bin/
    │   ├── curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
    │   ├── vim -> /var/lib/store/{hash}-vim-9.1/bin/vim
    │   └── ...
    ├── sbin/
    │   └── ...
    ├── lib/
    │   ├── libcurl.so -> ...
    │   ├── libcurl.so.4 -> ...
    │   └── pkgconfig/
    │       └── libcurl.pc -> ...
    ├── include/
    │   └── curl/ -> ...
    ├── share/
    │   ├── man/man1/
    │   │   └── curl.1 -> ...
    │   ├── info/
    │   └── applications/
    └── etc/
        └── ...
```

The system profile follows the same layout at `/var/lib/profiles/system/`.

Every `apm install` or `apm remove` creates a new generation and atomically
switches the `current` symlink.

### What gets merged

| Subdirectory | Purpose | Environment variable |
|---|---|---|
| `bin/` | Executables | `PATH` |
| `sbin/` | System executables | `PATH` |
| `lib/` | Shared libraries | (RPATH handles runtime; useful for dev linking) |
| `lib/pkgconfig/` | pkg-config files | `PKG_CONFIG_PATH` |
| `include/` | Headers | `C_INCLUDE_PATH` / `CPLUS_INCLUDE_PATH` |
| `share/man/` | Man pages | `MANPATH` |
| `share/info/` | Info pages | `INFOPATH` |
| `share/applications/` | Desktop files | `XDG_DATA_DIRS` |
| `etc/` | Configuration files | (read directly by programs) |
| `usr/{hash}` | GC roots | (keeps store paths alive) |
| `src/{hash}` | Source roots | (keeps source paths alive) |

### How the profile is built

The profile is built in **Rust** by APM itself, not via Nix's `buildEnv`
derivation. Three reasons:

1. **No Nix daemon dependency** -- APM works without nix-daemon running. The
   profile is a plain directory of symlinks, not a store derivation.

2. **Fast** -- Building a symlink tree for 200 packages takes ~100ms. A
   `buildEnv` evaluation round-trips through the Nix evaluator and daemon,
   taking 2-5s and creating a store path for each generation.

3. **No dead store paths** -- `buildEnv` creates a new store path per
   generation that becomes garbage when superseded. APM profiles are plain
   directories under `/var/lib/profiles/`; old generations are just directories
   of symlinks that can be deleted directly.

Algorithm:

1. Enumerate all installed packages from the profile's `meta/` directory
2. For each package, scan its store path for the merged subdirectories
   (`bin/`, `sbin/`, `lib/`, `include/`, `share/`, `etc/`)
3. Create `usr/{hash}` GC roots and FHS symlinks in a new generation directory (`gen-{N+1}/`)
4. Detect conflicts (two packages providing the same file) and report them
5. Atomic switch: create a temporary symlink, then `rename(2)` it to `current`

### Atomicity and rollback

The profile switch is atomic via `rename(2)` on the `current` symlink. At no
point is the profile in an inconsistent state -- processes that resolved the
old symlink continue using the old generation; new processes see the new one.

Rolling back is a single operation:

```sh
# User profile rollback:
ln -sfn gen-41 /var/lib/profiles/per-user/$USER/current

# System profile rollback (requires root):
ln -sfn gen-41 /var/lib/profiles/system/current
```

Old generations are kept until explicitly removed with `apm clean --generations`.
By default, APM retains the last 3 generations for rollback.

### Conflict detection

If two installed packages within the same profile both provide the same file,
the last-installed package wins -- the new generation's symlink points to the
most recently installed package. APM logs a warning so the user is aware:

```
WARNING: File conflict in bin/python3:
  python3/aos-core (3.12.1) provides bin/python3
  python2/aos-extra (2.7.18) provides bin/python3 (last installed, wins)
```

Conflicts are checked per-filename within each merged subdirectory. Two
packages providing `lib/libz.so` conflict; two packages each providing
`lib/libfoo.so` and `lib/libbar.so` do not.

Conflicting files from different profiles (user vs system) are resolved by
PATH ordering -- the user profile takes precedence over the system profile,
which takes precedence over the golden image.

### Man pages

Man pages are the documentation mechanism for APM-installed packages. No
custom doc index or pre-generation step is needed — `man` discovers pages
through `MANPATH`, and the profile merge provides that.

**How it works:**

1. **Store path** — Each package's man pages live in its store path:
   ```
   /var/lib/store/{hash}-curl-8.5.0/share/man/man1/curl.1
   /var/lib/store/{hash}-openssl-3.2.0/share/man/man1/openssl.1
   /var/lib/store/{hash}-openssl-3.2.0/share/man/man3/SSL_connect.3
   ```

2. **Profile merge** — When `apm` builds a new generation, it scans each
   installed package's `share/man/` tree and creates symlinks in the
   generation directory, preserving the man section structure:
   ```
   gen-42/share/man/
   ├── man1/
   │   ├── curl.1 -> /var/lib/store/{hash}-curl-8.5.0/share/man/man1/curl.1
   │   └── openssl.1 -> /var/lib/store/{hash}-openssl-3.2.0/share/man/man1/openssl.1
   ├── man3/
   │   └── SSL_connect.3 -> /var/lib/store/{hash}-openssl-3.2.0/share/man/man3/SSL_connect.3
   └── man5/
       └── ...
   ```

3. **MANPATH** — The profile environment scripts (see below) export
   `MANPATH` pointing at the profile's `share/man/`:
   ```
   MANPATH=/var/lib/profiles/per-user/$USER/current/share/man:...
   ```

4. **Discovery** — `man curl` resolves via `MANPATH` to the profile's
   merged `share/man/man1/curl.1`, which is a symlink into the store.
   No `mandb` indexing step is needed — `man` falls back to directory
   scanning when `MANPATH` is set.

**Lifecycle:**

- `apm install curl` — curl's man pages appear in the new generation's
  `share/man/`. `man curl` works immediately.
- `apm remove curl` — the new generation omits curl's man page symlinks.
  `man curl` stops resolving.
- `apm rollback` — the previous generation's man pages are restored
  atomically with everything else.

**Conflict handling:** Man page conflicts follow the same rules as other
merged files. If two packages ship `share/man/man1/foo.1`, the profile
build fails with a conflict error.

### Environment setup

AOS maintains three layers with distinct purposes:

```
Golden image:    /etc/aos/system-path                           <- immutable system packages (individual store paths)
System profile:  /var/lib/profiles/system/current/              <- system-wide APM packages (root)
User profile:    /var/lib/profiles/per-user/$USER/current/      <- per-user APM packages
```

The golden image does **not** merge system binaries into a single directory.
Instead, the toplevel derivation writes `/etc/aos/system-path` — a file
containing colon-separated `bin/` directories for each system package
(e.g., `/var/lib/store/{hash}-bash-5.2/bin:/var/lib/store/{hash}-coreutils-9.4/bin:...`).
The system init and shell profile read this manifest to construct `$PATH`.

PATH ordering: user profile first, system profile second, golden image last:

```
PATH=/var/lib/profiles/per-user/$USER/current/bin:/var/lib/profiles/per-user/$USER/current/sbin:/var/lib/profiles/system/current/bin:/var/lib/profiles/system/current/sbin:$(<cat /etc/aos/system-path)
```

If the same binary exists in multiple layers, the leftmost (highest-priority)
version wins. User-installed packages override system-wide APM packages, which
in turn override golden image packages.

**Golden image PATH** is set up early in init from the system-path manifest.
The toplevel derivation writes `/etc/aos/system-path` containing individual
store-path `bin/` entries; an init script (or `/etc/profile.d/00-system-path.sh`)
reads this file and exports it as PATH. APM profiles prepend to this base.

**System profile environment** is set up via `/etc/profile.d/apm.sh`,
provisioned by cloud-init:

```sh
# /etc/profile.d/apm.sh
_sys="/var/lib/profiles/system/current"
if [ -d "$_sys" ]; then
  export PATH="$_sys/bin:$_sys/sbin:$PATH"
  export MANPATH="$_sys/share/man:${MANPATH:-}"
  export INFOPATH="$_sys/share/info:${INFOPATH:-}"
  export XDG_DATA_DIRS="$_sys/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
  export PKG_CONFIG_PATH="$_sys/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi
```

**User profile environment** is sourced from the user's shell profile:

```sh
# ~/.profile, ~/.bashrc, or equivalent
_user="/var/lib/profiles/per-user/$USER/current"
if [ -d "$_user" ]; then
  export PATH="$_user/bin:$_user/sbin:$PATH"
  export MANPATH="$_user/share/man:${MANPATH:-}"
  export INFOPATH="$_user/share/info:${INFOPATH:-}"
  export XDG_DATA_DIRS="$_user/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
  export PKG_CONFIG_PATH="$_user/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi
```

`apm` can generate this snippet on first run, or the AOS base system can
include it in the default shell profile.

`apm list` annotates packages that are shadowed by a higher-priority layer:

```
curl/aos-core 8.5.0 [installed, shadowed by system-path]
vim/aos-core 9.1 [installed, shadowed by system profile]
htop/aos-core 3.3.0 [installed]
```

A shadowed package is still installed (its GC root exists, its files are in the
profile) but its binaries are not reachable via `$PATH` because a
higher-priority layer's version takes precedence.

---

## Multi-User Deduplication

The Nix store is shared across all users. When two users install the same
package, the store path exists only once on disk. Each user has independent
profiles with their own GC roots (the `usr/{hash}` symlinks inside each
generation):

```
/var/lib/profiles/per-user/
├── dylan/current/
│   ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0     <- dylan's GC root
│   └── bin/curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
└── alice/current/
    ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0     <- alice's GC root (same store path)
    └── bin/curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
```

The store path is content-addressed. Two users installing the same version
of the same package from the same registry will always reference the same
store path. `aos gc --collect` only removes store paths that have zero roots
across all users and profiles (system and per-user).

---

## Comparison with Other Systems

| Aspect | dpkg/apt | Nix profiles | APM |
|---|---|---|---|
| Scope | System-wide | Per-user | System-wide OR per-user |
| Binary location | `/usr/bin/` | Merged profile (store symlinks) | Merged profile (store symlinks) |
| Privilege required | root | No (per-user) | No (per-user default); root for system profile |
| Atomic install | No | Yes (profile swap) | Yes (generation swap) |
| Rollback | No | Yes (generations) | Yes (generations) |
| Profile build | N/A | `buildEnv` (Nix evaluator) | Rust (no Nix daemon) |
| Multi-user dedup | N/A | Yes (shared store) | Yes (shared store) |
| Rootfs mutation | Yes (`/usr`, `/etc`) | No | No |

Key distinctions:

- **dpkg/apt** requires root and mutates the shared rootfs. Every user sees
  the same installed packages.

- **Nix profiles** are per-user with shared store deduplication. APM uses the
  same model but builds profiles in Rust (no Nix daemon needed, faster, no
  dead store paths).

- **APM** adds an apt-familiar CLI, named packages with registries, and a
  pre-built guarantee on top of the Nix per-user profile model.
