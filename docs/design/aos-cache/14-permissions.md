# Permissions Model

> Part of the [AOS Cache Design](README.md)

## Directory Ownership

`/var/lib/aos` hosts both Nix-managed and AOS-managed directories. Ownership
is split by responsibility:

| Directory | Owner | Group | Mode | Manager |
|-----------|-------|-------|------|---------|
| `/var/lib/aos/` | `root` | `root` | `0755` | System init |
| `/var/lib/aos/store/` | `root` | `nix-daemon` | `1775` | Nix daemon |
| `/var/lib/aos/var/nix/` | `root` | `nix-daemon` | `0755` | Nix daemon |
| `/var/lib/aos/var/nix/db/` | `root` | `nix-daemon` | `0755` | Nix daemon |
| `/var/lib/aos/var/nix/gcroots/` | `root` | `nix-daemon` | `0755` | Nix daemon |
| `/var/lib/aos/gcroots/` | `aos-serve` | `nix-daemon` | `0775` | aos-serve |
| `/var/lib/aos/gcroots/{view}/bin/` | `aos-serve` | `nix-daemon` | `0775` | aos-serve |
| `/var/lib/aos/gcroots/{view}/src/` | `aos-serve` | `nix-daemon` | `0775` | aos-serve |
| `/var/lib/aos/meta/` | `aos-serve` | `nix-daemon` | `0750` | aos-serve |
| `/var/lib/aos/views/` | `aos-serve` | `nix-daemon` | `0750` | aos-serve |
| `/run/aos/` | `aos-serve` | `nix-daemon` | `0750` | systemd (RuntimeDirectory) |
| `/var/log/aos/` | `aos-serve` | `nix-daemon` | `0750` | systemd (LogsDirectory) |

## How AOS Coexists with the Nix Daemon

The `aos-serve` process supplements the Nix daemon as an "overlay" agent. It
does not modify Nix-managed directories directly — instead it coordinates
through the daemon's public interface:

1. **Building**: `aos-serve` calls `nix-store --realise` which communicates
   with the Nix daemon via its Unix socket. The daemon does all store
   writes, sandbox execution, output signing, and hash verification.

2. **Reading store metadata**: `aos-serve` reads `/var/lib/aos/var/nix/db/db.sqlite`
   directly (read-only) to serve narinfo responses. This requires `nix-daemon`
   group membership for read access.

3. **GC root management**: `aos-serve` creates/removes symlinks in
   `/var/lib/aos/gcroots/{view}/` — a directory it owns. The Nix GC
   discovers these through the indirect root:
   ```
   /var/lib/aos/var/nix/gcroots/aos -> /var/lib/aos/gcroots
   ```
   This symlink is created by the system init (image build or activation
   script), not by `aos-serve` at runtime.

4. **Metadata and views**: `aos-serve` writes JSON metadata to `meta/` and
   build state to `views/` — directories it owns exclusively.

## Users and Groups

| Identity | Purpose |
|----------|---------|
| `root` | Nix daemon process owner; owns store and state dirs |
| `nix-daemon` (group) | Read access to Nix DB; group-write on store |
| `aos-serve` (user) | Dedicated service user for `aos serve` |
| `aos-admins` (group) | Users allowed to manage tokens via Unix socket |

The `aos-serve` user is a member of the `nix-daemon` group. This grants:
- Read access to `/var/lib/aos/var/nix/db/db.sqlite` (narinfo queries)
- The ability to invoke `nix-store` commands that talk to the daemon socket

## Indirect GC Root

The critical link between AOS GC roots and the Nix garbage collector:

```
/var/lib/aos/var/nix/gcroots/aos -> /var/lib/aos/gcroots
```

This is an **indirect GC root**. When `nix-store --gc` runs, it:
1. Scans `/var/lib/aos/var/nix/gcroots/` for symlinks
2. Finds `aos` → follows it to `/var/lib/aos/gcroots/`
3. Recursively scans all `{view}/{ns}/{hash}` symlinks within
4. Each symlink points to a store path → that path is live (not collected)

**Creation**: This symlink is created once during system initialization (the
NixOS activation script or image build), not by `aos-serve` at runtime. It
lives in a Nix-owned directory and must be created by root.

## systemd Hardening

The `aos-serve.service` unit restricts filesystem access:

```ini
User=aos-serve
Group=nix-daemon
SupplementaryGroups=aos-admins

# AOS root contains both Nix and AOS dirs — grant full access
ReadWritePaths=/var/lib/aos /var/log/aos /run/aos

# Standard hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
LimitNOFILE=1048576
```

Since `/var/lib/aos` contains everything (store, state, gcroots, meta, views),
a single `ReadWritePaths=/var/lib/aos` is sufficient. The Nix store integrity
is protected by the daemon — `aos-serve` cannot write to `store/` or `var/nix/`
directly because it runs as `aos-serve` (not root), and those directories
are owned by root. The daemon enforces all store mutations.

## No Permission Conflicts

There are no permission conflicts because responsibilities are cleanly separated:

- **Nix daemon** (root): writes to `store/`, `var/nix/db/`, `var/nix/gcroots/`
- **aos-serve** (aos-serve user): writes to `gcroots/`, `meta/`, `views/`
- **System init** (root): creates `/var/lib/aos` directory tree and indirect GC root symlink

The only shared access is `aos-serve` reading the Nix DB (via group membership)
and the Nix GC reading AOS gcroots (via the indirect symlink). Both are
read-only from the perspective of the non-owning process.
