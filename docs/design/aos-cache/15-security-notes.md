# Security Notes

> Part of the [AOS Cache Design](README.md)

This section captures security considerations identified during design review.

## Socket Permissions

Two Unix sockets serve different purposes:

| Socket | Purpose | Permissions |
|--------|---------|-------------|
| `/run/aos/http.sock` | HTTP API listener (reverse proxy target) | `aos-serve:nix-daemon 0660` |
| `/run/aos/bootstrap.sock` | Token provisioning (SO_PEERCRED auth) | `aos-serve:aos-admins 0660` |

The bootstrap socket uses `SO_PEERCRED` to identify the connecting process's
UID/GID. Only processes running as root or in the `aos-admins` group can
connect (enforced by socket file permissions and verified via `SO_PEERCRED`).

## Token Storage

`/var/lib/aos/meta/tokens.db` stores provisioning secrets (hashed with Argon2)
and must be readable only by `aos-serve`:

```
-rw------- aos-serve nix-daemon /var/lib/aos/meta/tokens.db
```

If the DB file were group-readable, any process in the `nix-daemon` group
could read hashed secrets. The `0600` mode prevents this.

## JWT Lifetime

Short-lived JWTs (1-hour default) limit the blast radius of a leaked token.
The server validates JWTs against the provisioning secret that issued them —
revoking a provisioning secret (`aos token revoke`) invalidates all JWTs
derived from it, even before their natural expiry.

## GC Root Symlink Integrity

AOS per-view GC root symlinks (`/var/lib/aos/gcroots/{view}/{ns}/{hash}`,
where `{ns}` is `bin` or `src`) must point to valid store paths. The
`aos-serve` process creates these atomically:

```sh
ln -s /var/lib/aos/store/{hash}-{name} /var/lib/aos/gcroots/{view}/bin/{hash}.tmp
mv /var/lib/aos/gcroots/{view}/bin/{hash}.tmp /var/lib/aos/gcroots/{view}/bin/{hash}
```

This prevents a partially-written symlink from being visible to the Nix GC.

## Build Log Confidentiality

Build logs may contain sensitive information (environment variables, build
errors revealing internal paths). Logs are:

1. Streamed only to authenticated clients with `build` or `read` permission
   on the specific view
2. Stored in `/var/log/aos/builds/{drv-hash}.log` (owned by `aos-serve`)
3. Also persisted by Nix to `/var/lib/aos/var/log/nix/drvs/` (owned by root)

The Nix-managed logs are accessible to the `nix-daemon` group. The AOS-managed
logs under `/var/log/aos/` are restricted to `aos-serve` only.

## Store Path Validation

The server rejects uploaded paths that are not `.drv` files or fixed-output
derivations. This prevents a compromised client from pushing arbitrary
pre-built binaries into the store. The Nix daemon provides the final
enforcement — it verifies content hashes on import and refuses paths that
don't match their declared hash.

## No Pre-Built Binary Imports

This is the fundamental security property: the server **never** imports
pre-built binaries from clients. All outputs are produced by the local Nix
daemon in a sandbox. The daemon:

1. Verifies all input hashes
2. Executes builds in a sandboxed environment
3. Verifies output hashes match the derivation
4. Signs outputs with the server's key

A compromised client can only submit build recipes (`.drv` files) and
content-addressed sources — it cannot inject tampered binaries.
