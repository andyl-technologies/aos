# Unix Socket Architecture

All local communication with the AOS daemon uses Unix sockets. There are no HTTP endpoints, no UCAN on sockets, no tokens on sockets. Auth is purely:
- **SO_PEERCRED** for the host control socket (maps uid/gid to capabilities via local policy)
- **Socket-as-credential** for container/view sockets (the socket path implies the scope -- if you can connect, you're authorized at that scope)

Three socket types, three daemon modes, arbitrary nesting depth.

## Socket Types

### Control Socket (host-only)

```
/run/aos/control.sock
  Auth: SO_PEERCRED (real uid/gid from the host)
  Scope: all views, capabilities determined by local policy
  Used by: host users running `aos build`, `aos gc`, etc.
```

```toml
[control]
socket = "/run/aos/control.sock"
socket_group = "aos"

[control.groups]
aos-admin = ["submit", "observe", "manage", "fetch"]
aos-build = ["submit", "observe"]
aos-read  = ["observe"]
```

### View Socket (service containers, multi-user containers)

```
/run/aos/sockets/view-{name}.sock
  Auth: socket-as-credential (socket path = scope)
  Scope: one specific view, fixed capabilities
  Used by: containers that need to interact with a specific view
  Bind-mounted into container as: /run/aos/upstream.sock (for forwarding daemons)
                                  or /run/aos/control.sock (for single-process containers)
```

For nested view names like `profiles/dylan`, the socket path uses a flat
encoding with hyphens: `view-profiles-dylan.sock`. Slashes in the view name
are replaced with hyphens in the socket filename.

Created by the host daemon for each configured view. The daemon maps: socket fd -> view name -> capabilities.

### Build Socket (ephemeral, per-build)

```
/run/aos/sockets/build-{drv-hash}.sock
  Auth: socket-as-credential
  Scope: one ephemeral view, restricted capabilities only
  Capabilities: [path-info, register-output] -- NOTHING else
  Used by: build containers
  Bind-mounted into container as: /run/aos/control.sock
  Destroyed when build completes
```

### Summary table

```
+-------------------------+--------------+--------------+---------------------------+
| Socket                  | Auth         | Scope        | Capabilities              |
+-------------------------+--------------+--------------+---------------------------+
| control.sock            | SO_PEERCRED  | All views    | Per uid/gid policy        |
| view-{name}.sock        | Socket path  | One view     | submit, observe, path-info|
| build-{hash}.sock       | Socket path  | One ephemeral| path-info, register-output|
+-------------------------+--------------+--------------+---------------------------+
```

## Daemon Modes

Same `aos daemon` binary, three modes:

### Full Mode
- Owns a real Nix store
- Runs builds (nspawn + FUSE + overlay)
- Joins the libp2p mesh (UCAN auth for peers)
- Creates and manages FUSE views (views + ephemerals)
- Listens on control socket + view sockets + build sockets
- This is the "real" daemon on physical hosts and top-level VMs

### Forward Mode
- No Nix store, no FUSE, no mesh, no builds
- Just a socket proxy with SO_PEERCRED auth
- Listens on its own control socket for local users
- Forwards authorized requests to an upstream socket
- Relays responses back
- Extremely lightweight (~200 lines of real logic)
- Used inside multi-user containers and VMs

### Auto-detection

```rust
fn detect_mode(config: &Config) -> DaemonMode {
    match config.daemon.mode {
        Some(mode) => mode,  // explicit config always wins
        None => {
            if Path::new("/run/aos/upstream.sock").exists() {
                DaemonMode::Forward
            } else {
                DaemonMode::Full
            }
        }
    }
}
```

If `/run/aos/upstream.sock` exists on startup, the daemon enters forwarding mode (unless explicitly overridden). Containers just need:
```
--bind=/run/aos/sockets/view-staging.sock:/run/aos/upstream.sock
```

Then `aos daemon` inside auto-detects. Minimal config:
```toml
# /etc/aos/daemon.toml inside the container
# No [daemon] section needed -- mode auto-detected
[control]
socket_group = "developers"

[control.groups]
developers = ["submit", "observe"]
ops = ["submit", "observe", "manage"]
```

### Nested Mode (Full daemon inside a container)

A container runs a full daemon with its own store, its own views/ephemerals, and its own FUSE views. It communicates with the parent daemon via an upstream socket for fetching paths it doesn't have locally.

```toml
[daemon]
mode = "full"  # explicit override -- don't auto-detect forward mode

[forward]
upstream = "/run/aos/upstream.sock"  # parent daemon's view socket
# Used for: fetching NARs, submitting builds upstream

[p2p]
# Can optionally join the mesh too
listen_addr = "/ip4/0.0.0.0/udp/4001/quic-v1"
```

## Capability Intersection

The forwarding daemon's effective scope = `upstream_socket_scope INTERSECT local_user_policy`:

```
Host creates: view-staging.sock -> scope: [submit, observe, path-info]
  bind-mounted into VM as: /run/aos/upstream.sock

VM's forwarding daemon local policy:
  developers = [submit, observe]
  readonly   = [observe]

Developer (uid 1000):
  local policy: [submit, observe]
  upstream scope: [submit, observe, path-info]
  effective: [submit, observe]  <-- intersection

Readonly user (uid 1001):
  local policy: [observe]
  upstream scope: [submit, observe, path-info]
  effective: [observe]  <-- intersection
```

No escalation path. Security is layered: upstream scope is the ceiling, local policy further restricts within that ceiling.

## Forwarding Implementation

```rust
struct ForwardingDaemon {
    control_socket: PathBuf,
    upstream_socket: PathBuf,
    policy: AuthPolicy,
}

impl ForwardingDaemon {
    async fn handle_connection(&self, local: UnixStream) -> Result<()> {
        let cred = local.peer_cred()?;
        let caps = self.policy.capabilities_for(cred.uid(), cred.gid());

        let upstream = UnixStream::connect(&self.upstream_socket).await?;
        let (local_read, mut local_write) = local.into_split();
        let (upstream_read, mut upstream_write) = upstream.into_split();

        // Forward requests (with auth check)
        let caps_clone = caps.clone();
        let fwd = tokio::spawn(async move {
            let mut lines = BufReader::new(local_read).lines();
            while let Some(line) = lines.next_line().await? {
                let req: Request = serde_json::from_str(&line)?;
                if caps_clone.allows(&req.action) {
                    upstream_write.write_all(line.as_bytes()).await?;
                    upstream_write.write_all(b"\n").await?;
                } else {
                    // Send rejection directly to client
                    let err = serde_json::to_string(&Response::error("permission denied"))?;
                    // (written to local_write via a channel -- simplified here)
                }
            }
            Ok::<_, anyhow::Error>(())
        });

        // Relay responses (pass-through)
        let relay = tokio::spawn(async move {
            tokio::io::copy(&mut upstream_read, &mut local_write).await
        });

        tokio::try_join!(fwd, relay)?;
        Ok(())
    }
}
```

## Multi-Level Nesting

### Level 1: Simple containers (no daemon inside)

```
Host (full daemon)
  |-- control.sock (host users, SO_PEERCRED)
  |-- view-staging.sock
  |    +-- Container A (single app, no daemon inside)
  |         +-- /run/aos/control.sock -> view-staging.sock
  |              App connects directly, gets staging scope
  +-- build-{hash}.sock
       +-- Container B (build, no daemon inside)
            +-- /run/aos/control.sock -> build-{hash}.sock
                 Build process gets restricted scope
```

### Level 2: Forwarding daemon inside container

```
Host (full daemon)
  +-- view-staging.sock
       +-- VM (forwarding daemon inside)
            |-- /run/aos/upstream.sock -> view-staging.sock
            |-- /run/aos/control.sock (VM's own, SO_PEERCRED)
            |
            |-- User A (uid 1000, aos-dev) -> [submit, observe]
            |    $ aos build foo -> control.sock -> forwarding daemon
            |    -> checks SO_PEERCRED -> allowed -> forwards to upstream
            |    -> host daemon executes build, streams response back
            |
            +-- User B (uid 1001, aos-read) -> [observe]
                 $ aos build foo -> REJECTED by forwarding daemon
```

### Level 3: Full daemon inside container (nested views)

```
Host (full daemon, store at /var/lib/aos/store)
  +-- view-staging.sock
       +-- VM (full daemon, own store at /var/lib/aos/store)
            |-- /run/aos/upstream.sock -> view-staging.sock (for upstream fetches)
            |-- /run/aos/control.sock (VM's own, SO_PEERCRED)
            |
            |-- VM has its OWN views:
            |    |-- view "dev" (VM-local view)
            |    |    |-- FUSE mount at /run/aos/views/dev/
            |    |    |-- GC policy: ttl=24h
            |    |    +-- view-dev.sock
            |    |
            |    +-- view "test" (VM-local view)
            |         |-- FUSE mount at /run/aos/views/test/
            |         +-- view-test.sock
            |
            |-- VM creates its own build containers:
            |    +-- Container C (build for "dev" view)
            |         |-- /run/aos/control.sock -> build-{hash}.sock
            |         |-- /nix/store -> FUSE (ephemeral view of VM's store)
            |         +-- Build runs, output rooted in VM's "dev" view
            |
            |-- When VM needs a path it doesn't have:
            |    +-- VM's daemon fetches from upstream socket
            |         -> host daemon serves from its store
            |         -> VM's daemon imports into its own store
            |         -> VM's daemon roots in appropriate view
            |
            +-- VM users work with VM-local views:
                 $ aos build foo --view dev
                 -> VM's daemon builds locally (nspawn inside VM)
                 -> or forwards upstream if needed
```

### Level N: Arbitrary nesting

```
Host daemon (full)
  +-- View socket
       +-- VM daemon (full, own store)
            +-- View socket
                 +-- Container daemon (forwarding OR full)
                      +-- View socket
                           +-- ... (more levels)
```

Each level:
1. Has its own control socket with SO_PEERCRED
2. Has its own local auth policy
3. Can create view and build sockets for its children
4. Can forward to its parent via upstream socket
5. Capabilities only narrow at each level (intersection)

### Path fetching through levels

When a nested daemon needs a store path it doesn't have:

```
Container daemon (level 3) needs gcc:
  1. Check local store -> not found
  2. Check mesh peers -> not found (or not on mesh)
  3. Fetch from upstream socket:
     {"action": "fetch", "hash": "abc123"}
     -> VM daemon (level 2) receives
     -> Check VM's local store -> not found
     -> Fetch from VM's upstream socket:
        {"action": "fetch", "hash": "abc123"}
        -> Host daemon (level 1) receives
        -> Found in store -> streams NAR back
     -> VM daemon imports into its store
     -> Streams NAR back to container daemon
  -> Container daemon imports into its store
```

Each daemon is self-contained. It doesn't know how many levels deep it is. It just has: local store, optional upstream, optional mesh.

## Socket Protocol Extensions for Nesting

The control socket JSON-line protocol needs these commands for nested daemons:

```json
// Fetch a store path from upstream (used by nested daemons)
{"action": "fetch", "hash": "abc123"}
-> {"ok": true, "path": "/nix/store/abc123-gcc-14.2.0", "nar_size": 50000000}
// (NAR data follows on the stream)

// Query if upstream has a path
{"action": "has-path", "hash": "abc123"}
-> {"ok": true, "exists": true}

// Submit a build upstream (forwarding daemon)
{"action": "build", "attr": "pkgs.foo", "view": "staging"}
-> {"ok": true, "drv_hash": "xyz789"}
// (log lines follow on the stream)

// Watch build logs
{"action": "watch", "drv_hash": "xyz789"}
-> (log lines streamed)
```

## Security Properties

1. **No tokens on sockets** -- auth is purely structural (socket path) and kernel-mediated (SO_PEERCRED)
2. **No escalation** -- capabilities only narrow through nesting (intersection at each level)
3. **No information leakage** -- a forwarding daemon only forwards requests within its scope; out-of-scope requests are rejected locally, never reaching upstream
4. **Crash isolation** -- a forwarding daemon crash doesn't affect the upstream daemon or other containers; clients just see connection refused until restart
5. **Zero config for simple cases** -- single-process containers don't need a daemon inside; auto-detection handles forwarding mode

## Relationship to UCAN

UCAN is used for **mesh-level** (peer-to-peer) authentication between daemons. Unix sockets are used for **local** (same-machine or same-container) communication. They are separate layers:

```
User -> (Unix socket + SO_PEERCRED) -> Local daemon -> (libp2p + UCAN) -> Remote daemon
                                    -> (Unix socket, upstream) -> Parent daemon
```

The two auth mechanisms never mix. Sockets don't carry UCANs. The mesh doesn't use sockets.
