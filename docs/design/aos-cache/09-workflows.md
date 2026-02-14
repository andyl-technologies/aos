# Build & Read Workflows

> Part of the [AOS Cache Design](README.md)

## Trust Model

```
                           TRUST BOUNDARY
                               │
  Client (untrusted)           │        Server (trusted)
  ──────────────────           │        ────────────────
                               │
  nix-instantiate              │
  → produces .drv (text)       │
                               │
  copy .drv closure ──────────►│──► store .drv files (safe — text build recipes)
                               │
  copy sources (fetchurl) ────►│──► store sources (safe — content-addressed,
                               │    hash verified by Nix on import)
                               │
  POST /build ────────────────►│──► nix-store --realise .drv
                               │      │
                               │      ├── sandbox build (isolated)
                               │      ├── output hash verification
                               │      ├── daemon signs outputs
                               │      └── build logs → SSE stream
                               │
                     ◄─────────│──── GC roots created for outputs
                               │
  nix build --substituters ───►│──── serve narinfo + NAR (read path)
```

**What crosses the trust boundary**:
- `.drv` files: just text describing how to build. Safe.
- Fixed-output sources: content-addressed, hash-verified on import. Safe.
- Build request: triggers a sandboxed build. Safe.

**What NEVER crosses the trust boundary**:
- Pre-built binaries. The server builds everything itself.

## Build Workflow (Step by Step)

### Client side (`aos build --remote URL`)

```
1. Evaluate locally:
     nix-instantiate ./default.nix -A foo
     → /var/lib/aos/store/{hash}-foo.drv

2. Compute derivation closure:
     nix-store -qR /var/lib/aos/store/{hash}-foo.drv
     → list of .drv files + fixed-output source paths
     (No intermediate build outputs — just recipes and sources)

3. Read server capabilities:
     GET /:view/nix-cache-info
     → Capabilities: pack-upload query-missing sse-logs content-range

4. Batch query what the server needs:
     POST /:view/query-missing {"paths": [...all closure paths...]}
     → {"missing": [...], "fetchable": [...]}

5. Upload missing inputs:
     Partition "missing" (excluding "fetchable") by size:
       Small (.drv + sources < 10MB) → bundle into one pack POST
         POST /:view/upload-pack  (all .drv files in a single stream)
       Large (sources > 10MB) → parallel individual PUTs (8 connections)
         PUT /:view/store/{hash}  (with Content-Range resume on failure)

6. Request build:
     POST /:view/build?drv=/var/lib/aos/store/{hash}-foo.drv

7. Stream build logs from SSE response:
     event: status → update progress display
     event: log    → print to terminal
     event: complete → report success + output paths
     event: error  → report failure + log tail

8. Report: "built /var/lib/aos/store/zzz-foo in 2m34s (pack: 47 .drv, uploaded: 3 sources)"
```

**On a warm server** (has built things before): step 3 returns mostly empty
missing list. The server already has gcc, glibc, coreutils, etc. Only new
or changed derivations and their sources need uploading. Step 4 takes
seconds instead of minutes.

**On a cold server** (first build ever): the full derivation closure is
uploaded. This is the same as the first build on any CI system — subsequent
builds are incremental.

### Server side (handling POST /build)

```
1. Authenticate bearer token (build permission for view)

2. Verify .drv exists in local store
   → 400 if not found (client must PUT .drv first)

3. Check if outputs already realised:
     nix-store --query --outputs /var/lib/aos/store/{hash}.drv
     → if all outputs exist in store, skip to step 7

4. Start SSE response stream
   Send: event: status {"phase": "building"}

5. Build via Nix daemon:
     nix-store --realise /var/lib/aos/store/{hash}.drv
     - Daemon fetches any missing sources (fetchurl)
     - Daemon builds input derivations recursively
     - Daemon executes build in sandbox
     - Daemon verifies output hash
     - Daemon signs output with its key
   Stream stderr → SSE event: log (line by line)

6. On failure:
     Send: event: error {"exit_code": 1, "log_tail": "..."}
     → DO NOT create GC roots for partial outputs
     → Respond with final status

7. On success — create binary roots:
     Compute runtime closure of outputs:
       nix-store -qR /var/lib/aos/store/{output}
     For each path in closure:
       Create GC root (atomic):
         ln -s /var/lib/aos/store/{hash}-{name} gcroots/{view}/bin/{hash}.tmp
         mv gcroots/{view}/bin/{hash}.tmp gcroots/{view}/bin/{hash}
       Write metadata JSON (atomic: .tmp + fsync + rename):
         meta/{view}/bin/{hash}.json
         {"store_path": "...", "pushed_at": ..., "expires_at": ...}

8. Create source roots (if source_mirror enabled):
     Enumerate fixed-output source inputs from the .drv
     For each source path:
       Create GC root (atomic):
         ln -s /var/lib/aos/store/{hash}-{src} gcroots/{view}/src/{hash}.tmp
         mv gcroots/{view}/src/{hash}.tmp gcroots/{view}/src/{hash}
       Write metadata JSON (with source_ttl):
         meta/{view}/src/{hash}.json
         {"store_path": "...", "pushed_at": ..., "expires_at": ...,
          "source_of": ["/var/lib/aos/store/{drv}"]}

9. Send: event: complete {"outputs": [...], "bin_roots": N, "src_roots": M}
```

**Key principle**: The Nix daemon is the sole authority for building and
signing. We never import pre-built outputs. A build either succeeds
completely (daemon built + signed + GC rooted) or fails cleanly (no
partial state).

---

## Read Workflow (Step by Step)

### narinfo request

```
GET /ci/abc123.narinfo
           │
           ▼
  ┌── Auth check: token has "read" on "ci" view ──┐
  │                                                 │
  │  Fail → 401/403                                │
  │  Pass ↓                                         │
  ├── Visibility check (all namespaces) ─────────────┤
  │   readlink /var/lib/aos/gcroots/ci/bin/abc123    │
  │   readlink /var/lib/aos/gcroots/ci/src/abc123    │
  │                                                 │
  │   No symlink in any namespace → 404              │
  │   Symlink → /var/lib/aos/store/abc123-foo      │
  │   ↓                                             │
  ├── Query metadata (SQLite direct read) ──────────┤
  │   SELECT path, hash, narSize, deriver, sigs     │
  │   FROM ValidPaths WHERE path = ?                │
  │   + JOIN Refs for references                    │
  │                                                 │
  ├── Format narinfo (nix_compat) ──────────────────┤
  │   StorePath: /var/lib/aos/store/abc123-foo      │
  │   URL: nar/abc123-{narhash}.nar.zst             │
  │   NarHash: sha256:{base32}                      │
  │   ...                                           │
  │   Sig: {server-key}:{base64}                    │
  │                                                 │
  └── Respond 200, text/x-nix-narinfo ─────────────┘
```

### NAR request

```
GET /ci/nar/{narhash}.nar.zst
           │
           ▼
  ┌── Auth check ──────────────────────────────────┐
  │                                                 │
  ├── Resolve narhash to store path ────────────────┤
  │   (maintain an in-memory narHash→path cache     │
  │    populated when serving narinfo)              │
  │                                                 │
  ├── Stream NAR ───────────────────────────────────┤
  │   Spawn: nix-store --dump /var/lib/aos/store/abc123-foo
  │   Pipe stdout → zstd compressor → HTTP body     │
  │   (tokio::process::Command + AsyncRead)         │
  │                                                 │
  └── Respond 200, application/x-nix-nar ──────────┘
```

### Performance: narHash → path resolution

The server needs to map NAR hashes to store paths. Options:

1. **On-demand**: when serving narinfo, include the store path hash in the
   URL (`nar/{store-hash}-{narhash}.nar.zst`). The store hash lets us
   directly resolve to a path. This is what nix-serve does.
2. **In-memory cache**: LRU cache mapping narHash → storePath, populated
   when narinfo is served. Cache misses fall back to a full scan (rare).

**Recommendation**: Option 1 — encode the store path hash in the URL.
This is the nix-serve approach and avoids any caching/lookup complexity:

```
URL: nar/{store-path-hash}-{narhash}.nar.zst
```

The Nix client uses the URL from the narinfo response verbatim, so the
format doesn't matter as long as it's consistent.
