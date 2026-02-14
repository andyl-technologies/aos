# Comparison to Existing Approaches

> Part of the [AOS Cache Design](README.md)

## vs. Nix Remote Builds (ssh-ng://)

`aos serve` implements the same three daemon operations as `ssh-ng://`
remote builds — `IsValidPath`, `AddToStore`, `BuildPaths` — but over
HTTP instead of SSH. The semantics are identical; the transport is better.

| Aspect | ssh-ng:// | aos (HTTP) |
|--------|-----------|------------------|
| Input transfer | Serial, one pipe | **Parallel**, multiple connections |
| Resume | No — restart closure copy | **Yes** — Content-Range for large files |
| Timeout | `connect-timeout` ignored (#7459) | Standard HTTP timeouts |
| Binary safety | TTY escape corruption possible | Binary-safe by design |
| Log streaming | Stderr over SSH pipe | SSE — reconnectable, structured |
| Build results | Copy outputs back over SSH | Stay in server store, serve via cache |
| Error handling | Pipe error = opaque | HTTP status per operation |
| Warm server | Must re-query every path | Batch `query-missing` in one round-trip |

The critical improvement: **build outputs stay on the server**. With
`ssh-ng://`, outputs must be copied back to the client over SSH (another
serial, non-resumable transfer). With `aos serve`, outputs are GC-rooted
in the view and served via the standard binary cache protocol — any client
can substitute from the cache.

## vs. Attic

The nix-expert's analysis identified these concrete problems:

1. **Accepts arbitrary pre-built binaries**: Attic's upload protocol accepts
   NAR files from clients and imports them directly. A compromised client
   can push a tampered binary that won't match its derivation. Attic relies
   on NAR hash verification, but that only checks internal consistency, not
   that the binary matches its claimed build recipe. We build everything
   locally — the daemon ensures outputs match their derivations.

2. **6-table relational schema with state machines**: Attic tracks NARs through
   `PendingUpload → Valid` states in PostgreSQL. We use atomic file operations
   instead — a path is either fully imported or it doesn't exist.

2. **Connection pool exhaustion under load** (attic issue #24): PostgreSQL
   connection pooling is a solved problem, but only if you need a database. We
   don't.

3. **FastCDC chunked dedup prevents S3 redirects**: For multi-chunk NARs,
   attic must reassemble chunks server-side, defeating the CDN/S3 redirect
   optimization. We serve whole NARs from the store — one `nix store dump-path`
   pipe per request, trivially CDN-cacheable.

4. **No token revocation** (attic issue #34, most-requested feature): Attic's
   JWT tokens are stateless, making revocation fundamentally hard. We store
   provisioning secrets in SQLite — `aos token revoke` deletes the secret
   immediately, and short-lived JWTs (1-hour) bound to it expire naturally.

5. **No declarative cache configuration** (attic issue #169): Caches must be
   created via CLI commands. Our views are declarative in TOML.

6. **512MB+ RAM for basic operation**: Attic buffers and chunks NARs in memory.
   We stream everything — memory usage is bounded by the zstd compression
   window (~128KB default).
