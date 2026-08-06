# Daemon operation

`crucible serve` exposes the lifecycle control API over HTTP/2. Remote service
uses mutual TLS: the server authenticates every client certificate against an
explicit client CA, and clients authenticate the server against an explicit CA.
Cleartext service is available only through an explicit trusted-network option.

By default the server constructs a quiescent lifecycle loop for API testing.
Pass `--production-qemu` to host inline scenarios with the same packaged QEMU
lifecycle used by local execution. Production service requires the packaged
kernel, root image, patched QEMU, plugin, and standalone debugger gateway.

## Start a daemon

Start an authenticated listener:

```sh
./result/bin/crucible serve \
  --listen 0.0.0.0:9000 \
  --tls-cert server.crt \
  --tls-key server.key \
  --client-ca clients-ca.crt \
  --production-qemu \
  --debug-role 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef=observe,control \
  --max-sessions 32
```

All three TLS paths are required together. The server advertises HTTP/2 only,
requires a client certificate during the TLS handshake, and derives the
authenticated transport identity from the leaf-certificate SHA-256 fingerprint.
The server prints the resolved `https://` endpoint. `--max-sessions` must be
greater than zero.

Each repeatable `--debug-role` maps the lowercase SHA-256 fingerprint of one
client leaf certificate to a closed set of capabilities: `observe`, `control`,
`mutate`, `shell`, and `admin`. Duplicate fingerprints and unknown capabilities
are rejected. Certificates without a mapping have no debugger access, even
though they may use the ordinary lifecycle API.

For an isolated development network, cleartext must be opted into explicitly:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9000 \
  --trusted-unauthenticated-bind
```

Do not use this option on an untrusted interface. It cannot be combined with
the mutual-TLS flags. The trusted cleartext listener receives all debugger
capabilities; this is intentionally conspicuous and suitable only for an
isolated development network.

Use `--read-only` to reject mutating API calls:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9000 \
  --trusted-unauthenticated-bind \
  --read-only
```

Read-only mode is for query/watch clients. It cannot host normal run creation or
control workflows, acquire debugger controller leases, attach a debugger, or
open a writable GDB relay.

The process handles `SIGINT` and `SIGTERM`, requests server shutdown, and allows
a short drain interval before exiting.

## Connect a client

Pass either a host and port or a complete endpoint:

```sh
./result/bin/crucible \
  --daemon https://daemon.example:9000 \
  --daemon-ca server-ca.crt \
  --daemon-cert operator.crt \
  --daemon-key operator.key \
  run scenario.toml
```

The three client TLS paths are required together. The certificate and key are
combined only in memory before constructing the HTTP/2 client.

For an explicitly trusted cleartext endpoint, use:

```text
--daemon http://127.0.0.1:9000 --trusted-unauthenticated-daemon
```

For compatibility, an address without a URI scheme is interpreted as
`http://`; new scripts should use the explicit trusted spelling so their
security assumption is visible.

## Current remote command coverage

The control client has concrete remote workflows for:

- `run`;
- `verify`;
- `save`; and
- `resume`, including its interactive command path; and
- `debug --session ... --node ... attach-gdb`, using an authenticated local
  loopback GDB relay.

Current restrictions include:

- `fork`, `search`, and `fuzz` are local-only;
- artifact `replay` refuses a daemon route because the client cannot validate
  producer build provenance remotely;
- `serve --daemon ...` is invalid because a server cannot route itself to
  another daemon; and
- the default daemon backend is quiescent; use `serve --production-qemu` for
  live guests; and
- a production debug session currently prepares the first VM node's private
  gdbstub, so `--node` must name that node.

## Security boundary

Mutual TLS authenticates the transport. Debugger capabilities and controller
leases are a separate authorization layer: possessing a valid client
certificate does not itself grant `observe`, `control`, `mutate`, `shell`, or
`admin`. The server derives the principal from the transport, never from a
request field. Controller leases are session-owned and generation-checked on
every relay operation. Relay opens can connect only to the loopback endpoint
reported by the session actor, and chunks are bounded to 64 KiB.

## Intended evolution

Unix-socket peer authentication and guest exec/PTY/SSH channels remain planned.
The current remote surface is authenticated HTTP/2 GDB relay only.
