# Daemon operation

`crucible serve` exposes the lifecycle control API over cleartext HTTP/2. It is
useful for control-plane development and local/remote conformance testing.

It is not currently a production remote-QEMU service. The packaged server
constructs a quiescent lifecycle loop rather than the production QEMU lifecycle
used by local `run`. This is the most important constraint on daemon operation:
remote and local commands share the API shape, but they do not currently share
backend fidelity.

## Start a daemon

Bind a loopback listener:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9000 \
  --max-sessions 32
```

The server prints the resolved `http://` endpoint. `--max-sessions` must be
greater than zero.

Use `--read-only` to reject mutating API calls:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9000 \
  --read-only
```

Read-only mode is for query/watch clients. It cannot host normal run creation or
control workflows.

The process handles `SIGINT` and `SIGTERM`, requests server shutdown, and allows
a short drain interval before exiting.

## Connect a client

Pass either a host and port or a complete endpoint:

```sh
./result/bin/crucible \
  --daemon 127.0.0.1:9000 \
  --format table \
  run scenario.toml
```

If the value has no URI scheme, the client prepends `http://`. The equivalent
explicit spelling is:

```text
--daemon http://127.0.0.1:9000
```

## Current remote command coverage

The control client has concrete remote workflows for:

- `run`;
- `verify`;
- `save`; and
- `resume`, including its interactive command path.

Current restrictions include:

- `fork`, `search`, and `fuzz` are local-only;
- artifact `replay` refuses a daemon route because the client cannot validate
  producer build provenance remotely;
- `serve --daemon ...` is invalid because a server cannot route itself to
  another daemon; and
- the current daemon backend does not start packaged QEMU guests.

## Security boundary

The server currently binds an unauthenticated cleartext HTTP/2 endpoint. Bind it
to loopback or a trusted development network. Do not expose it directly to an
untrusted network and do not infer authentication, authorization, or TLS from
the higher-level registry services elsewhere in AOS.

## Intended evolution

RFC-0010 targets local/remote equivalence: the daemon should host the same
session actor and production backend as local execution, differing only in
transport. That is not yet the shipped behavior. Remove this experimental
warning only after `serve` constructs the production QEMU lifecycle and a live
conformance test proves canonical-output equivalence.
