# Ordinary Workers-only compatibility smoke

This fixture starts the ordinary Worker distribution under the existing fleet
Miniflare runner. It uses real HTTPS and persistent SQLite Durable Objects, KV
and local R2. It shares the Native settings fixture's HTTP, password login,
session-token and reviewed API client without changing that fixture.

Select the ordinary `pkgs.aos-hub-worker-dist`, Native `pkgs.aos-hub`, and
`pkgs.aos-hub-console-dist` outputs from one independently verified source
capture. A distribution built with `do-e2e` is not an ordinary smoke input.
Use the AOS-built Python, Node, OpenSSL and `pkgs.miniflare` outputs.
Pass actual realized output paths; this command does not build or deploy them:

```sh
"$python/bin/python3" tests/native/hub-worker-only.py \
  --hub-binary "$hub/bin/aos-hub" \
  --worker-dist "$worker" --console-dist "$console" \
  --node-binary "$node/bin/node" --wrangler-root "$wrangler" \
  --openssl-binary "$openssl/bin/openssl"
```

Run outside the build sandbox as an unprivileged user. The fixture selects a
loopback port and generates a proper local CA and server leaf. It supplies that
CA to Python and the production bootstrap CLI, retaining normal hostname and
certificate verification. No hosting-provider resource is provisioned. The
dummy control-plane token and DNS URL are unused; this smoke performs no domain
verification or cloud operation.

The local configuration explicitly selects `worker_only` and request sharding
`on`. The production `worker bootstrap-root` command sends the password on stdin
and the seal through the private child environment. Checks require password
login 303, cookie/CSRF session exchange, a scoped bearer, reviewed private
organization/registry creation, anonymous refusal, registry website access,
byte-identical selected console assets and registry/session persistence after a
real process restart. Root password login is repeated after restart.

The printed owner-private directory retains `worker-options.json`, TLS keys,
`tls.log`, `bootstrap.log`, `workerd.log` and `checks.json`. Treat the directory
as secret: configuration, cookies and keys must not be published. The JSON
report records selected file hashes and completed checks, not passwords or
tokens. Retain the corresponding package/source receipts separately; file
selection alone does not prove all packages share a source capture.

Source checks that start no Worker are:

```sh
"$python/bin/python3" tests/native/hub-worker-only-tests.py
"$python/bin/python3" tests/native/hub-worker-only.py --help
"$node/bin/node" --check tests/fleet/_hub-worker-runner.cjs
```

A runtime pass establishes local ordinary topology compatibility. It does not
qualify Cloudflare R2, provider credentials, Hybrid DirectRequired transfers,
parallel throughput or the five-machine fleet. Missing independent acceptance
in a healthy Hybrid pair remains a separate negative runtime check.
