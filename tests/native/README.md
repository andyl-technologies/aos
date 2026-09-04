# Native Hub settings verification

`hub-settings.py` starts the actual native Hub executable with a fresh SQLite
database, uses password login and the session-token exchange over TCP, creates
its fixture through reviewed public APIs, and drives `aos hub delivery`.
It exercises confirmation rejection, explicit credentials with an expired
stored profile, replay, process restart, concurrent resume, blocked activation,
and unchanged audience selections. It never inserts database observations.

Build the binaries and interpreter from the AOS package set:

```sh
hub=$(nix-build -A pkgs.aos-hub --no-out-link)
client=$(nix-build -A pkgs.aos --no-out-link)
python=$(nix-build -A pkgs.python3 --no-out-link)
"$python/bin/python3" tests/native/hub-settings.py \
  --hub-binary "$hub/bin/aos-hub" --aos-binary "$client/bin/aos" \
  --require-assets
```

For incremental testing, binaries built with `nix develop -c cargo build` can
also be passed explicitly. The native Hub build must receive
`AOS_HUB_CONSOLE_JS`, `AOS_HUB_CONSOLE_WASM`, and `AOS_HUB_CONSOLE_CSS` from the
current `pkgs.aos-hub-console-dist` output. The test rejects development fallback
assets. It retains its private temporary directory, server log, and JSON check
record for diagnosis, and terminates its own server on completion or failure.

The same script is wired into `checks.vm.hub-settings`:

```sh
nix-build -A checks.vm.hub-settings
```

That check boots a VM and runs the native process test as an unprivileged user
with AOS-built dependencies. It requires the repository's VM/KVM infrastructure.

## Browser verification

Add `--keep-running` to retain the server after the process checks. Alternatively,
`--serve-only` prepares the organization, registry, cache, and storage fixture
without running delivery CLI assertions. The script prints the loopback URL and
a private password-file path for browser testing.

Run the browser helper with an installed Chrome-compatible executable:

```sh
"$python/bin/python3" tests/native/hub-settings-browser.py \
  --browser /path/to/google-chrome-stable \
  --url http://127.0.0.1:PORT \
  --email operator@example.test \
  --password-file /tmp/aos-hub-settings-FIXTURE/browser-password \
  --output-dir /tmp/aos-hub-browser-results
```

This optional external validation tool uses only Python's standard library and
Chrome's debugging pipe. It creates an isolated browser profile and records
rendered-page assertions, browser errors, and desktop/narrow screenshots. Chrome
is not introduced as a Hub package dependency. Stop the fixture with Ctrl-C after
inspection.

## Coverage limits

The fixture's CDN is intentionally unconfigured: verification must fail and
activation must remain unavailable. Successful external CDN activation also
requires an actual provider mapping, an authorized gateway controller report,
and current route evidence. A process-test pass does not establish that positive
provider path or deployed Worker latency. VM evaluation alone does not establish
a VM runtime pass; record those results separately.
