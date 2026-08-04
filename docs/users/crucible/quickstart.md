# Tutorial: Run Nginx and Curl in Crucible

This tutorial builds a custom two-VM world and runs it through Crucible's live
QEMU lifecycle. One guest runs Nginx, another runs Curl, and all traffic crosses
a deterministic link owned by Crucible. The scenario passes only after the
Curl guest reports that it received an HTTP 200 response and the scenario's
guest-console assertion becomes satisfied.

Run every command from the repository root on an `x86_64-linux` host. QEMU uses
deterministic software translation, so KVM is not required.

## 1. Build Crucible and the guest

Build the CLI, the workload kernel, and the tutorial guest image:

```sh
nix build .#pkg-crucible -o result-crucible
nix build .#pkg-linux -o result-crucible-kernel
nix build \
  .#crucible-nginx-curl-guest \
  -o result-crucible-nginx-curl
```

The separate guest image contains AOS-built Nginx, Curl, and networking tools.
It has no Crucible agent or instrumentation; its init selects the preinstalled
Nginx or Curl role from ordinary kernel boot arguments. Crucible launches the
image as supplied, puts each node's writes in a disposable overlay, and observes
its ordinary serial output through an output-only host connection instead of
modifying the base image or injecting commands into the guest.

Verify the image before the run:

```sh
sha256sum -c result-crucible-nginx-curl/root.ext4.sha256
```

Check the packaged backend:

```sh
./result-crucible/bin/crucible selftest
```

Production self-tests run the live QEMU gates by default. Stop here and use
[Troubleshooting](troubleshooting.md) if backend discovery or a gate fails.

## 2. Generate the scenario

The generator and runner at
[`crates/crucible-api/examples/crucible-nginx-curl-http-200.rs`](../../../crates/crucible-api/examples/crucible-nginx-curl-http-200.rs)
define:

- an `nginx` VM at `10.0.0.2` and a `curl` VM at `10.0.0.3`;
- a deterministic link between the two nodes;
- an assertion that neither node crashes;
- a guest-console assertion that matches the Curl workload's
  `CURL_STATUS=200` result; and
- a terminal event that passes only after that assertion becomes satisfied.

Build it in the repository development environment:

```sh
nix develop -c cargo build \
  --manifest-path crates/Cargo.toml \
  -p crucible-api \
  --example crucible-nginx-curl-http-200
```

Generate the canonical scenario file:

```sh
crates/target/debug/examples/crucible-nginx-curl-http-200 \
  --emit-scenario > nginx-curl.scenario.toml
```

The generated form should match the repository fixture:

```sh
diff -u \
  tests/crucible/fixtures/nginx-curl-http-200.scenario.toml \
  nginx-curl.scenario.toml
```

An empty diff proves that the Rust model produced the checked canonical form,
including every derived content ID. Regenerate the file instead of editing IDs
by hand.

## 3. Run the scenario

Resolve the immutable build outputs to their Nix store paths:

```sh
crucible_kernel=$(readlink -f result-crucible-kernel/boot/vmlinuz-*)
crucible_root=$(readlink -f result-crucible-nginx-curl/root.ext4)
```

Run the canonical scenario through the packaged CLI and retain its canonical
event log:

```sh
CRUCIBLE_KERNEL="$crucible_kernel" \
CRUCIBLE_ROOT_IMAGE="$crucible_root" \
CRUCIBLE_KERNEL_CMDLINE="console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init" \
  ./result-crucible/bin/crucible \
  --seed 0x200 \
  --format jsonl \
  --trace nginx-curl.run.jsonl \
  run nginx-curl.scenario.toml \
  --max-quanta 10000
```

A successful run exits with status `0`, and its JSONL contains a passing
`final_outcome`. The scenario can pass only after the Curl guest emits
`CURL_STATUS=200`, Crucible records that console observation at a deterministic
scheduler boundary, and the assertion evaluator publishes its satisfied state.

The check does not inspect plaintext Ethernet payloads. It uses ordinary guest
console output as the application-level result, so the same assertion pattern
also works when the request and response travel over HTTPS. No Crucible agent is
required in the guest, and the host side of the console connection is read-only.

Verify that the supplied base image is still byte-for-byte identical:

```sh
sha256sum -c result-crucible-nginx-curl/root.ext4.sha256
```

## 4. Create your own variant

Copy the working generator so the repository example remains unchanged:

```sh
cp \
  crates/crucible-api/examples/crucible-nginx-curl-http-200.rs \
  crates/crucible-api/examples/my-nginx-curl.rs
```

Open `crates/crucible-api/examples/my-nginx-curl.rs` and change the root seed in
`Seed::from_u64` from `0x200` to `0x201`. Build your generator, then emit a
second scenario:

```sh
nix develop -c cargo build \
  --manifest-path crates/Cargo.toml \
  -p crucible-api \
  --example my-nginx-curl
crates/target/debug/examples/my-nginx-curl \
  --emit-scenario > nginx-curl-custom.scenario.toml
```

Compare the scenario identities:

```sh
grep -m1 '^id = ' \
  nginx-curl.scenario.toml \
  nginx-curl-custom.scenario.toml
```

The IDs differ because the seed is part of the immutable scenario definition.
Run your variant with the same unmodified guest image:

```sh
CRUCIBLE_KERNEL="$crucible_kernel" \
CRUCIBLE_ROOT_IMAGE="$crucible_root" \
CRUCIBLE_KERNEL_CMDLINE="console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init" \
  ./result-crucible/bin/crucible \
  --seed 0x201 \
  --format jsonl \
  --trace nginx-curl-custom.run.jsonl \
  run nginx-curl-custom.scenario.toml \
  --max-quanta 10000
```

You now have two independently addressed scenario definitions, both exercised
against the same guest bytes. Continue with [Scenarios](scenarios.md) to model
faults and additional properties, then use
[Reproduction and branching](reproduction.md) to retain and investigate an
interesting execution.

## Clean up

The generated scenarios, traces, and copied generator are ordinary local
artifacts:

```sh
rm nginx-curl.scenario.toml nginx-curl-custom.scenario.toml
rm nginx-curl.run.jsonl nginx-curl-custom.run.jsonl
rm crates/crucible-api/examples/my-nginx-curl.rs
```

Keep the Nix results and incremental Cargo build if you plan to iterate again.
