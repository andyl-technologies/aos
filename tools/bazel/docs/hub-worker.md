# Worker build graph

The Worker has two native test configurations and three Wasm deployment
configurations. Each owns a separate pinned Rust SDK, with Cargo feature units
split between the native execution platform and the selected target. The
ordinary build consumes those source repositories offline; dependency updates
remain an explicit operation.

| Developer family | Target | Cargo features |
| --- | --- | --- |
| `hub-worker` | Native tests and editor | Defaults |
| `hub-worker-all-features` | Native tests and editor | Defaults, `do-e2e`, `query-timing` |
| `hub-worker-wasm` | Production Wasm | Defaults |
| `hub-worker-wasm-do-e2e` | Runtime probe Wasm | Defaults, `do-e2e` |
| `hub-worker-wasm-all-features` | Runtime probe Wasm | Defaults, `do-e2e`, `query-timing` |

The shared Service, Database, Model and Native Hub declarations select their
features explicitly for each configuration. Wasm dependencies retain their
Cargo aliases, including `getrandom` and `getrandom_03` where both versions are
used. The runtime-independent Worker tests retain the Native Hub test-support
edge without adding it to deployment builds.

## Deployment packaging

`//crates/hub/aos-hub-worker:shared` compiles the deployment library for
`wasm32-unknown-unknown`. It preserves size optimization, fat LTO, one codegen
unit, aborted panics and stripped symbols. Source-built native tools execute
the generators: wasm-bindgen, the Node glue rewrite and esbuild. Every tool and
its runtime closure is a declared action input.

`//crates/hub/aos-hub-worker:worker_dist` exports `shim.mjs`, `index.wasm` and
the complete generated `assets` directory. The CDN assets use the existing
content-derived version, bootstrap interface and cache headers. Default
production packaging rejects the runtime probe markers. Probe features remain
explicit selections.

The directory package boundary resolves the declared tree alias, rejects
nested symlinks and special files, and exports a complete flat manifest with a
digest for each file. Installation checks the package identity and digests
before ordinary AOS fixup. No host cache service participates in these steps.

## Validation

The native qualification checks execute unit tests, doctests, Clippy,
formatting, Cargo feature parity and the selected editor comparison in both
configurations. All 50 original test declarations remain in the source; 47
execute on the native target. The three tests in the Wasm-only console module
retain their target guards.

The [native development checkpoint](../tests/evidence/hub-worker-native-development.json)
retains both successful configurations with the local disk action cache. The
[source graph record](../tests/evidence/hub-worker-source-graph.json) validates
all 54 Rust SDKs and 40 configured source inventories. These records distinguish
their scope from the uncached and live-runtime checks below.

```sh
nix-build tools/bazel/tests/hub-worker.nix -A all --no-out-link \
  --max-jobs 4 --cores 4 --option substitute false
nix-build tools/bazel/tests/hub-worker-wasm.nix -A all --no-out-link \
  --max-jobs 4 --cores 4 --option substitute false
nix-build tools/bazel/tests/hub-worker-wasm.nix -A do-e2e.live-runtime \
  --no-out-link --max-jobs 4 --cores 4 --option substitute false
```

Wasm qualification compares each deployment with a fresh Cargo build consuming
the same declared Console assets. It checks every CDN asset byte for byte,
validates both modules with the source-built Node runtime, compares public
Wasm export names and kinds, and compares compiled dependency features.
Numbered bindgen function-element trampolines encode compiler-private indices;
each module retains its own matching generated JavaScript glue.

The separate KVM-backed VM gate injects the Bazel-built probe deployment into
the existing real-workerd launcher and driver. It exercises the genuine
SQLite Durable Object, provider dispatch, multipart concurrency, request body
limits and CLI image operations. Pure native tests and Wasm module validation
do not establish that runtime behavior. The gate's object-store adapter
remains the existing SQLite-backed test provider because open-source workerd
does not implement Cloudflare R2.

The frozen Cargo baseline records remain in `../tests/evidence/`. Full
compiler-argument equivalence, performance acceptance and production-builder
migration require their own evidence. Adding this graph does not replace the
production Cargo builders.
