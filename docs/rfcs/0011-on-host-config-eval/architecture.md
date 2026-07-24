# Architecture

This document specifies the two-stage evaluation model, the render/assemble
split that keeps the "nothing is built on-host" invariant honest, the `config`
output and the manifest data contract, the evaluator (stock Nix for P1,
aos-nix for P2), and the boot / first-boot bootstrap ordering.

## Two-stage evaluation

### Stage 1 — build / publish (off-host, derivation-producing)

`pkgs/*.nix` build binaries exactly as today via `mkDerivation`. The change is
additive: each package gains a second output, **`config`**, alongside `out`.

- `out` is the binary closure (glibc, openssl, the program) — unchanged.
- `config` is a store path containing the package's **config-only Nix module**
  (plus any private helper `.nix` it imports by relative path within the same
  NAR). This is the RFC-0001 `expose` surface
  (`pkgs/build-support/_expose-renderer.nix`) promoted from a static JSON blob
  into a real module that declares typed options and `config`.

The discipline that makes the whole design work: the `config` module references
its own and other packages' outputs as **plain store-path strings**, recorded
at build time (e.g. `"/nix/store/<hash>-redis-8.2/bin/redis-server"`), never as
`mkDerivation` results. A store-path string carries *string context* (metadata)
but is not a derivation; interpolating it triggers no instantiation and no
realization. This is the documented distinction in
`crates/aos-doc/src/data/language.rs`: `"${pkgs.hello}/bin/hello"` forces the
derivation and instantiates; a bare path string does not.

Stage-1 modules and stage-2 modules are therefore *different kinds of module*:
stage 1 is derivation-producing (`mkDerivation`), stage 2 is config-only
(references paths as strings, declares systemd/`/etc`/networking options).

This discipline is **mechanically enforced, not left to convention** (review): a
**publish-time lint** rejects a `config` output whose module graph holds a
derivation or forces an `outPath` — the same probe-eval pass that checks the
provides/requires interface ([`module-system.md`](module-system.md)). An
accidental derivation reference is a publish failure, not a silent on-host build
attempt. (P2 aos-nix can additionally refuse instantiation in the engine.)

### Stage 2 — activation (on-host, eval-only, config-producing)

APM resolves the desired package set (see
[`module-system.md`](module-system.md) for the resolver), then runs one
`lib.evalModules` over three input groups:

1. **The base module library**, shipped *in the image* and version-bound to the
   image generation. It owns the structural roots the renderer itself consumes
   (`systemd.*`, `environment.etc.*`, `users.*`, `networking.*`) and is
   **injected** into package modules as `lib`/module args — package modules do
   not import it. (`lib/modules.nix:541-567` supplies `lib`/`pkgs`/`extraArgs`;
   `_module.args` is seeded from `specialArgs` at `lib/modules.nix:620`.)
2. **Every resolved package's `config` module**, mounted under its own root
   (`{pkg}.*`) as a submodule — the existing `attrsOf (submodule …)` +
   name-injection idiom already used by `systemd.services.<name>`
   (`lib/modules/systemd/types.nix:71-91`, `lib/default.nix:77-88`).
3. **The operator's leaf `host.nix`**, delivered as **literal Nix in the cloud
   user-data** and fetched by the `aos metadata` agent (see
   [`provisioning.md`](provisioning.md) and
   [`trust-and-secrets.md`](trust-and-secrets.md)).

The evaluation produces a pure-data **manifest** (next section). Because every
referenced store path already exists locally as a downloaded NAR and the modules
hold strings rather than derivations, the evaluation never instantiates a
`.drv`, never forces an `outPath`, and never realizes anything.

## The render/assemble split

Today `system.build.toplevel` *is a derivation*: its builder runs `mkfs.erofs`
for the composefs `/etc` metadata, materializes `generateUnits` (itself a
derivation), and assembles symlink trees (`modules/base/build.nix`,
`lib/modules/systemd/lib.nix`). An eval-only host cannot realize that.

RFC-0011 splits **render** (pure eval) from **assemble** (imperative
activation):

1. **Render becomes pure Nix.** `generateUnits` and the `/etc` assembly stop
   being derivations and become pure functions returning data:
   `{ "systemd/system/redis.service" = { text = "…"; mode = "0644"; }; … }`.
   The builder-side toplevel consumes the same manifest via a thin materialize
   step, so build-time behavior is unchanged — but render is now host-portable.

   **Shell-snippet service options must carry text, not derivations (review
   C2).** Unit rendering is *not* pure string templating today: `script=`,
   `preStart=`, `postStart=`, `reload=`, `preStop=`, `postStop=` route through
   `makeJobScript` → `pkgs.writeShellScriptBin` (`lib/modules/systemd/unit-options.nix:644`,
   `lib.nix:691`), a **derivation** whose built `/nix/store/…-unit-script/bin`
   path is embedded in `ExecStart=`. Job-script content is a function of the
   *evaluated* config, so it cannot be pre-built in stage 1, and an eval-only host
   cannot build it. **Fix (F2-A):** render emits each job-script's **text** into
   the manifest (`manifest.jobScripts["redis.service:ExecStartPre.0"] = { text }`);
   the materializer writes it to a generation-local path and rewrites the
   `ExecStart=`/`ExecStartPre=` to point there. Consequence: the rendered command
   bytes differ from the build-time `writeShellScriptBin` path, so the **P0
   "byte-identical toplevel" gate compares job scripts semantically (text
   equality), not by embedded path** ([`implementation-plan.md`](implementation-plan.md)).
   (Alternative F2-B — ban these options in stage-2 modules via a publish lint —
   is a real language restriction; see [`known-issues.md`](known-issues.md) F2.)

2. **Assemble becomes an APM activation step.** Turning the manifest into the
   composefs `/etc` lower (`mkfs.erofs` of the metadata image + the basedir +
   symlink trees, plus writing the job-script texts above) is **materialization,
   not building**: it runs **no compiler, no `configure`/`make`, and realizes no
   derivation** — it only assembles already-present bytes into an image with a
   fixed tool, the same category as `systemd-tmpfiles` and the work APM already
   does for `expose` artifacts (`crates/aos-package/src/exposed_units.rs`,
   `config_artifact.rs`). The composefs/erofs assembler ships as a base on-host
   tool.

3. **The generation is content-addressed by the manifest.** APM hashes the
   evaluated manifest (+ the closure of referenced store paths) → that is the
   config-generation id. Rollback keeps the materialized generation directory,
   so switching back is re-point + re-activate — no re-eval needed for
   same-ABI rollback (see [`generations.md`](generations.md)).

Everything downstream of the manifest is **unchanged**: the three-lowerdir `/etc`
compose, the pre-swap unit diff, the atomic `mount --move --beneath`, and the
post-swap reconcile in `modules/base/activate.sh.in`.

## The manifest — the data contract

The manifest is the single contract between the pure evaluation and the
imperative materializer. It is the eval output that today's flat merge produces
piecewise. Schematically:

```json
{
  "schema": "aos.config-manifest/v1",
  "etc": {
    "systemd/system/redis.service": { "text": "…", "mode": "symlink" },
    "systemd/network/10-eth0.network": { "text": "…", "mode": "0644" }
  },
  "units": { "redis.service": { "action": "restart", "credentials": ["join-token"] } },
  "jobScripts": { "redis.service:ExecStartPre.0": { "text": "#!/bin/sh\n…" } },
  "users": [ … ],
  "presets": [ … ],
  "storePaths": ["/nix/store/<hash>-redis-8.2", "/nix/store/<hash>-curl-8.12"],
  "module_abi": 1,
  "inputs": { "base_lib": "<hash>", "evaluator": "<hash>", "config_modules": "<closure-hash>",
              "host_nix": "<hash>", "instance_facts": "<facts-hash>" }
}
```

It is persisted per-generation as `gen-N/manifest.json` (alongside the existing
`meta/*.json`) so the dry-run diff and the parity gate can operate on it
structurally, and so a verifier can confirm reproducibility from `inputs`. The
manifest contains **no secret values** — credentials appear only as handles
(see [`trust-and-secrets.md`](trust-and-secrets.md)).

## The evaluator

### P1 — stock C++ Nix (already in the image)

Stock C++ Nix 2.24.12 is already built from source as an AOS package
(`pkgs/tools/nix.nix`) with `nix eval` present and tested. P1 uses it directly.
Starting on stock Nix is not a compromise on the model: the module system is
*our* Nix code (`lib/modules.nix`) and evaluates identically on either
evaluator. The seam is exactly `eval entry.nix → JSON manifest`.

Invocation (eval-only by construction; the string-path discipline guarantees no
instantiation even in a normal evaluator):

```text
nix eval --json \
  --pure-eval \                                  # determinism; blocks currentTime/getEnv/currentSystem
  --option restrict-eval true \                  # read only /run/aos-eval + the store
  --option allow-import-from-derivation false \  # no IFD ⇒ no build can sneak in
  -I /run/aos-eval \
  -f /run/aos-eval/entry.nix manifest
```

Three capabilities stock Nix lacks vs aos-nix, each with a P1 stand-in:

- **Read instrumentation** → not needed for the fixpoint. The strict module
  system already names the missing option when it throws
  (`lib/modules.nix:744`, `:917`); the resolver parses that and fetches the
  provider (error-driven fixpoint, see [`module-system.md`](module-system.md)).
  A publish-time AST scan pre-closes the set so the loop usually runs zero or
  one extra eval.
- **In-engine bounding** → OS-level bounding. The eval runs inside a hardened
  transient systemd unit with `MemoryMax`/`RuntimeMaxSec`/`TasksMax` (see
  [`operability.md`](operability.md)); a runaway is OOM-/timeout-killed and the
  existing "eval failed → keep current generation" path takes over.
- **Incremental cache** → full re-eval each activation. Acceptable: activation
  is infrequent and the on-host eval is only base-lib + config modules +
  host.nix, not nixpkgs-scale.

### P2 — aos-nix, behind the same seam

`aos-nix` (RFC-0007, Phase-1 complete) exposes `eval_expr → JSON` that never
realizes, plus `TreeWalkOptions` with `restrict-eval` path allowlists,
`pure-eval`, URI allowlists, and an opt-in IFD realizer. P2 swaps it in behind
the `eval → manifest` seam, upgrading: one-shot read-tracing (no fixpoint loop),
**in-engine** bounding/timeouts (cleaner than an OOM-kill, and a path to
totality analysis), an incremental early-cutoff cache (cheap re-eval), and
first-class graph intrinsics (the option read/write graph exposed directly to
the resolver instead of reconstructed from AST scans and eval errors). None of
this touches the registry format, the module contract, or the generations.

## Boot / first-boot bootstrap ordering

The chain below is the end state: native metadata acquisition, authenticated
first-boot storage, systemd-native substrate, and stage-2 evaluation. Ignition
and its configuration format are absent.

The first on-host eval runs **post-switch-root, in stage-2** — the same locus
where APM reconciles at first boot today (`modules/base/apm.nix`). Initrd cannot
host it: putting the evaluator + registry client in initrd would drag the
toplevel into the initrd closure (the documented `initrd → toplevel → initrd`
derivation cycle, `modules/services/ignition.nix:608-615`,
`lib/build/rootfs.nix:241-249`), and registry trust anchors + DNS
(`systemd-resolved`) are stage-2 constructs. Initrd's job is to acquire and
authorize provisioning input, validate the narrow storage schema, and deliver
the exact bound `host.nix`; stage-2 performs full Nix evaluation.

### Ordered chain

**Initrd**:

1. `aos-metadata-detect.service` — writes
   `/run/aos-metadata/platform.env`.
2. `aos-metadata-network.service` — baseline DHCP over the initrd
   `80-dhcp.network` (no config-driven networking yet).
3. `aos-metadata-fetch.service` fetches literal `host.nix` or an
   `aos.provisioning/v1` bundle.
4. `aos-provisioning-authorize.service` applies the image's `platform` or
   `signed` policy. `aos-storage-plan-render.service` validates any typed plan
   and renders transient `repart.d`. A declared invalid plan stops here with no
   fallback or disk mutation; an absent plan selects the baked convention.
5. `systemd-repart` → `aos-var-crypt`/`mount-var` → `nix-overlay-setup` →
   `aos-seed-profiles`
   (seeds **gen-0**) → `run-etc-setup`.
6. The accepted host.nix and validation record survive under `/run`; registry
   trust configuration comes from gen-0.
7. `etc-overlay-setup.service` — assembles the three-layer `/etc` overlay from
   the seed toplevel.
8. `switch_root` → stage-2.

**Stage-2:**

9. `systemd-networkd` + `systemd-resolved` come up from gen-0's baked `/etc`
   (DHCP-on-all-`en*` + `resolved.conf`); `network-online.target` reachable.
10. **`aos-eval.service` (new)** — `After=network-online.target
   nix-overlay-setup.service aos-seed-profiles.service`,
   `Before=aos-install-packages.service`, `Type=oneshot`, best-effort. Runs the
   sandboxed evaluator over base-lib (in image) + per-package `config` modules
   (downloaded from the registry — needs net + DNS + store + trust) + the leaf
   `host.nix`. Emits the manifest (a `desired.toml`-shaped reconcile input).
11. `aos-install-packages.service` — `apm install --system --from <manifest>`
    (`modules/base/apm.nix:385-406`), which materializes the manifest into a
    generation and invokes `activate.sh.in` for the atomic `/etc` swap.
12. `aos-preset.service` — applies preset policy, starts `aos-pkg-*.target`.

### Chicken-and-egg resolution

To evaluate config that configures networking, you need networking up to fetch
the config modules. Resolved by the **gen-0 seed**: baseline DHCP-on-all-`en*`
baked in the image reaches the registry; config-driven networking (static IPs,
VLANs, bonds from `host.nix`) takes effect only after the first eval
materializes a generation and `activate.sh.in` swaps `/etc`. The path is:
**DHCP seed → Ignition delivers host.nix → fetch config closures → eval →
materialize → activate (real net applied at swap).**

### gen-0 seed

gen-0 is the image's own `system.build.toplevel`, **evaluated by the build host
at image-build time, never on the box** (`lib/build/rootfs.nix`,
`aos-seed-profiles.service` already seeds it with a `registry:"seed"`
sentinel). It must contain: baseline DHCP networking + `resolved.conf`; registry
+ trust anchors baked into `/etc` (`registries.d`, `trusted-keys.d`,
`trusted-sb-certs.d`, `trusted-config-keys.d`); the evaluator (`pkgs.aos` on
PATH) and the base lib; the Nix store closure of all the above; and the
profile-state seed.

### Failure-safe by construction

`aos-eval.service` produces **only a manifest; it never calls `activate`**. A
failed eval or fetch (no network, registry unreachable, rejected provisioning input)
yields no manifest, so `aos-install-packages.service` (already
`ConditionPathExists`-guarded, `modules/base/apm.nix:397`) is a no-op →
`activate.sh.in` is never invoked → no `/etc` swap → the box stays fully live on
the gen-0 seed, reachable (SSH, DHCP) for the operator to fix `host.nix`. This
maps directly onto the pre-swap staged exit codes
(`modules/base/activate.sh.in:39-46`): every pre-commit failure runs
`cleanup_partial_gen` and "the previous gen stays live." The atomic
`mount --move --beneath` is the only commit point, so an eval/fetch error can
never leave a half-applied configuration.

### Steady-state reconfiguration

Ignition is idempotent and does not re-run on later boots (guarded by
`/sysroot/var/etc/.ignition-result.json`), so a reboot alone does not re-eval.
Re-eval is triggered by an explicit reconcile (`aos eval` / `apm upgrade
--system`) or a control-plane action (RFC-0004). A changed `host.nix` is
re-applied through a normal activation: `activate.sh.in`'s `prepare` stage
re-runs Ignition fetch+files into the candidate `/etc` lower
(`modules/base/activate.sh.in:183-208`), so reconfiguration uses the same
atomic swap and the same staged-exit-code safety, and is rollback-capable via
the per-generation profile pointer.
