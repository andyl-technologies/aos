# Operability and migration

This document specifies the dry-run / off-host preflight, eval-failure
observability, GC of config closures, the flat-merge ↔ module-eval parity gate,
and the perf budget + test plan. Most primitives already exist; the design
extends them.

## Dry-run / preflight — `apm switch --dry-run`

Because the eval is a pure function of its inputs (`host.nix`, the installed
set's config modules, registry-pinned inputs), it runs identically off-host
(CI) and on-host. The command mirrors the existing `dry_run` reconcile plumbing
(`crates/aos-package/src/desired.rs:90`, `config_artifact.rs:51`
`preflight_desired_config`):

```text
apm switch --dry-run [--from host.nix] [--json]      # eval-only; no gen, no /etc swap
apm switch --dry-run --diff-against current          # default base = live generation's manifest
apm switch --dry-run --diff-against gen-N            # diff against any retained generation
```

`--dry-run` runs the evaluator, loads the current generation's stored
`gen-N/manifest.json`, prints a structural diff, and stops before
`Profile::new_generation()`/`switch_to()`/`activate`:

```text
$ apm switch --dry-run
manifest diff (gen-7 → candidate)

  /etc entries
    ~ /etc/aos/packages/web/config.env      (3 keys: PORT 8080→9090, +TRACING, -DEBUG)
    + /etc/nftables/forward.conf            (new; provider: firewall)
    - /etc/aos/packages/legacy/config.toml  (package 'legacy' removed)

  systemd units
    ~ web.service        reload   (config artifact changed)
    ~ firewall.service   restart  (forwardPolicy drop→accept)
    + tracing.service    start    (new unit from 'web')

  packages to fetch (closure delta)
    + /nix/store/…-otel-collector-0.9   (12.4 MiB NAR, not in cache)

  cross-package resolution
    firewall.forwardPolicy = accept   (web → firewall; won over base default 'drop')

3 etc changes, 3 unit actions, 1 path to fetch (12.4 MiB). No conflicts. No assertion failures.
```

The `--json` form extends the existing planned-status envelope (`desired.rs:214`)
with `etc_diff`, `unit_actions`, `fetch_plan` (closure delta vs the local store,
enumerated by `aos-cache/src/discover.rs:18`), and `resolution_trace`.

**Off-host CI preflight.** A `checks.config-eval` derivation
(`default.nix` `checks` rec) evaluates the same expression with
`--eval-system x86_64-linux` and a checked-out `host.nix` + a pinned registry
lock, per host fixture: (1) `evalModules` succeeds (else fail with the
module-system error verbatim); (2) the manifest is schema-valid and
**deterministic** — eval twice, assert byte-identical JSON; (3) optionally diff
against the fleet's
last-known-good manifest committed in-tree so a reviewer sees the change in the
PR. The on-host `--dry-run` and the CI gate share one Rust codepath, so green CI
is a real prediction of on-box behavior.

## Observability

The module system already throws structured, sourced messages; the job is to
preserve them across the Rust boundary and classify them. Four failure classes,
each a clean **no-op on the live system** (they occur before any generation is
created or `/etc` is touched):

| Class | Origin | Operator-facing one-liner |
|-------|--------|----------------------------|
| Assertion | `lib/modules.nix:935`, fired when the manifest is forced | `config eval failed: assertion 'web needs firewall.forwardPolicy=accept but host.nix sets drop' (web/config.nix:42)` |
| Undefined option | `lib/modules.nix:744` | `config eval failed: option 'firewall.forwardPolicy' read but no provider (read by web/config.nix; no module defines it)` |
| Scalar conflict | `lib/modules.nix:721` (lists every def + `file`) | `config eval failed: conflict on 'firewall.forwardPolicy': 'accept' (web/config.nix) vs 'drop' (host.nix)` |
| OOM / timeout | systemd cgroup kill of the eval scope | `config eval killed: exceeded MemoryMax=2G (OOM) / RuntimeMaxSec=120s` |

APM does not reformat the Nix trace into prose — it tags the class and surfaces
the last throw line (the one with file:option) as the summary, keeping the full
trace at `--verbose` (the existing `Printer` stderr/stdout convention). The
resolve↔eval fixpoint carries a causal chain so its terminal states are legible:

- **No provider / no owner:** for a shared root with no installed owner,
  `no installed package owns root 'firewall' (read by web)`; for a structural
  root, `unresolved: 'foo.bar' read by web but no registry package named 'foo'`
  (distinct exit codes). Shared-root owners are never auto-fetched — the operator
  installs one.
- **Conflict:** the readonly-conflict throw already lists every def with its
  `file` — the `'conflict … between web and host.nix'` message, for free.
- **Non-convergence / cycle:** cap fixpoint iterations; on exceeding, dump the
  iteration trace (`iter 3: +firewall; iter 4: firewall reads tls.mode →
  +tls; iter 5: tls reads firewall.zone …cycle`).

## GC of config closures

A generation today roots `gen-N/usr/<hash>` (package outputs) and `gen-N/src/<hash>`
(source drvs) via symlink dirs `nix-store --gc` honors (`store.rs:create_gc_roots`,
`profile/mod.rs:10`). RFC-0011 adds **two** roots, not one:

- **`gen-N/cfg/<hash>` → `<config-output store path>`** — the manifest's realized
  *outputs* (rendered `/etc` trees, unit files, job-script texts, the `toplevel`).
- **`gen-N/cfgsrc/<hash>` → config-module *source* closure + `host.nix` store
  path** — the eval **inputs** (review M-gc-inputs). The `cfg/` outputs reference
  package *runtime* closures, **not** the config-module source NARs the evaluator
  read; without `cfgsrc/`, a plain `apm gc` would collect the inputs and break the
  cross-ABI re-eval that [`generations.md`](generations.md) depends on. Both are
  written by the extended `create_gc_roots`.

The config closure references the package outputs it wires up, so rooting it
transitively keeps `usr/` alive — but the explicit `usr/` roots stay, so a
package remains pinned even if a later eval drops it from `/etc` (rollback
safety). The per-generation `manifest.json` is a plain file in the gen dir, so
it travels with the generation and is deleted with it.

Retention is unchanged: while gen-N is retained, its `cfg/` roots keep the config
closure alive (rollback is a pure pointer switch); when gen-N is pruned
(`prune_generations`, `apm clean --generations`), the whole `gen-N/` dir is
removed, dropping `usr/`/`src/`/`cfg/` at once, and the config store paths become
collectable on the next `apm gc` (`clean.rs:204`) unless still referenced by a
retained generation (Nix GC computes reachability across all roots). The
ephemeral `/run/etc/upper-N` overlay uppers are not store paths and are reclaimed
by reboot/tmpfs + generation GC (`activate.sh.in:325-348`), untouched by config
GC. The only GC contract change is "add `cfg/` to the per-gen root set."

## Migration + parity gate

**Coexistence in one generation.** The unit of opt-in is the package. A package
ships a `config` module or it doesn't; during transition the manifest builder
partitions the installed set:

- **With a config module** → artifacts come from `evalModules` (participates in
  cross-package resolution).
- **Without** → falls back to today's `render_package_config` flat merge
  (`config_artifact.rs:212`), keyed only by its own `desired.toml` stanza, no
  cross-package visibility.

Both render into the same `/etc/aos/packages/<pkg>/…` namespace and the same
reload/restart unit sets, so a generation's manifest is the union. The module-
eval path *replaces* the flat renderer for opted-in packages; the downstream
`materialize_package_config` / `apply_config_reconciliation` machinery is
identical. No flag-day.

**Parity gate.** `checks.config-parity`
takes fixture packages that have **both** a flat `expose.config` and an
equivalent config module; for each, render **both ways** with the same
`desired.toml` inputs, canonicalize, and **byte-diff** the materialized
artifacts + the reload/restart sets. The flat path is already deterministic
(`BTreeMap` ordering, `config_artifact.rs:269`), so the diff is well-defined.
**Fail CI on any divergence.** This guarantees a package migrates without
changing a byte of materialized config — the safe-migration invariant. As
packages migrate, each gets a parity fixture; once module-only, the fixture
retires. The gate is pure eval-time (no VM), next to `checks.eval`, cheap on
every PR.

## Perf budget + testing

**Budget (P1, stock Nix).** Reference: stock C++ Nix on a NixOS-scale module set
is ~1–5 s wall, few-hundred-MB RSS; an AOS config eval is *smaller* (no
kernel/initrd module tree — just base lib + per-package config modules +
host.nix). Targets for ≤ ~50 config-module packages:

- **Wall:** p50 ≤ 3 s, p99 ≤ 15 s — **per eval**.
- **RSS:** ≤ 1.5 GiB typical, hard ceiling 2 GiB.

> **The reference figures are warm; P1 is cold + K× (review).** The ~1–5 s
> reference is a *warm* nixpkgs eval; P1 runs **cold subprocess** stock-Nix evals,
> and the error-driven fixpoint discovers **one missing option per eval**, so a
> first boot needing K providers is ≈ K cold evals. The publish-time AST scan
> pre-closes the set to keep K small (usually 0–1 extra), and the wall budget
> above is **per eval** — `RuntimeMaxSec` bounds each, while the resolver bounds
> the total iteration count.

The budget *defines* the systemd limits on the transient eval scope (the cgroup
is the enforcement, and a kill maps to the OOM/timeout diagnostic above):

```text
RuntimeMaxSec=120        # ~8× p99 headroom; >2 min is pathological → kill, class "timeout"
MemoryMax=2G             # hard ceiling above the 1.5 GiB target → OOM-kill, class "OOM"
MemoryHigh=1536M         # soft throttle before the hard kill
```

The eval runs **before** the `activate.sh.in` staged swap, so a kill is a clean
no-op on the live system.

**Test strategy (three tiers, existing conventions):**

1. **`checks.eval` (pure, every PR)** — module logic: cross-package resolution
   pulls a provider; conflicts throw with both source files; undefined-option
   reads throw; assertions fire when the manifest is forced; **manifest
   determinism** (eval-twice byte-identical). Reuse the `module-enforcement.nix`
   / `module-args.nix` patterns that already exercise `evalModules` throws and
   the lazy-vs-forced semantics (`lib/modules.nix:799`).
2. **`checks.config-parity` (pure, every PR)** — the flat-vs-module byte parity
   gate above.
3. **VM + fleet tests (KVM, activation reality)** — extend the fleet harness.
   `tests/fleet/apm-system-activation-fail.nix` is the template for "eval/
   activation failure is a clean no-op + legible journal";
   `apm-system-upgrade.nix` / `apm-desired-sequencing.nix` for the happy path.
   New cases: (a) a host.nix triggering a cross-package conflict → assert apm
   exits non-zero with the conflict message and the live generation is
   untouched; (b) a successful module-eval switch → assert `/etc` matches the
   dry-run-predicted manifest and the expected units reloaded/restarted; (c)
   rollback to a pre-migration generation → assert its `cfg/` roots kept the old
   config closure alive so a same-ABI rollback can reactivate without evaluation
   or fetch, while a cross-ABI rollback can re-evaluate retained inputs. Guest constraints per the
   harness (no grep/sed in guest; `/proc`/`/sys` introspection;
   `requiredSystemFeatures = ["kvm"]`).

The dry-run command doubles as a test oracle: every fleet activation test runs
`apm switch --dry-run --json`, activates, then asserts the realized `/etc`
equals the predicted manifest — closing the loop between CI preflight and the
on-box result.
