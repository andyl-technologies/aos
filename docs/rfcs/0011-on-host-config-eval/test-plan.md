# Test plan — characterization-first TDD

RFC-0011 is mostly a **refactor under invariants**: the render/assemble split is
"byte-identical toplevel," the atomic `/etc` swap and rollback are unchanged, and
the Ignition→`systemd-repart`/metadata-agent swap must preserve observable
substrate outcomes. That makes characterization testing the right discipline:
**write tests that pin current behavior, green them on master *first*, then
implement RFC-0011 keeping them green.** This suite is the **first code into the
PR** — before any render refactor or on-host-eval work.

The principle: split the surface into **preserve** (behaviors RFC-0011 must not
change → characterization tests now, on master, as the regression net) and
**change** (new contracts → test spec authored red-first, go red→green per
phase). Only the preserve set is TDD-able against current.

## Current test surface (what exists to test against)

Grounded in `default.nix:264-330` (the `checks` rec), `modules/base/checks.nix`
(module `system.checks.*` → `system.build.checks.*` via `mkVMTest`), the
auto-discovered fleet tests (`default.nix:216-254`), and `lib/testing/`.

**Pure-eval (fast, every PR):** `checks.eval` (`lib/testing/eval.nix`),
`module-enforcement`, `module-args`, `systemd-generate`, `systemd-lib`,
`ignition-format`, `package-expose`, `lint`. These assert option content,
throws, and `tryEval` — **string-content only; there is no golden/snapshot of the
toplevel render today.**

**VM/fleet (KVM):** `system-boot` (`modules/tests/boot.nix` — PID-1 systemd,
multi-user, 3-layer `/etc` overlay, erofs RO), `apm-system-upgrade` (the full
6-stage `activate.sh.in` flow + `mount --move --beneath` + daemon reconcile),
`install-from-image` (partition labels, `/var` carved/grown/mounted, erofs RO),
`measured-boot` (LUKS2 + TPM seal + unattended `/var` unlock + SB enforcing).

**Coverage vs. the RFC-0011 preserve seams:**

| Preserve seam | Guarded by | Status |
|---|---|---|
| Atomic `/etc` swap (`activate.sh.in` stages, `mount --move --beneath`) | `fleet.apm-system-upgrade` | ✓ guarded |
| 3-layer `/etc` overlay, erofs RO, boot→multi-user | `system-boot` | ✓ guarded |
| Disk outcomes (root-a/b/var/swap, var grown+mounted) | `install-from-image`, `measured-boot` | ✓ guarded |
| LUKS2 + TPM seal + unattended unlock + SB | `measured-boot` | ✓ guarded |
| Daemon reconciliation (reload/restart diff) | `apm-system-upgrade` (`systemctl --failed` empty) | ✓ guarded |
| **Toplevel render byte-detail** (etcDump, unit texts) | — | ✗ **unguarded** |
| **Flat-merge config materialization determinism** | — (`config_artifact.rs` has no tests) | ✗ **unguarded** |

So VM tests already catch *integration/activation/boot* regressions across the
refactor; the two unguarded rows are exactly what the new characterization
artifacts below fill — and they are the regressions the P0 render refactor most
risks.

## The three characterization artifacts (write first, green on master)

All three introspect *current* behavior, need **no RFC-0011 code**, and become
the regression net the refactor runs under.

### 1. Pure-eval toplevel golden (the strongest lever)

`lib/testing/system-characterization.nix` + committed fixtures under
`tests/fixtures/system-characterization-goldens/<system>/`. For each system variant, snapshot
the current `system.build.toplevel` render and assert byte-equal:

- `etcDump.txt` — the composefs-dump(5) text (deterministic, sortable).
- `systemd-units/` — the rendered unit bodies from
  `system.build.systemdSystemUnits`.
- `activate-script.sh` — the substituted `activate.sh.in` (tool paths).
- `os-release`, the presets, the `/etc` entry listing.

Added to `checks.eval` (pure, every PR). This turns the P0 "byte-identical
toplevel" claim into an **enforced gate**, and is the oracle the new on-host eval
path must reproduce in P1.

> **Job-script normalization (review C2).** The C2 fix moves shell-snippet
> options (`script=`/`preStart=`/…) from a `writeShellScriptBin` store path into
> manifest *text*, so the rendered `ExecStart=` bytes change intentionally. The
> golden comparator **must normalize job scripts to their text** (compare the
> snippet body, not the embedded `/nix/store/…-unit-script` path) — otherwise
> every such unit diverges. Build this normalization into the comparator from the
> start; it is the one place "byte-identical" is deliberately "text-identical."

### 2. Flat-merge Rust golden (the parity oracle)

`crates/aos-package/tests/golden_config_artifact.rs` + fixtures under
`crates/aos-package/tests/fixtures/`. Snapshot `render_package_config()` for a
fixture corpus (e.g. a 3-artifact package × multiple config fields); re-render
with **shuffled input order** and assert stable + matches the committed golden.
This pins the determinism the content-addressing model depends on, and it is
exactly the `checks.config-parity` oracle: once module-eval lands, render
flat-merge vs. module-eval for the same inputs and assert byte-equal (see
[`operability.md`](operability.md)).

### 3. Activate + substrate fleet assertions

Extend the existing fleet tests from "boots" to "boots **and** these observable
outcomes hold," so they pin behavior identically **across** the Ignition→repart
and Ignition→metadata-agent swaps:

- `systemd-repart` / cryptsetup status, partition labels + sizes, `/var`
  mounted rw (must survive the substrate swap).
- `/var/etc` allowlist survival + the dirty-upper warning when files escape it
  (currently unguarded per the inventory).
- post-swap `systemctl --failed` empty + the expected units reloaded/restarted.

Guest introspection follows the harness constraints (`lib/testing/vm.nix`,
`vm.succeed`/`vm.fail`/`vm.wait_for_unit`; no grep/sed/ip in guest — use
`/proc`, `/sys`, `systemctl`, `journalctl`).

## The barrier pattern

Commit the goldens at the branch base, green. The implementation work runs
*under* them; a golden changes **only** via an intentional, reviewed diff
(documented in the commit). An unexpected golden diff in CI **is** a caught
regression. (Mirrors the aos-nix byte-identical `.drv` gate discipline.)

## New-subsystem tests (change set — authored red-first, per phase)

These have no current equivalent, so they go red→green as each phase lands. They
are *specified here* so the tests are written before the code:

- **On-host eval → manifest** (`fleet`): agent receives literal-Nix user-data →
  evaluates → emits manifest; **eval twice ⇒ byte-identical** (determinism gate);
  manifest has the expected `etc`/`units`/`jobScripts`/`inputs` shape.
- **Resolve↔eval fixpoint** (`checks.eval` + `fleet`): a host.nix enabling a
  package whose config module isn't present pulls the **config output first**,
  re-evals, converges; a missing provider fails legibly; a cycle dumps the trace.
- **`module_abi` gate** (`checks.eval`): a config module with an incompatible
  `module_abi_compat` is **refused pre-eval**, fail-closed, old gen stays live.
- **Two-axis generations** (`fleet`): config rollback is a pointer switch
  (no eval, no reboot); cross-ABI rollback **re-evals** retained inputs; `apm gc`
  does **not** break cross-ABI re-eval (the `cfgsrc/` root, review M-gc-inputs).
- **Unit graph / degraded boot** (`fleet`, from `apm-system-activation-fail`): a
  single failing package fetch ⇒ `is-system-running = degraded`, `multi-user`
  reached, healthy packages live, box SSH-reachable; the committed gen is the
  **re-projected** (subset) manifest, still content-addressed.
- **systemd-repart substrate** (`fleet`): explicit `systemctl status
  systemd-repart-*` + idempotency (carve+grow on fresh VM, **no-op on reboot**) +
  the destructive-op state-probe guards run once.
- **`aos metadata` agent** (`checks` + `fleet`): per-platform fetch over recorded
  fixtures (offline channels first), transport-only stash, **stage-2** signature
  verification against `trusted-config-keys.d`, facts → `host.facts.*`,
  static-networking seed for DHCP-less clouds.
- **Conscription / capability-scoped contribution** (`checks.eval`): a foreign
  `enable` write is rejected at resolve time (its paths are not a subset of the
  installed owner's contributable surface in `SystemRoots`); a contribution to an
  owner-declared contributable sub-path is allowed; provenance from the
  authenticated source
  (forged `_file` does not earn operator priority — review M-forgeable-file).

## How a check is added

- **Pure-eval / global:** add `lib/testing/<name>.nix`, import in
  `default.nix`'s `checks` rec → `nix-build -A checks.<name>`.
- **Module VM check:** `modules/tests/<name>.nix` defining `system.checks.<name>`
  → auto-wrapped by `modules/base/checks.nix` → `nix-build -A
  systems.server.checks.<name>`.
- **Fleet:** `tests/fleet/<name>.nix` (machines + `testScript`) → auto-discovered
  → `nix-build -A checks.fleet.<name>`.
- **Rust:** `crates/aos-package/tests/<name>.rs` → `cargo test`.

## Sequencing

1. **First commit of the PR:** the characterization suite (artifacts 1–3),
   **green on master** (verified on a Linux/KVM builder — the pure-eval goldens
   and the Rust goldens, then the fleet-assertion extensions).
2. **P0 render/assemble refactor** runs under the toplevel golden; the only
   allowed golden change is the job-script normalization (documented).
3. Each subsequent phase lands its red-first new-subsystem tests alongside the
   code, with the characterization suite staying green throughout.
