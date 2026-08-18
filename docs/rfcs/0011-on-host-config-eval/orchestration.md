# Orchestration: compiling the eval output into a systemd unit graph

This document specifies how the on-host eval output is compiled into a systemd
**unit/target graph** — so systemd's dependency ordering, parallelism, failure
isolation, partial-boot, and recovery carry the whole provisioning+install
pipeline, rather than a monolithic `apm install` orchestrator. The substrate and
metadata layers are in [`provisioning.md`](provisioning.md); the first-boot
ordering and the resolve↔eval fixpoint are in [`architecture.md`](architecture.md).

## Why a unit graph

Today the stage-2 pipeline is two monoliths: `aos-install-packages.service`
(`modules/base/apm.nix:385-406`) is a single `apm install --system --from
desired.toml` that fetches **all** closures, renders **all** config, and calls
`activate.sh.in` once — one unit, one fate; a single bad fetch fails the whole
reconcile. RFC-0011 replaces it with a graph in which per-package fetch/install
are individual units, so:

- **ordering** follows the config dependency graph (`nginx` after `firewall`);
- **parallelism** is free (independent packages fetch concurrently);
- **failure isolation** means one bad package degrades rather than aborts
  (§"Failure isolation");
- **recovery** is `systemctl restart <one unit>`, not re-running everything.

The `systemctl` graph is a better orchestrator than anything built adjacent, and
it natively gives a partially-booted, reachable system on failure.

## Mechanism: runtime unit files in `/run/systemd/system` + `daemon-reload` + a target

The eval runs **post-`network-online.target`** (it needs the registry: net,
DNS, trust anchors, store). Two candidate mechanisms are rejected:

- **Generators** run in the earliest boot transient (before `basic.target`, no
  network, no D-Bus) and must be fast/synchronous. The manifest does not exist
  that early — a first-boot generator would emit nothing. Wrong tool.
- **`StartTransientUnit` (D-Bus)** is painful for a *graph* of dozens of
  interrelated units (aux-property structs), the units aren't inspectable
  (`systemctl cat` shows nothing), individual retry is awkward, and the existing
  `aos-systemd` client doesn't implement the call. Right for fire-and-forget
  jobs, not a retryable graph.

**Recommendation:** the graph compiler **writes unit files to
`/run/systemd/system/`, calls `daemon-reload`, then starts `aos-config.target`**
— exactly the capability set the `aos-systemd` client already exposes
(`crates/aos-systemd/src/client.rs`: `start_unit`/`reload`(=daemon-reload)/
`reset_failed_unit`/`list_units_by_patterns`). `/run/systemd/system` outranks
`/etc` and `/usr`, is tmpfs (wiped every boot, re-derived from gen-0 + the
manifest), and is **not** part of the composefs `/etc` overlay — so orchestration
scaffolding never pollutes the content-addressed `/etc` generation. Units are
inspectable (`systemctl cat`) and individually retryable.

**Bake the templates; generate only instances + dropins.** Ship the *template*
units statically in the image (gen-0), so almost nothing is synthesized at
runtime (the typed `systemd.*` tree already supports templates —
`lib/modules/systemd/unit-options.nix:178,198`):

- `aos-pkg-fetch@.service` — `ExecStart=apm fetch %i` (download + verify one
  package's NAR closure). `Type=oneshot`, `Restart=on-failure`, network-ordered.
- `aos-pkg-install@.service` — `ExecStart=apm render-one %i` (render that
  package's config artifact + credential handles). `Type=oneshot`.
- `aos-fetch.target`, `aos-config-render.target`, `aos-config.target` — static.

At runtime the compiler writes only **tiny per-instance dropins** + the targets'
`.wants/` symlinks:

```ini
# /run/systemd/system/aos-pkg-install@nginx.service.d/10-edges.conf  (generated)
[Unit]
After=aos-pkg-install@firewall.service     # mirrors the config edge nginx → firewall
Wants=aos-pkg-install@firewall.service
```

That is the entire runtime-generated surface: a handful of 3-line dropins +
symlinks, then one `daemon-reload`. Everything heavyweight (template body,
sandboxing, slices) is image-baked and measured.

## First-boot unit graph

`═▶` = `Requires=`+`After=` (hard); `─▶` = `Wants=`+`After=` (soft,
failure-isolated); `┄▶` = `After=` only.

```text
[initrd]  aos-metadata-detect ═▶ aos-metadata-fetch ═▶ aos-metadata-authorize
          ═▶ aos-storage-plan-render ═▶ systemd-repart ═▶ aos-var-crypt/mount-var
          ═▶ nix-overlay-setup ═▶ aos-seed-profiles (gen-0) ═▶ etc-overlay-setup ═▶ switch_root

[stage 2] networkd/resolved (gen-0 /etc) ┄▶ network-online.target
   │
   ▼
 aos-eval.service        After=network-online.target ; Type=oneshot, best-effort, hardened scope
   verify initrd binding → resolve↔eval fixpoint (fetch config-module closures) →
   PRODUCES /run/aos/manifest.json + /run/aos/graph.json     (NEVER calls activate)
   │
   ▼
 aos-graph-compile.service   After=aos-eval ; ConditionPathExists=/run/aos/manifest.json
   writes /run/systemd/system/{aos-pkg-fetch@<p>, aos-pkg-install@<p>} dropins + .wants ;
   daemon-reload ; systemctl start --no-block aos-config.target
   │
   ▼
 aos-fetch.target ─▶ aos-pkg-fetch@nginx ─▶ aos-pkg-fetch@firewall ─▶ …   (parallel, NETWORK,
   │                  Restart=on-failure ; Wants= ⇒ one fail ≠ target fail)  retryable)
   ▼
 PRE-COMMIT WING (failure-isolated):
   aos-pkg-install@firewall ┄▶ aos-pkg-install@nginx   (After= mirrors config edge ;
     each After=aos-pkg-fetch@<self>)                    renders that pkg's config)
   │  (aos-config-render.target — Wants= all installs)
   ▼
 ╔══════════════ THE ATOMIC COMMIT ══════════════╗
 ║ aos-activate.service  After=aos-config-render.target ; Type=oneshot
 ║   apm activate <gen-N> → activate.sh.in:
 ║   prepare → compose(3-lower) → pre-swap reconcile →
 ║   **mount --move --beneath /etc**  ← ONLY COMMIT POINT  → post-swap reconcile
 ╚═══════════════════════════════════════════════╝
   │
   ▼
 aos-preset.service  After=aos-activate ; preset-all + start --no-block aos-pkg-<name>.target …
   │  (each package's own nginx.service/redis.service now live in committed /etc,
   ▼   with After=firewall.service rendered from the manifest)
 multi-user.target
```

The pipeline has three zones: a **failure-isolated, retryable pre-commit wing**
(parallel fetch + per-package render), the **single atomic commit**
(`activate.sh.in`'s `mount --move --beneath` — global because `/etc` is global;
you cannot shard the swap per package), and a **failure-isolated post-commit
wing** (per-package target starts via `--no-block`).

## Failure isolation → partial boot, not failed boot

The lever is **`Wants=` vs `Requires=`.** systemd propagates a start-job failure
to a dependent only through `Requires=`/`BindsTo=`/`Requisite=`; a failed
`Wants=` dependency leaves the dependent and the target *unaffected*.

| Edge | Directive | On failure |
|---|---|---|
| target → package | `Wants=` | failed package does **not** fail the target |
| config edge nginx → firewall | `After=` (+ optional `Wants=`) | ordering only; no abort propagation |
| package main → its mac/ebpf sidecar | `BindsTo=`/`Requires=` | genuine hard dep (intended coupling, `exposed_units.rs`) |

So `aos-fetch.target`/`aos-config.target` pull each `aos-pkg-*@<p>` via
**`Wants=`**. If `aos-pkg-fetch@nginx` exhausts its `Restart=on-failure` budget,
nginx's install (`After=` an unmet fetch) stays inactive, the targets still
reach `active`, `aos-activate` commits a **re-projected manifest** (next
paragraph), and `multi-user.target` is reached. `systemctl is-system-running` →
**`degraded`**, not a failed boot — SSH, DHCP, and the healthy packages all run.
This is the same intent already encoded as `EX_DEGRADED=6` in `activate.sh.in:46`.

**Committing a subset must stay content-addressed (review M-partial-commit).** A
`/etc` committed from "whatever fetched" is not `hash(full-manifest)`, so naively
it would be a non-reproducible generation that depends on transient fetch
outcomes — breaking the content-addressing model in
[`generations.md`](generations.md). Instead, `aos-activate` commits a
**re-projected manifest**: the full manifest **restricted to the packages that
actually materialized**, re-hashed, with the **dropped set recorded** in the
generation. The degraded config-gen is therefore itself content-addressed and
reproducible from `(authenticated inputs + the recorded drop-set)` — a verifier can
reproduce exactly what was committed. (Re-running fetch for the dropped packages
later produces a *new* config-gen via the normal reconcile path, not a mutation
of the degraded one.)

**Reserve `Requires=`/`BindsTo=` exclusively for true substrate edges**, so only
genuine substrate loss — never a single package — can pull the system out of
multi-user:

- authenticated `host.nix` provisioning projection invalid, or substrate broken in initrd
  (repart/cryptsetup/mount-var, hard edges) → cannot
  reach `initrd-fs.target` → **`emergency.target`**;
- stage-2 structural failure (`/etc` swap indeterminate, `EX_SWAP=4`) →
  **`rescue.target`**.

### Recovery ladder

1. **Auto-retry** — `Restart=on-failure`+`RestartSec` rides out transient
   registry/network blips with no operator action.
2. **Manual unit retry** — `systemctl reset-failed aos-pkg-fetch@nginx &&
   systemctl start aos-pkg-fetch@nginx` (the client exposes `reset_failed_unit`
   + `start_unit`); the `/run` unit persists for the boot, so the failed node is
   inspectable and re-runnable without re-evaluating the manifest.
3. **Re-eval** — `apm switch` / `apm upgrade --system` re-runs `aos-eval` →
   recompiles the graph → re-drives `aos-config.target`.
4. **Manifest never produced** (no net, registry down, provisioning policy
   rejection) —
   `aos-eval` is best-effort and emits nothing; `aos-graph-compile`'s
   `ConditionPathExists=/run/aos/manifest.json` makes it a clean no-op; the box
   stays fully live on the **gen-0 seed**, reachable to fix `host.nix`.

## Mapping the config dependency graph onto the systemd graph

The eval emits `manifest.json` (the data contract) and a companion `graph.json`
(the cross-package dependency DAG — `nginx` depends on `firewall`
⇒ edge `nginx → firewall`). It is derived from authenticated package metadata,
the publish-time AST scan, and the error-driven fixpoint
([`module-system.md`](module-system.md)). Keep **two
projections** of that DAG separate:

1. **Eval-time resolution (already done before any unit exists).** "nginx needs
   `firewall.forwardPolicy = accept`" is resolved *inside* `evalModules` —
   merged into firewall's config at operator/provider priority. By the time the
   manifest exists, the *content* is consistent; conflicts are loud eval
   failures, never runtime races.
2. **Runtime ordering (what the compiler projects onto systemd).** The same edge
   becomes (a) provisioning order — `aos-pkg-install@nginx` gets a generated
   `After=aos-pkg-install@firewall` dropin (firewall's nftables artifact
   materializes first); and (b) service start order — the manifest renders
   nginx's own unit into committed `/etc/systemd/system/nginx.service` with
   `After=firewall.service`. Independent packages get no edge and run **fully
   parallel**.

**Fetch carries no config edges** — downloads are order-independent, so they
saturate the network in parallel; only install/activate/start honor ordering.
**Cycle safety** is inherited: a non-converging fixpoint fails eval with an
iteration trace, so `graph.json` is always a DAG and systemd never sees an
ordering cycle.

## Reconfiguration (steady state)

Every boot reacquires/authorizes `host.nix` and re-drives evaluation. A
committed GPT marker suppresses storage mutation, not runtime reconciliation.
An explicit `apm switch`/`upgrade` re-drives the same graph between boots:

1. `aos-eval` re-runs → new `manifest.json` + `graph.json`.
2. `aos-graph-compile` **diffs old vs new manifest** (reusing the
   `apm switch --dry-run` / `unit_diff` plumbing, [`operability.md`](operability.md))
   and rewrites `/run/systemd/system/`: new packages get fresh instances +
   `.wants`; **removed** packages get their `/run` units deleted and
   `reset_failed` called; changed edges get rewritten dropins; one
   `daemon-reload`.
3. `systemctl start --no-block aos-config.target` re-drives fetch→install for the
   **delta** only (unchanged packages are already-`active` `RemainAfterExit`
   oneshots ⇒ no-ops).
4. `aos-activate` runs `activate.sh.in` for the new gen-N — the same atomic
   `mount --move --beneath`, the same pre/post-swap reconcile that
   reloads/restarts only the units whose config changed.

Because the per-boot `/run` units are pure functions of the manifest, and the
manifest is content-addressed into a config-generation
([`generations.md`](generations.md)), reconfiguration is idempotent and
rollback-capable — rollback is a pointer switch to a retained gen-N (whose
`cfg/` GC root kept its config closure alive), re-running `aos-activate` with no
re-eval for same-ABI rollback.

## Deltas to land this

- **`modules/systemd/` (new `graph.nix` or extend `presets.nix`)** — declare the
  static templates `aos-pkg-fetch@.service` / `aos-pkg-install@.service` and the
  `aos-fetch`/`aos-config-render`/`aos-config` targets in the typed `systemd.*`
  tree; bake into gen-0.
- **`modules/base/apm.nix`** — replace the monolithic
  `aos-install-packages.service` (`:385-406`) with `aos-eval.service`
  (best-effort, hardened scope) + `aos-graph-compile.service` + `aos-activate.service`;
  keep `aos-preset.service` `After=aos-activate.service`.
- **`crates/aos-package/`** — the graph compiler: a new module (sibling to
  `exposed_units.rs`/`config_artifact.rs`) that consumes `manifest.json` +
  `graph.json`, writes `/run/systemd/system/` instance dropins + `.wants`, and
  drives the chain via the existing `aos-systemd` client. New `apm` subverbs
  `fetch <pkg>` / `render-one <pkg>` for the template `ExecStart`s. The single
  transactional commit (`activate.sh.in`) is reused unchanged.
- **Tests** — `tests/fleet/apm-desired-sequencing.nix` for parallel/ordered
  execution; `apm-system-activation-fail.nix` for "one package fails ⇒
  `is-system-running = degraded`, multi-user reached, healthy packages live, box
  reachable." Honor the VM-harness constraints (no grep/sed in guest;
  `/proc`+`/sys` introspection; `requiredSystemFeatures=["kvm"]`).
