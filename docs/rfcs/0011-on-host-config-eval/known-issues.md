# Known issues, open decisions, and the review-revision log

An adversarial review (72 agents: per-dimension skeptical finders + a refute-each
attempt) raised 65 findings; 48 survived refutation (2 critical, 13 major, 24
minor; 17 refuted). This document records the **three open decisions** the review
forced (they need a human call), and the **revision log** of fixes applied to the
other docs. The findings themselves were the review's; the resolutions here are
the RFC's response.

## Open decisions (forks)

> **RESOLVED.** F1, F2, and F3 are now locked with decision-free mechanisms in
> [`decisions.md`](decisions.md): **F1** → dm-verity on the erofs root, roothash
> on the measured UKI `.cmdline` (PCR-11 covers the producer); **F2** → manifest
> carries job-script text, materializer writes gen-local paths; **F3** →
> capability-scoped contribution surface (owner declares contributable
> sub-paths). The original framing is kept below for context.

### F1 — How is the on-host evaluator + base lib anchored to measured boot? (from C1)

The review correctly found that `trust-and-secrets.md` overclaimed: the evaluator
and base lib are **not** in the measured UKI — they are consumed from the **erofs
root**, which today has **no dm-verity/roothash** (`verity.nix` exists but no
production system imports it), and the `/var` seal binds only PCR-11 (UKI) + PCR-7
(SB state), neither covering the root partition. So an offline attacker can swap
the evaluator/base-lib without moving any PCR and `/var` still unseals — defeating
"measure the producer." The overclaiming text has been corrected (see log); the
remedy is a decision:

- **A (recommended): dm-verity on the erofs root, roothash on the measured
  kernel cmdline.** Root tampering then changes PCR-11 and fails the seal.
  Composes with existing measured boot; `verity.nix` already exists. Cost:
  wire dm-verity into the production image + the roothash into the UKI cmdline.
- **B: embed the evaluator + base-lib closure in the UKI initrd.** Directly
  measured, but a large initrd and in tension with the documented
  `initrd → toplevel → initrd` cycle avoidance.
- **C: scope the claim down.** Accept the root is unmeasured; rely only on the
  `/var` seal + signed eval inputs. Weakest — an attacker with offline root write
  runs a tampered producer.

### F2 — How are shell-snippet service options rendered on-host? (from C2)

`script=`/`preStart=`/`postStart=`/`reload=`/`preStop=`/`postStop=` compile via
`makeJobScript` → `writeShellScriptBin` → a **derivation** whose built
`/nix/store/…-unit-script/bin` path is embedded in `ExecStart=`. Job-script
content is a function of the *evaluated* config, so it cannot be pre-built in
stage 1; on an eval-only host it would have to be **built** — violating invariant 1.

- **A (recommended): the manifest carries job-script *text*; the materializer
  writes each to a generation-local path and rewrites `ExecStart=` to point at
  it.** Keeps the full systemd module language. Cost: the rendered `ExecStart=`
  bytes differ from the build-time form, so the P0 "byte-identical toplevel" gate
  must compare job scripts *semantically* (text equality), not by embedded path.
- **B: forbid the shell-snippet options in stage-2 config modules**, enforced by
  a publish-time lint. Simpler, but a genuine language restriction (many real
  units use `preStart`) and it falsifies "evaluates identically on either
  evaluator."

### F3 — What authorizes a package to write into another's (shared) root? (conscription vs composition)

The conscription rule (forbid foreign-root writes) rejects **legitimate
composition** — `nextcloud` writing `nginx.virtualHosts.*`,
`postgresql.ensureDatabases`, `redis.*` is a foreign-root write — while the
"registered contributor" escape is the same act an attacker would use, making the
rule either too strict or vacuous.

- **A: operator-grant.** `host.nix` explicitly grants package A write access to a
  root/service. Safe and explicit; more operator wiring for ordinary apps.
- **B (recommended): capability-scoped contribution surface.** The shared-root
  *owner* declares which sub-paths are open to non-owner contributors (e.g.
  `nginx` opens `virtualHosts.*` and `upstreams.*` but keeps `enable`/global
  owner-only). The owner curates the surface; composition (add a vhost/database)
  works without operator wiring; enabling/conscripting the service stays blocked.
  This makes "contributor" non-vacuous by scoping it per-root, per-sub-path.
- **C: strict-forbid; the operator composes.** Apps declare requirements
  (assertions); the operator wires `nginx ↔ nextcloud` in `host.nix`. Most
  restrictive; heaviest operator burden.

## Revision log (fixes applied)

| # | Finding (sev) | Resolution | Doc(s) |
|---|---|---|---|
| C1 | Evaluator/base-lib not actually measured | Corrected the measured-vs-derived text to stop claiming UKI-measured; added the F1 requirement (dm-verity-root or embed). | trust-and-secrets.md |
| C2 | Job scripts need a build | Render now emits job-script **text** into the manifest; materializer writes gen-local; P0 excludes job-script bytes. (F2-A.) | architecture.md, implementation-plan.md |
| M-facts | Instance facts are an unrecorded host-varying input | Facts are a **first-class recorded input**: `facts_hash` (+ retained `facts.json`) in the manifest `inputs` and the `gen-attestation` record, distinct from the operator-authored provisioning input. | trust-and-secrets.md, README.md, module-system.md |
| M-gen0key | Gen-0 SSH key seeded from unauthenticated IMDS before policy acceptance | **Removed** the carve-out. No `authorized_keys` is seeded from the facts channel before the selected provisioning trust policy accepts input; pre-eval reachability comes only from image-baked or accepted provisioning input. | provisioning.md |
| M-repart-order / locus | Full host.nix eval cannot precede first-boot repart | Keep full Nix evaluation in stage-2. A narrow typed storage plan in the provisioning bundle is authorized and validated in initrd, rendered to transient `repart.d`, and applied on first boot. Raw fragments and invalid plans fail before disk mutation; no plan uses baked defaults. | provisioning.md |
| M-static-ip | DHCP-less metadata-network clouds deadlock | The initrd `aos metadata` agent parses platform network config and seeds **static `networkd`** into the gen-0 `/var/etc` lower, so stage-2 has a route without DHCP. | provisioning.md |
| M-partial-commit | Degraded partial /etc ≠ hash(manifest) | The degraded generation is content-addressed over the **re-projected** manifest (full manifest minus un-fetched packages), re-hashed; the gen records the dropped set. Reproducible from (inputs + recorded drop-set). | orchestration.md, generations.md |
| M-forgeable-file | Priority-75/conscription key on forgeable `_file` | Provenance is assigned by the **resolver from the authenticated fetch source** (signed package identity / policy-accepted host.nix store path); module-supplied `_file` is **ignored** for priority and conscription. | module-system.md |
| M-read-absent | Fixpoint throw doesn't name a read of an absent root | Two discovery mechanisms separated: writes-to-undeclared (strict throw) vs reads-of-absent-root (resolver detects the raw missing-attr and dispatches on its root segment — `SystemRoots` for shared roots, else structural by-name lookup); throw-string parsing flagged P1-fragile, structured in P2 (aos-nix). | module-system.md |
| M-gc-inputs | cfg/ roots outputs, but cross-ABI re-eval needs inputs | Added a per-gen **`cfgsrc/` root** pinning the config-module **source** closure + the host.nix store path, so `apm gc` cannot break cross-ABI re-eval. | operability.md, generations.md |
| M-rollback-glob | `default aos-*.efi` glob picks the suspect UKI | Image rollback uses `bootctl set-default` / sd-boot boot-counting (`+tries` assessment), not the lexically-highest glob. | generations.md |

### Doc-consistency fixes (minors)

- README/problem framing: "fed by / driven by Ignition" → cloud user-data
  (Ignition removed). Reworded.
- Evaluator identity: gen-0 ships **stock C++ Nix** (`pkgs/tools/nix.nix`) for P1,
  invoked by `aos`; "evaluator = pkgs.aos" clarified.
- First-boot re-eval: a **new image's** first boot re-evals; a **plain reboot on
  the same image** does not. Both stated explicitly.
- `activate.sh.in` is **not** "reused unchanged": its `prepare` stage hard-codes
  the Ignition binary and must be retargeted to the `aos metadata` agent. Noted.
- `-Dfirstboot=false` is build-**disabled** (not just stripped); prefer
  manifest-rendered hostname. Noted.
- "materialization not building" sharpened: no compiler/configure/derivation
  realization — only assembling already-present bytes into an image with a fixed
  tool (`mkfs.erofs`).
- String-path discipline is enforced by a **publish-time lint** (no derivation
  refs in config modules), not author convention alone.
- Perf budget annotated: the figure is per *cold subprocess* eval, and the
  error-driven fixpoint adds K× (one missing option discovered per eval) — see
  operability.md; P2 aos-nix collapses K to 1 with structured errors + cache.
- Citation precision: options-only laziness lives in `mkOptionsTree` (not
  `:924-930`), and `isDefined`/`definitions` may force a merge — softened.

## Accepted as known (deferred, low severity)

- Throw-string parsing as a P1 resolver dependency is fragile by nature; it is the
  deliberate stock-Nix stopgap, retired by aos-nix structured errors (P2).
- The `uniq` conflict throw does not list every def/file (less legible than the
  readonly-conflict throw); acceptable for P1, improvable.
- Provider/capability disambiguation when one option-path maps to many packages
  is handled by the single-owner rule (D10) + variants `Conflicts` (D16); the
  residual ambiguity for capability *tokens* is tracked under the installed-set
  write-provider map (an unmet token is a terminal resolve assertion, never an
  auto-fetch).
