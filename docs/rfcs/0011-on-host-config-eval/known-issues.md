# Resolved review findings and the revision log

An adversarial review (72 agents: per-dimension skeptical finders + a refute-each
attempt) raised 65 findings; 48 survived refutation (2 critical, 13 major, 24
minor; 17 refuted). This document preserves the **three formerly open forks**
and the **revision log** of fixes applied to the other docs. All three forks are
resolved and implemented; the findings themselves were the review's, and the
resolutions here are the RFC's historical response.

## Resolved decisions (historical forks)

> **RESOLVED.** F1, F2, and F3 are now locked with decision-free mechanisms in
> [`decisions.md`](decisions.md): **F1** → dm-verity on the erofs root, roothash
> on the measured UKI `.cmdline` (PCR-11 covers the producer); **F2** → manifest
> carries job-script text, materializer writes gen-local paths; **F3** →
> capability-scoped contribution surface (owner declares contributable
> sub-paths). The alternatives below are retained only as design history; their
> descriptions do not describe current implementation gaps.

### F1 — How is the on-host evaluator + base lib anchored to measured boot? (from C1)

The review found that an earlier design put the evaluator and base lib on an
unprotected erofs root, outside the measured UKI. In that design an offline
attacker could replace the evaluator/base-lib without moving PCR-11 or PCR-7.
The implemented resolution is F1-A: the `server-verity` production-integrity
variant protects the erofs root with dm-verity and includes its root hash in the
PCR-11-measured UKI command line.

- **A (selected and implemented): dm-verity on the erofs root, roothash on the
  measured kernel cmdline.** Root tampering changes PCR-11 and fails the seal.
  This composes with the measured-boot stack and is wired by
  `systems/server-verity.nix`.
- **B (rejected): embed the evaluator + base-lib closure in the UKI initrd.**
  This would measure it directly, but produces a large initrd and conflicts
  with the documented
  `initrd → toplevel → initrd` cycle avoidance.
- **C (rejected): scope the claim down.** This would accept an unmeasured root
  and rely only on the
  `/var` seal + signed eval inputs. Weakest — an attacker with offline root write
  runs a tampered producer.

### F2 — How are shell-snippet service options rendered on-host? (from C2)

`script=`/`preStart=`/`postStart=`/`reload=`/`preStop=`/`postStop=` compile via
`makeJobScript` → `writeShellScriptBin` → a **derivation** whose built
`/nix/store/…-unit-script/bin` path is embedded in `ExecStart=`. Job-script
content is a function of the *evaluated* config, so it cannot be pre-built in
stage 1; on an eval-only host it would have to be **built** — violating invariant 1.

- **A (selected and implemented): the manifest carries job-script *text*; the
  materializer writes each to a generation-local path and rewrites `ExecStart=`
  to point at it.** Keeps the full systemd module language. Cost: the rendered `ExecStart=`
  bytes differ from the build-time form, so the P0 "byte-identical toplevel" gate
  must compare job scripts *semantically* (text equality), not by embedded path.
- **B (rejected): forbid the shell-snippet options in stage-2 config modules**,
  enforced by a publish-time lint. Simpler, but a genuine language restriction (many real
  units use `preStart`) and it falsifies "evaluates identically on either
  evaluator."

### F3 — What authorizes a package to write into another's (shared) root? (conscription vs composition)

The conscription rule (forbid foreign-root writes) rejects **legitimate
composition** — `nextcloud` writing `nginx.virtualHosts.*`,
`postgresql.ensureDatabases`, `redis.*` is a foreign-root write — while the
"registered contributor" escape is the same act an attacker would use, making the
rule either too strict or vacuous.

- **A (rejected): operator-grant.** `host.nix` would explicitly grant package A
  write access to a root/service. Safe and explicit; more operator wiring for
  ordinary apps.
- **B (selected and implemented): capability-scoped contribution surface.** The
  shared-root *owner* declares which sub-paths are open to non-owner contributors (e.g.
  `nginx` opens `virtualHosts.*` and `upstreams.*` but keeps `enable`/global
  owner-only). The owner curates the surface; composition (add a vhost/database)
  works without operator wiring; enabling/conscripting the service stays blocked.
  This makes "contributor" non-vacuous by scoping it per-root, per-sub-path.
- **C (rejected): strict-forbid; the operator composes.** Apps would declare requirements
  (assertions); the operator wires `nginx ↔ nextcloud` in `host.nix`. Most
  restrictive; heaviest operator burden.

## Revision log (fixes applied)

| # | Finding (sev) | Resolution | Doc(s) |
|---|---|---|---|
| C1 | Evaluator/base-lib was not actually measured | Anchored the erofs bytes through dm-verity and the PCR-11-measured UKI command line (F1-A). | trust-and-secrets.md |
| C2 | Job scripts need a build | Render now emits job-script **text** into the manifest; materializer writes gen-local; P0 excludes job-script bytes. (F2-A.) | architecture.md, implementation-plan.md |
| M-facts | Instance facts are an unrecorded host-varying input | Facts are a **first-class recorded input**: `facts_hash` (+ retained `facts.json`) in the manifest `inputs` and the `gen-attestation` record, distinct from the operator-authored provisioning input. | trust-and-secrets.md, README.md, module-system.md |
| M-gen0key | Gen-0 SSH key seeded from unauthenticated IMDS before policy acceptance | **Removed** the carve-out. No `authorized_keys` is seeded from the facts channel before the selected provisioning trust policy accepts input; pre-eval reachability comes only from image-baked or accepted provisioning input. | provisioning.md |
| M-repart-order / locus | Full host.nix eval cannot precede first-boot repart | Evaluate only the closed `aos.provisioning` projection from authenticated `host.nix` in initrd. Independently validate its pure JSON result, then render repart definitions. The full registry/package fixpoint remains stage 2. | provisioning.md |
| M-dual-config-language | A JSON storage bundle duplicates `host.nix` and creates two sources of truth | Removed the bundle schema. Cloud user-data is literal `host.nix`; a minimal URL/hash/signature pointer is transport metadata only. All storage intent lives at `aos.provisioning.storage`. | provisioning.md |
| M-provisioning-replay | Convergent repart on every boot lets later metadata changes mutate a committed host | Add a pending/committed GPT provenance protocol. Pending fails closed for recovery; committed boots still acquire/evaluate runtime configuration and dry-run the storage projection, but can never reopen disk mutation. | provisioning.md |
| M-image-policy | Server/debug/workload policy was selected by the golden image despite host.nix being primary | Define an explicit image/host boundary; split mixed profiles and move roles, desired packages, identity, services, runtime security, and observability into host.nix. | image-host-boundary.md |
| M-static-ip | DHCP-less metadata-network clouds deadlock | The initrd `aos metadata` agent parses platform network config and seeds **static `networkd`** into the gen-0 `/var/etc` lower, so stage-2 has a route without DHCP. | provisioning.md |
| M-partial-commit | Degraded partial /etc ≠ hash(manifest) | The degraded generation is content-addressed over the **re-projected** manifest (full manifest minus un-fetched packages), re-hashed; the gen records the dropped set. Reproducible from (inputs + recorded drop-set). | orchestration.md, generations.md |
| M-forgeable-file | Priority-75/conscription key on forgeable `_file` | Provenance is assigned by the **resolver from the authenticated fetch source** (signed package identity / policy-accepted host.nix store path); module-supplied `_file` is **ignored** for priority and conscription. | module-system.md |
| M-read-absent | Fixpoint throw doesn't name a read of an absent root | Two discovery mechanisms separated: writes-to-undeclared (strict throw) vs reads-of-absent-root (resolver detects the raw missing-attr and dispatches on its root segment — `SystemRoots` for shared roots, else structural by-name lookup); throw-string parsing flagged P1-fragile, structured in P2 (aos-nix). | module-system.md |
| M-gc-inputs | cfg/ roots outputs, but cross-ABI re-eval needs inputs | Added a per-gen **`cfgsrc/` root** pinning the config-module **source** closure + the host.nix store path, so `apm gc` cannot break cross-ABI re-eval. | operability.md, generations.md |
| M-rollback-glob | `default aos-*.efi` glob picks the suspect UKI | Image rollback uses `bootctl set-default` / sd-boot boot-counting (`+tries` assessment), not the lexically-highest glob. | generations.md |

### Doc-consistency fixes (minors)

- README/problem framing: "fed by / driven by Ignition" → cloud user-data
  (Ignition removed). Reworded.
- Evaluator identity: gen-0 ships **aos-nix** as the measured production
  evaluator. The AOS-built C++ Nix remains only in differential parity checks;
  it is never a runtime fallback.
- Runtime re-eval: every boot reacquires/authorizes `host.nix` and performs
  full evaluation; only storage mutation is first-boot-only.
- `activate.sh.in` now prepares through the native `aos metadata` agent; no
  Ignition binary remains in the production activation path.
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
