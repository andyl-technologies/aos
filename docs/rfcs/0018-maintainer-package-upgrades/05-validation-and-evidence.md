# Validation, evidence, and reporting

## Principle

Affected-graph tests provide fast repair feedback; the complete required AOS
test policy determines completion. A narrow build or an agent's claimed test
result never substitutes for final validation.

Every gate result binds:

- exact base and candidate Git commits or pre-commit tree identity;
- maintenance inventory, discovery snapshot, update plan, and policy digests;
- campaign and every unit/component current/target identity;
- target platform and builder identity;
- exact test definition and AOS tool closure;
- immutable result and log digests.

Any semantic edit, generated-input change, candidate commit, history rewrite,
rebase, or relevant policy change invalidates affected results.

## Gate planning

The pure planner selects gates from evaluated facts:

- campaign units, component target vectors, members, and source/artifact graph;
- supported targets from
  [`pkgs/_platform-support.nix`](../../../pkgs/_platform-support.nix);
- direct/transitive dependencies and reverse dependencies;
- package-authored checks;
- system, image, VM, and fleet consumers reached by the changed closure;
- package-authored risk floor and deterministic escalation;
- explicit exceptional-gate tags.

The resulting `aos.package-update-gate-plan/v1` is closed, canonical, and
included in the update plan. Execution can reorder independent gates for fast
feedback but cannot omit or reinterpret them. Unknown applicability is a block,
not implicit inapplicability.

## Quick validation

Run after deterministic materialization and every accepted repair:

1. update-plan, schema, owner-path, expected-value, diff, and policy validation;
2. Nix parsing and `aos fmt --check`;
3. `aos lint` plus maintenance-inventory coverage/integrity checks;
4. `checks.eval`;
5. every changed source and declared fixed-output materializer;
6. every update-unit member on each eligible target available through the
   configured local AOS build environment;
7. all package-authored checks for those members;
8. a deterministic bounded reverse-dependency canary set;
9. the previously failing gate first, when an attempt is a focused repair.

Independent gates may continue after one failure when doing so is safe and
provides useful diagnosis. Each result retains its exact status; an overall
failure cannot hide passing or additional failing gates.

The reverse-dependency canary algorithm favors:

- direct consumers;
- consumers exercising distinct outputs and target paths;
- high fan-out and system-critical nodes;
- packages with relevant authored checks;
- a stable sample keyed by the plan digest so retries use the same set.

High-risk units may select the full affected closure even during quick
validation.

## Candidate commit and final validation

After a maintainer accepts and commits the candidate, final validation runs on
that exact commit. `ready-for-pr` requires:

1. canonical inventory, discovery, plan, journal, semantic diff, filesystem
   diff, and evidence validation;
2. every campaign component source and secondary fixed-output artifact;
3. every campaign unit member on every eligible AOS target;
4. every member's package-authored checks;
5. the complete affected reverse-dependency closure selected by risk policy;
6. every existing `aos test` layer—eval, Rust, build, VM, and fleet;
7. source assurance, license, local contributor-identity/signature preflight,
   and package-update policy checks;
8. all unit/risk-specific gates;
9. repeat clean builds where exceptional policy requires comparison.

The five repository layers are implemented in
[`crates/aos/src/commands/test.rs`](../../../crates/aos/src/commands/test.rs).
The maintainer tool invokes them through the documented AOS/Nix environment,
not `cargo run`, host tools, or nixpkgs.

All tests run from the maintainer workflow. If the current machine and its local
AOS build/confinement environment cannot provide KVM, a target platform, or
another required capability, the gate remains unavailable and the run remains
incomplete. The tool reports the exact command, capability, and expected result
needed; it does not silently reduce the plan.

Authoritative contributor authorization is necessarily pending until the PR
exists and the repository's fail-closed private-record check evaluates its exact
head. It is not a local final gate and `ready-for-pr` does not imply it passed.
After publication, a later foreground observation may record remote
authorization/review/check state as `merge-eligible-observed`; uncertainty
remains action-required.

If a repair follows final-test failure, it creates a new attempt/candidate
commit. All commit-bound final results run again. If the maintainer rewrites
history before publication, final validation runs on the exact new published
head.

## Result states

Every logical gate has one of:

- `success`: it ran and passed, or deterministic policy proved it inapplicable;
- `failure`: it ran and failed, or its policy input was invalid;
- `action-required`: it could not run, required evidence is indeterminate, or a
  maintainer/specialist decision is outstanding;
- `cancelled`: the run was superseded or deliberately stopped.

“Not attempted,” “host lacks capability,” and “agent says unnecessary” are not
success. Inapplicability includes a machine-verifiable explanation in the gate
plan.

## Special validation

### Concurrent streams

- Build and test only the selected stream's unit and its actual affected graph.
- Do not mutate sibling major units because they share a family.
- Validate family/successor metadata and any default alias separately.
- A stream introduction, retirement, or default change is a human migration
  with its own plan and complete impact graph.

### Bootstrap and compiler ladders

- Prove each changed bootstrap edge in order.
- Rebuild downstream compiler/runtime stages and selected systems.
- Require an explicit cohort/migration plan.
- Never compare historical rungs with the family's global newest release.
- Require maintainer/toolchain review and policy-selected repeat builds.

### Kernel, init, crypto, and Secure Boot

- Build every supported architecture and relevant image.
- Run boot, VM, fleet, recovery, and signing-policy tests reached by the graph.
- Surface configuration/ABI, dependency, and feature changes.
- Require named specialist review.

### QEMU and Crucible

- Preserve the Apache-host/GPL-side process and protocol boundary.
- Run `gate:abi-conformance` and `gate:license-boundary`.
- Validate updates to `pkgs/emulation/qemu-patches/LICENSES.md` when files are
  created or removed.
- Prove complete corresponding source for distributed patched QEMU.
- Require the human legal-name DCO sign-off for QEMU-side changes.
- Retain the release policy that publishes the `crucible` suite rather than an
  invalid standalone patched-QEMU root.

### New dependencies

- Stop for explicit maintainer scope approval.
- Add the dependency as a complete hermetic AOS package.
- Give it a valid maintenance classification/update unit.
- Recompute build/runtime/reverse-dependency and license impact.
- Preserve upstream features rather than disabling them.
- Expand to a new multi-unit campaign plan and rerun invalidated gates.

## Evidence model

Every attempt produces canonical `aos.package-update-evidence/v1`. The final
dossier references all attempts and contains these sections.

### Identity

- campaign, run, attempt, parent-attempt, and ordered update-unit IDs;
- family, stream, classification, lifecycle, members, and cohort;
- every unit's current/target package version and component
  upstream/comparison vector;
- base, candidate head, tree, patch, inventory, snapshot, plan, policy, and
  evidence digests;
- platforms and risk.

### Discovery and source

- provider/project/adapter identity and retrieval time;
- raw primary and advisory candidate sets;
- normalization, rejection, ordering, and selection reasons;
- requested URL, mirrors, redirects, final origin, size, and digest;
- release/tag/ref, checksum, signature, and provenance identities/results;
- anomalies, disagreement, quarantine, and maintainer source decisions.

### Mutation

- exact semantic fields and expected/actual old/new values;
- changed paths, modes, and filesystem diff digest;
- source/artifact materialization graph and outputs;
- generated lock/vendor inputs;
- deterministic, agent-proposed, and maintainer-authored change classes;
- approved scope/risk changes and the accepting maintainer action.

### Validation

- planned gates and applicability explanations;
- exact typed command/action, target, builder identity, AOS/tool closure,
  start/end observation, exit class, and log/result digest;
- retries and flaky/infrastructure classification without discarding failure
  history;
- complete exact-head final summary.

### Workflow

- append-only transitions and actor classes;
- worktree, branch, commit, and PR identity;
- attempt/time/token/compute/download/disk usage and limits;
- warnings, blockers, superseding/rejection/abandon reason;
- final disposition and eventual protected merge identity if observed.

Schemas bound string, list, map, log, and artifact sizes. Public PR rendering
strips credentials, headers, cookies, environment values, private paths/URLs,
raw model prompts/responses, and unrelated source content. Restricted local logs
remain mode `0600` under the run's retention policy.

## Evidence is not release provenance

The dossier proves what the local maintainer tool observed and ran. It is not a
release signature, publication receipt, or claim that the candidate is benign.
RFC-0017 independently evaluates the merged protected commit and creates its
own build, qualification, signing, and publication evidence.

A future format can wrap trusted test results in an in-toto v1
[Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
using the
[test-result predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md).
Until a trusted signer authenticates it, the JSON remains structured evidence,
not an attestation. GitHub similarly notes that attestations require consumer
verification, are not a security verdict, and target released artifacts rather
than frequent test builds. See its
[artifact-attestation guidance](https://docs.github.com/en/actions/concepts/security/artifact-attestations).

## Human-readable reports

### Staleness report

Group by risk and lifecycle, then family/stream. Show:

- current and selected candidate identities;
- primary source and Repology agreement/disagreement/unknown;
- observation freshness;
- ignored/prerelease/other-stream candidates and reasons;
- freeze reason/review date;
- last run and blocker;
- expected impact/cost class.

Do not reduce the report to current/latest columns. It must make maintained
stream policy visible, especially for concurrent majors and LTS lines.

### Run status

Show the verified state, current attempt, worktree/commit, semantic diff,
completed/failing/pending gates, remaining budget, and exact next safe command.

### PR summary

Render a bounded summary such as:

```text
Unit: bazel-8 (family bazel, stream 8)
Change: 8.4.2 -> 8.4.3
Upstream: confirmed by declared primary; Repology agrees/disagrees/unknown
Inputs: source and Bazel dependency hashes changed; patches unchanged
Impact: 1 member, 34 reverse dependencies, four eligible targets
Risk: high (build-tool reach; package-authored floor)
Repairs: one bounded patch refresh accepted by the maintainer
Final head: <commit>
Gates: 27 passed, 0 failed, 0 action-required
Human gates: package/toolchain owner review
Evidence digest: sha256:...
```

The displayed numbers come from structured evidence. The report does not embed
raw logs or agent narratives.

## Metrics

The local report aggregates non-sensitive run data for the checkout:

| Metric | Purpose |
| --- | --- |
| Package/update-unit classification coverage | Foundation completeness |
| Automatic source/artifact coverage | Safely automatable surface |
| Stale age by risk and lifecycle | Maintenance exposure |
| Discovery unknown/disagreement rate | Provider and mapping quality |
| Deterministic materialization success | Value before agent assistance |
| First quick-gate success | Contract/package quality |
| Agent assist, escalation, and gateway-rejection rate | Repair effectiveness and scope quality |
| Attempts and elapsed time to ready-for-PR | Maintainer throughput |
| Final gate pass/failure by target/layer | Candidate and test health |
| Same-identity byte anomaly count | Supply-chain warning |
| Compute, disk, download, and inference use per accepted update | Local resource control |

The goal is trustworthy reduction in stale exposure and reviewer work, not the
maximum number of generated PRs.

## Retention and cleanup

Retain merged, rejected, high-risk, and quarantined run dossiers longer than
ordinary no-change or superseded observations. Cache data is disposable when no
retained run references it. Deleting large logs leaves a tombstone with digest,
size, result, and retention decision.

`aos maintain clean` shows the worktree, branch, run state, retained evidence,
and reclaimable space before deletion. It refuses an uncommitted/unadopted
worktree by default and never deletes unrelated Git worktrees or repository
state.
