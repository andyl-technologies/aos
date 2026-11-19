# Upgrade packages with `aos maintain`

`aos maintain` discovers upstream releases, plans and applies package updates
in isolated Git worktrees, runs the required gates, and prepares an ordinary
pull request. Every step is a foreground command whose state survives shell
exit and reboot, so you can stop, inspect, edit by hand, and resume at any
point. The tool never merges or releases: a merged update enters the normal
[release process](release-checklist.md) like any other source change.

Run the commands from a maintainer checkout with the development shell. The
[package maintenance design](../engineering/package-maintenance/README.md)
explains the update contract, workflow states, and confinement boundary.

## Find stale packages

```sh
aos maintain inventory --check
aos maintain scan
aos maintain report --outdated
aos maintain status
```

`inventory` evaluates the repository's update units and binds them to the
exact Git commit, tree, and dirty state it evaluated; `--check` fails unless
every unit satisfies the closed contract. `scan` queries each unit's declared
primary upstream (GitHub releases or tags, or Go releases) and caches the
observations. A read-only GitHub token from `AOS_GITHUB_READ_TOKEN` (or
`--token-env NAME`) raises API limits. `--repology-fallback` additionally probes
Repology by project name for units without an explicit advisor; Repology
findings are advisory and never select source bytes. `--offline` uses only
sufficiently fresh cached observations.

`report` is a read-only inbox over the cached observations. Select one view
with `--outdated`, `--unknown` (incomplete upstream evidence), `--advisory`,
`--vulnerable`, or `--license-change`, and narrow it with `--family`. `ui` opens
a read-only full-screen view of the same state.

Packages without a typed update contract appear as manual units. Bootstrap
inputs that are deliberately pinned appear as frozen.

## Plan and run an update

```sh
aos maintain plan zlib-1
aos maintain run zlib-1
```

A plan freezes the candidate version of every component, the permitted edits,
materializers, risk, and gates without touching the checkout. Use
`--target VERSION` for a one-component unit or `--component NAME=IDENTITY` for
each component of a composite unit. `--campaign COHORT` plans every
update-ready unit of a cohort that must land atomically.

`run` creates a managed worktree at the planned base, rewrites the declared
version, URL, and hash literals, materializes generated inputs such as Cargo,
Go, npm, and Bazel dependencies, validates the semantic diff against the plan,
and runs the quick gates. It stops at `quick-gated` by default; use
`--until worktree-ready`, `materialized`, or `policy-valid` to stop earlier, and
`run --plan PLAN --confirm-plan DIGEST` to execute a plan created earlier.

Inspect progress at any time:

```sh
aos maintain inspect <run>
aos maintain inspect <run> --failure
aos maintain inspect <run> --log <gate>
aos maintain diff <run> --semantic
aos maintain diff <run> --patch
```

Run identities may be abbreviated when unambiguous. `resume <run>` continues
from the last verified boundary after an interruption.

## Repair a failure

When a gate fails, `repair <run>` returns typed manual repair instructions by
default. With `--agent local --adapter /abs/path/to/adapter`, it runs one
local adapter program, which speaks a closed JSON protocol on standard input
and output, inside the confinement boundary. The adapter has no Git, GitHub,
release, signing, SSH-agent, or unrelated filesystem access. A proposal is only
applied after you confirm its exact patch digest with `repair <run> --confirm
DIGEST`.

You can also edit the worktree yourself. `accept <run> --adopt-worktree`
records validated manual edits as a new attempt; the tool never overwrites an
unknown head.

## Accept, commit, and run the final gates

```sh
aos maintain accept <run> --confirm <patch-digest>
aos maintain commit <run> --confirm <run>
aos maintain test <run> --final
```

`accept` and `commit` print a preview first and act only when given the
confirmation value it shows. The commit uses your Git identity and repository
policy. Final gates run against the exact commit; any later edit invalidates
earlier results. `test <run> --quick` reruns the quick gates. The run's
retained records (journal, materialization, accepted repair attempts, and quick
and final gate results) are its evidence; there is no separate dossier.

## Publish and hand off

```sh
aos maintain prepare-pr <run>
aos maintain publish-pr <run> --expected-remote-head absent
aos maintain observe-pr <run> --authorization-check <check-name>
aos maintain handoff <run> --confirm <merge-commit>
```

`prepare-pr` works offline. On a final-gated run it first verifies that the
retained materialization, accepted repair lineage, and quick and final gate
results bind one plan, the accepted patch, and the exact candidate commit with
every gate successful, then records the run as `ready-for-pr`. It renders the
title, body, and publication inputs, which bind the canonical digest of the
final gate results. Repeating it on a `ready-for-pr` run re-verifies the same
records and renders the same draft.
`publish-pr` pushes only the exact final-gated branch and creates the matching
pull request using a token from `AOS_GITHUB_TOKEN` (or `--token-env`); pass the
current remote branch head instead of `absent` when updating an existing
branch, and repeat with `--confirm` and the digest shown by the preview.
`observe-pr` refreshes the exact head's checks, reviews, the required
contributor-authorization check, and merge state with a read token. After a
human merges the pull request, `handoff` records the protected merge commit as
ready for release.

Use `abandon <run>` to stop a run while keeping its evidence, and
`clean <run> --confirm <run>` to remove a terminal run's clean worktree.

## Packages without an update contract

For a package that has no typed update contract yet, edit its version by hand
and refresh its fixed-output hashes:

```sh
aos maintain refresh-hashes <unit>
aos maintain refresh-hashes <unit> --check
```

The command replaces one known fetcher or dependency hash at a time with the
standard placeholder, asks Nix for the resulting fixed-output hash, and restores
the file if evaluation or realization fails. `--check` verifies without keeping
changes.

## Local state

State lives under `$XDG_STATE_HOME/aos/maintain` (default
`~/.local/state/aos/maintain`), with one directory per repository identity,
derived from the canonical remote and Git common directory. Override it with
`--state-dir`. It holds inventory envelopes, discovery snapshots, immutable
plans, managed worktrees, and per-run journals and attempts. Journals are
hash-chained to detect accidental corruption.

Candidate evaluation, network materialization, gates, and repair adapters run
inside a local confinement boundary built from Linux user, mount, PID, IPC, UTS,
and network namespaces plus the AOS Landlock wrapper. Commands that need it fail
rather than run unconfined when the host lacks either primitive.
