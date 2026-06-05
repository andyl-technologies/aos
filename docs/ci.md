# Continuous Integration

AOS CI is built on one principle: **`flake.nix` is the single source of
truth for what CI runs.** Every lint, test, and build is a Nix derivation
under `checks.<system>`; GitHub Actions does not maintain its own list. A
generator turns the check set into a job matrix, so adding a check in Nix
automatically adds a CI status — no workflow edits.

This works because AOS is built entirely from source (no nixpkgs): a check
is reproducible by construction, and "running" it is just `nix build`.

## Layout

```
flake.nix
  checks.<system>.<name>          ← every check, flat, one leaf derivation each
  githubActions.matrix            ← classified job matrix (x86_64-linux)

lib/ci/github-matrix.nix          ← pure-Nix matrix generator + tier classifier
lib/testing/rust.nix              ← cargo-fmt / cargo-clippy / cargo-test / cargo-doc
lib/testing/nix-lint.nix          ← `checks.lint`: hermeticity & convention linter

.github/workflows/ci.yml          ← fast lane + dynamic matrix + ci-success gate
.github/workflows/cache-warm.yml  ← master: build & push the closure to Attic
```

## Tiers

Each check is classified by name into a tier that selects its runner and
whether it needs KVM (see `lib/ci/github-matrix.nix`):

| Tier | What | Examples | Runner | KVM |
|------|------|----------|--------|-----|
| 0 | fast, no compile | `format`, `lint`, `cargo-fmt`, `cargo-clippy`, `eval`, `tla-*`, `module-*`, `systemd-*` | `andyl-nixos-latest` | no |
| 1 | compiles / builds | `cargo-test`, `cargo-doc`, `aos`, `build-*` | `andyl-nixos-latest-32` | no |
| 2 | virtualized | `server-*`, `edge-*`, `integration-*`, `fleet-*` | `andyl-nixos-latest-32` | **yes** |

The classifier matches exact names first, then name prefixes, and finally
falls back to tier 1 (build on the big runner) for any unrecognised check —
so a new check is never silently treated as free.

## Workflow shape

`ci.yml` runs on every PR, on `master`, and in merge queues:

- **Fast lane** — `format`, `lint`, `cargo-fmt`, `cargo-clippy` run as
  dedicated jobs that start immediately, giving sub-minute red/green on the
  most common mistakes. (They are excluded from the matrix to avoid a
  duplicate status.)
- **`matrix`** — one `nix eval` produces the job matrix.
- **`checks`** — a fan-out job per check, routed to its tier's runner, with
  `fail-fast: false` so one failure never masks the others. Each job appends
  a one-line result (status, tier, runner, duration) to the run summary and,
  on failure, folds the tail of `nix log` into the job output.
- **`ci-success`** — a single aggregate status. Make *this* the required
  status for branch protection; it turns red if any job failed.

`cache-warm.yml` runs on pushes to `master`: it builds the entire check
closure on the 32-core runner and pushes every store path to the `andyl-os`
Attic cache, so subsequent PR runs substitute pre-built paths and only
rebuild what changed.

## Running checks locally

Everything CI runs is reproducible with one command:

```sh
nix build .#checks.x86_64-linux.cargo-clippy   # a single check
nix build .#checks.x86_64-linux.lint           # the Nix linter (== aos lint)
nix flake check                                # everything
aos lint                                        # the Nix linter, via the CLI
nix eval --json .#githubActions.matrix          # preview the CI matrix
```

## Adding a check

1. Add the derivation to `default.nix`'s `checks` (or to a system / package,
   which is auto-discovered).
2. Expose it as a leaf attribute in `flake.nix`'s `checksFor`, named so the
   classifier routes it correctly (prefix it `build-` for a build check,
   leave VM checks under `server-`/`edge-`/`integration-`/`fleet-`, etc.).
3. That's it — CI picks it up on the next run. If it needs an unusual
   runner/tier, add an entry to the classifier.

---

## Infrastructure prerequisites (must be done on the Andyl side)

This PR adds the workflows and the Nix plumbing. The following must exist on
the infrastructure side (`nix-host`, the Attic server, repo settings) before
CI is green and fast. None of it lives in this repo.

### 1. Create the `andyl-os` Attic cache

AOS shares **no** store paths with the existing `andyl-nixos` /
`andyl-nixpkgs` caches — those are nixpkgs-derived; AOS is built from source.
A dedicated cache is required, or every CI build is cold.

On the atticd master (see `nix-host: config/host/role/builder/atticd.nix`):

```sh
atticadm make-cache andyl-os          # or the equivalent for the modified attic
# generate the cache's signing keypair; record the public key
```

### 2. Make the runners substitute from `andyl-os`

Add the new cache to the runners' default substituters and trusted keys,
alongside the existing entries in
`nix-host: config/host/base/nix/default.nix` (the `andyl.nix.cache` block):

```nix
settings.substituters       = [ ... "https://nix-cache-hil1.paradise-matrix.ts.net/andyl-os/" ];
settings.trusted-public-keys = [ ... "andyl-os:<PUBLIC_KEY_FROM_STEP_1>" ];
```

Until this lands, PR builds are correct but cold (no cache hits). `ci.yml`
intentionally relies on the runner's `nix.conf` for *reads* (matching
`nix-host`'s own `test.yaml`) rather than passing `--extra-substituters`, so
no per-workflow secret is needed for substitution.

### 3. Grant `ATTIC_TOKEN` push access to `andyl-os`

`cache-warm.yml` uses `andyl-technologies/github-actions/setup-attic` with
`secrets.ATTIC_TOKEN` and the `deploy` environment (same as `nix-host`'s
`build-cache.yaml`). Ensure the token's permissions include push to the new
`andyl-os` cache, and that the `andyl-os` repo is allowed to use the
`deploy` environment / `ATTIC_TOKEN` secret.

### 4. Confirm `/dev/kvm` inside the runner container (tier-2 checks)

VM and fleet checks (`server-*`, `edge-*`, `integration-*`, `fleet-*`) set
`requiredSystemFeatures = [ "kvm" ]`. The runners run inside a NixOS
container (`nix-host: config/host/role/builder/github-runners.nix`), which
does not currently pass `/dev/kvm` through. Verify and, if needed, expose the
device to the container (and ensure the `kvm` system feature is advertised in
the runner's `nix.conf`). Without this, tier-2 jobs cannot run on the
self-hosted runners.

### 5. Branch protection

Set **`CI Success`** as the sole required status check for `master`. It
aggregates every fast-lane job and every matrix job, so it is the only name
that needs to be required even as checks come and go.
