# Continuous Integration

AOS CI is built on one principle: **`flake.nix` is the single source of
truth for what CI runs.** Every lint, test, and build is a Nix derivation
under `checks.<system>`. CI does not maintain its own list of checks — it
builds them, grouped into a few jobs by function.

This works because AOS is built entirely from source (no nixpkgs): a check
is reproducible by construction, and "running" it is just `nix build`.

## Why functional jobs (not one job per check)

AOS already has hundreds of checks and will have thousands. Fanning out one
CI job per check is the wrong model:

- it hits GitHub's matrix limits (max 256 jobs per run), and
- most checks share large build closures (the toolchain, packages, the
  kernel), so per-check jobs rebuild the same things over and over.

Instead, checks are **segmented into a small, fixed set of jobs by
function**. Each job builds its whole group with a single `nix build` of an
aggregate derivation, so a shared dependency is realised once per job.
Adding a check never adds a job — it joins an existing group by name.

| Job | Covers (check names) | Runner |
|-----|----------------------|--------|
| `lint` | `format`, `lint` (alejandra + the hermeticity/convention linter) | `andyl-nixos-latest` |
| `eval` | `eval`, `module-*`, `ignition-format`, `fleet-spec`, `systemd-*`, `trivial-builders` | `andyl-nixos-latest` |
| `rust` | `cargo-fmt`, `cargo-clippy`, `cargo-test`, `cargo-doc` | `andyl-nixos-latest-32` |
| `tla` | `tla-*` (TLA+ model checking) | `andyl-nixos-latest-32` |
| `build` | `aos`, `build-*` (critical packages, kernel config, hardening) | `andyl-nixos-latest-32` |
| `integration` | `integration-*` (Firecracker package smoke tests) | `andyl-nixos-latest-32` *(KVM)* |
| `vm` | `server-*`, `edge-*` (module VM tests) | `andyl-nixos-latest-32` *(KVM)* |
| `fleet` | `fleet-*` (multi-VM tests) | `andyl-nixos-latest-32` *(KVM)* |

The mapping lives in `lib/ci/groups.nix` (`groupOf`), keyed off the flat
check names. Unknown checks fall into `build` (the heavy runner) rather
than being treated as cheap.

## Layout

```
flake.nix
  checks.<system>.<name>     ← every check, flat, one leaf derivation each
  ciGroups.<system>.<group>  ← one aggregate per functional job

lib/ci/groups.nix            ← group classifier + aggregate builder
lib/testing/rust.nix         ← cargo-fmt / cargo-clippy / cargo-test / cargo-doc
lib/testing/nix-lint.nix     ← checks.lint: hermeticity & convention linter

.github/workflows/ci.yml         ← the functional jobs + ci-success gate
.github/workflows/cache-warm.yml ← master: build & push the closure to Attic
```

## Workflow

`ci.yml` runs on every PR, on `master`, and in merge queues. It has one job
per group (each `nix build .#ciGroups.x86_64-linux.<group>`) plus
**`ci-success`**, a single aggregate status — make *that* the required
status for branch protection so it stays stable as checks come and go.
`concurrency` cancels superseded runs.

`cache-warm.yml` runs on pushes to `master`: it builds the entire check
closure on the 32-core runner and pushes every store path to the `andyl-os`
Attic cache, so PR runs substitute pre-built paths and only rebuild what
changed.

## Running checks locally

```sh
nix build .#checks.x86_64-linux.cargo-clippy   # a single check
nix build .#ciGroups.x86_64-linux.eval         # a whole CI job's group
nix build .#checks.x86_64-linux.lint           # the Nix linter (== aos lint)
nix flake check                                # everything
aos lint                                        # the Nix linter, via the CLI
```

## Adding a check

1. Add the derivation to `default.nix`'s `checks` (or to a system / package,
   which is auto-discovered).
2. Expose it as a leaf attribute in `flake.nix`'s `checksFor`, named so
   `lib/ci/groups.nix`'s `groupOf` routes it to the right job (prefix it
   `build-` for a build check; leave VM checks under
   `server-`/`edge-`/`integration-`/`fleet-`; etc.).
3. That's it — the matching job picks it up. No workflow edits, no new job.
   If it's a genuinely new *function*, add a group to `groupNames`/`groupOf`
   and a one-job stanza to `ci.yml`.

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
relies on the runner's `nix.conf` for *reads* (matching `nix-host`'s own
`test.yaml`), so no per-workflow secret is needed for substitution.

### 3. Grant `ATTIC_TOKEN` push access to `andyl-os`

`cache-warm.yml` uses `andyl-technologies/github-actions/setup-attic` with
`secrets.ATTIC_TOKEN` and the `deploy` environment (same as `nix-host`'s
`build-cache.yaml`). Ensure the token can push to the new `andyl-os` cache,
and that this repo may use the `deploy` environment / `ATTIC_TOKEN` secret.

### 4. Confirm `/dev/kvm` inside the runner container (`integration`/`vm`/`fleet`)

The `integration`, `vm`, and `fleet` jobs run checks with
`requiredSystemFeatures = [ "kvm" ]`. The runners run inside a NixOS
container (`nix-host: config/host/role/builder/github-runners.nix`), which
does not currently pass `/dev/kvm` through. Verify and, if needed, expose the
device (and advertise the `kvm` system feature in the runner's `nix.conf`).
Without this, those jobs cannot run on the self-hosted runners.

### 5. Branch protection

Set **`CI Success`** as the sole required status check for `master`. It
aggregates all functional jobs, so it is the only name that needs to be
required even as checks come and go.
