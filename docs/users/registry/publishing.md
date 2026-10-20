# Publish packages and releases

Use one authoring clone per registry and serialize publishers for that clone.
The local clone has a release lock, but two machines can still race when they
publish the same remote pointers.

## Set up an authoring clone

Create a new signed registry as shown in the [quickstart](quickstart.md). To
attach a smart Git remote at creation time:

```sh
apr create acme \
  --remote ssh://git@code.example.com/acme/registry.git \
  --trust-key "$TRUST_KEY" \
  --trust-key-id initial \
  --key "$KEY"
apr push --registry acme --branch stable --set-upstream
```

To take over an existing registry, configure its public URL and trust anchor
with `apr add`. When invoked as `apr`, the command materializes an authoring
clone as well as consumer state:

```sh
apr add https://packages.example.com/acme/ \
  --name acme \
  --trust-key 'acme:Ed25519:BASE64_KEY'
```

Register locally held signing keys by roster id:

```sh
apr keys register initial \
  --key /secure/registry/acme-initial.key \
  --registry acme
```

An external secret manager can be used without writing its key to APM config:

```sh
apr keys register initial \
  --key-command 'secret-tool lookup service aos-registry key initial' \
  --registry acme
```

The command string is saved in local registry configuration and run through a
shell. Keep secrets out of the string itself, and ensure the command writes
only an OpenSSH private key to standard output.

## Publish one package

Build the package first, then publish its store path:

```sh
STORE_PATH="$(nix build .#pkg-curl --no-link --print-out-paths)"

apr publish "$STORE_PATH" \
  --registry acme \
  --key-id initial
```

For an ordinary package, `apr publish` evaluates the target-specific
`DerivationInventoryV1` and requires the requested path to be that record's
exact primary output. Name, version, public metadata, source identity, named
outputs, generated documentation, and any package contract all come from the
same evaluated record. A contract-bearing package is written with its
documentation and complete realization graph in one transaction and one
commit; the command never searches for a contract by package name or store
path.

The complete ordinary-package transaction always creates one signed commit.
`--no-commit` and manual metadata flags are reserved for `--sysroot`, whose
image catalog entry is outside the ordinary package inventory.

For a grouped change, commit only the intended registry paths with `apr commit`.
It uses the same in-process signer as the other producer commands, requires a
trusted key when `keys.toml` has an active roster, and refuses an already-staged
index so unrelated maintainer state cannot leak into the commit. `apr sign`
only signs nonrelease maintenance tags; signed semver releases are immutable:

```sh
apr commit packages store registry.toml \
  --registry acme \
  --key-id initial \
  --message "publish the 2026.8 package set"
apr verify --registry acme
```

Review `apr status` and `apr diff` before committing. Name every intended path
explicitly; `apr commit` does not retain a shell-out signing path or silently
fall back to a broad `git add -A`.

Useful package forms include:

```sh
# Publish an OS toplevel.
apr publish /nix/store/HASH-aos-system-toplevel \
  --registry acme --sysroot --key-id initial

# Associate prebuilt image artifacts with a sysroot package.
apr publish /nix/store/HASH-aos-system-toplevel \
  --registry acme --sysroot \
  --image-payload /nix/store/HASH-aos-image-qcow2 \
  --image-disk /nix/store/HASH-aos-image-qcow2-disk \
  --image-info /nix/store/HASH-aos-image-qcow2-info \
  --image-format qcow2 --image-uki /nix/store/HASH-uki/aos.efi \
  --image-payload /nix/store/HASH-aos-image-raw \
  --image-disk /nix/store/HASH-aos-image-raw-disk \
  --image-info /nix/store/HASH-aos-image-raw-info \
  --image-format raw --image-uki /nix/store/HASH-uki/aos.efi \
  --key-id initial
```

Provide one payload, regular-file disk output, regular-file metadata output,
format, and exact UKI for each image encoding. The disk and metadata outputs
are published through the registry's Nix cache; the payload supplies layout,
recovery, and update facts for validation. `--previous` records the prior
package version when maintaining a version chain. `--source-drv` records
source material used by `apm source`.

## Inspect before release

Review the authoring state and verify that the local store still contains the
published closure:

```sh
apr status --registry acme
apr diff --registry acme
apr verify --registry acme
apr store verify --registry acme --deep
```

`apr verify` checks metadata and closure-graph consistency. `apr validate`
checks that referenced artifacts are reachable from an advertised cache and is
most useful after an upload:

```sh
apr validate --registry acme --jobs 32
```

## Run the complete release pipeline

For routine publication, prefer `apr release` over a hand-assembled sequence:

```sh
apr release 2026.8.0 \
  --registry acme \
  --key-id initial \
  --cache-key /secure/registry/acme-narinfo.key \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

The positional version is the registry snapshot version and has no `v`
prefix. It does not need to match any package version.

When `--store-path` is supplied, one command publishes the package and the
release:

```sh
apr release 2026.8.1 \
  --registry acme \
  --store-path "$STORE_PATH" \
  --description "Command-line URL transfer tool" \
  --license curl \
  --maintainer registry@example.com \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

The package version still defaults to the version parsed from the store-path
basename. Use `--version` when the output name does not carry its package
version, or when the package version intentionally differs from the registry
snapshot version. Attached image metadata must name that exact package version.

`--cache-key` is optional. When present, it is a Nix narinfo signing key in
`name:base64-secret` form. It is not the OpenSSH maintainer key used by
`--key-id`.

Preview the ordered plan without mutation:

```sh
apr release 2026.8.1 \
  --registry acme \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry \
  --dry-run
```

Use `--resume` after an interrupted release. It reuses verified immutable
artifacts for the same release; an explicit stage also requires its observed
`--stage-revision`. Do not use it to paper over an
unknown or conflicting publisher.

## Upload an unpublished candidate

For a fresh static surface, publish the signed initialization commit before
creating the first stage. This establishes its default `HEAD` and base commit;
it does not create a release or assign channel partitions:

```sh
apr origin upload --registry acme \
  --upload-url s3://acme-packages/registry
```

Start from a maintainer branch in the authoring clone. Default and channel
branch names are reserved; the stage binds the ordinary source branch and the
exact prepared commit. Use the same release porcelain with a stable stage id
when the candidate needs inspection before finalization:

```sh
git -C "$HOME/.local/share/apm/registries/acme" \
  switch -c dplecki/august-hotfix

apr release 2026.8.1 \
  --registry acme \
  --stage august-hotfix \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry

apr stage list --registry acme
apr --json stage show august-hotfix --registry acme
```

A new stage starts at revision `1`. Record the revision returned by
`apr stage show`; an update with `--stage-revision N` creates revision `N + 1`.
Resume that exact observed revision after an interrupted upload, retaining the
same destination and signing inputs:

```sh
apr release 2026.8.1 \
  --registry acme \
  --stage august-hotfix --stage-revision "$REVISION" --resume \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

A stage records the selected candidate, its prepared signed commit, withheld
publication pointers, and immutable inventory. Moving the workspace head does
not change a resumed candidate. Inspect the inventory and current revision before finalizing:

```sh
apr release 2026.8.1 \
  --registry acme \
  --from-stage august-hotfix --stage-revision "$REVISION" \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

Staging and finalization publish a release only. Both `--stage` and
`--from-stage` reject channel convenience flags. After the first release is
published, initialize its channel explicitly and upload the resulting pointers:

```sh
AUTHORING_BRANCH="$(git -C "$HOME/.local/share/apm/registries/acme" branch --show-current)"
apr channel init stable 2026.8.1 --registry acme --key-id initial
git -C "$HOME/.local/share/apm/registries/acme" switch stable
apr origin upload --registry acme \
  --upload-url s3://acme-packages/registry
git -C "$HOME/.local/share/apm/registries/acme" switch "$AUTHORING_BRANCH"
```

`apr origin upload` deliberately exports the checked-out `HEAD`. Switch to the
registry's default channel (`stable` here) before uploading its pointers, then
restore the maintainer branch. Stage finalization preserves the remote default
`HEAD`; it does not export the live authoring branch as that default.

For an existing channel, use `apr channel advance` as described in
[rollouts](rollouts.md). The direct release workflow without a stage retains
its channel convenience flags.

Default public catalogs and channel partitions keep selecting published
releases while a stage is unfinished. A known object digest, authoring ref,
cache path, or CDN URL may still reveal uploaded candidate bytes. Use storage
access controls when those bytes must be confidential.

Discard a candidate only after checking its revision:

```sh
apr stage discard august-hotfix --registry acme \
  --stage-revision "$REVISION"
```

Discard retains its roots through a minimum 24-hour grace period; shared and
released objects keep their other retention roots. `apr cache gc` honors these
roots while collecting eligible aged stage objects and cache pairs; it retains
stage records and workspaces. A release stage is
independent of a deployment named staging. See
[Release stages](../../registry/release-stages.md) for the state, discovery,
transport, and garbage-collection contracts.

## Publish to a smart Git remote

`apr push` pushes a branch; it does not publish the static cache, channel
files, or every signed tag:

```sh
apr push --registry acme --branch stable
git -C "$HOME/.local/share/apm/registries/acme" \
  push origin refs/tags/2026.8.0
```

A smart Git remote is useful for maintainer collaboration and branch or tag
consumers. A production channel also needs the generated static origin over
HTTP. Maintainer branches hold workspaces; configured channel branch names remain
reserved for the published frontier. Use Git as the authoring remote and `apr release --upload-url ...` for the consumer surface.

## Use focused commands for repair

The release pipeline is composed from commands that remain available for
inspection and recovery:

| Command | Use |
| --- | --- |
| `apr tag VERSION --key-id ID` | Create a signed release tag |
| `apr sign TAG --key-id ID` | Sign a nonrelease maintenance tag; semver release refs are immutable |
| `apr cache generate` | Regenerate or upload the static binary cache |
| `apr origin upload` | Refresh and upload the static Git origin |
| `apr store backfill` | Record closures for older package entries |
| `apr store bless` | Add an accepted realization |
| `apr store revoke` | Revoke an accepted realization |

Use these when the intended result is already clear. For a normal release,
the guarded `apr release` ordering is safer and easier to audit.
