# Automate registry releases

Registry automation should make the same guarded transitions an operator makes
manually. It must not turn a mutable build directory or an unreviewed package
set directly into the production channel.

The normal pipeline has four separately observable stages:

1. build and test the package;
2. publish signed package metadata;
3. create and upload an immutable registry release;
4. advance a bounded set of channel partitions.

Keep one logical publisher for each registry. The local authoring clone has a
release lock, but publishers on different machines can still race over remote
branches, tags, and channel pointers.

## Supply credentials

Automation can require three independent credentials:

| Credential | Purpose |
| --- | --- |
| OpenSSH Ed25519 key | Signs registry commits, tags, and channel pointers |
| Nix cache signing key | Signs `.narinfo` records when `--cache-key` is used |
| Upload credential | Writes the generated static origin and NAR objects |

Do not combine these keys merely because one job uses all three. Grant the
upload identity write access only to the intended registry prefix. Keep
long-lived signing keys in a hardware-backed or external signing system when
possible.

Register an external signing command once in the authoring clone:

```sh
apr keys register release \
  --registry acme \
  --key-command 'secret-tool lookup service aos-registry key release'
```

The command is stored in local registry configuration and executed through a
shell. Store only the lookup instruction there, never the private key or a
secret embedded in its arguments. The command must write one OpenSSH private
key to standard output and no other text.

Provider upload credentials should come from the CI secret store or workload
identity. Do not pass them as command-line arguments, where they may appear in
process listings or job logs.

## Build an immutable input

Run the build and tests from a reviewed commit, then retain the exact store
path that passed:

```sh
set -eu

PACKAGE=acme-health-agent
STORE_PATH="$(nix build ".#pkg-$PACKAGE" \
  --no-link --print-out-paths)"

nix run . -- test eval
test -n "$STORE_PATH"
printf '%s\n' "$STORE_PATH"
```

Do not rebuild from a moving branch in a later release stage. Pass the store
path or an immutable build identifier forward through the CI system.

## Preview the release

Publish the package metadata, verify the authoring state, and preview the
release plan:

```sh
apr publish "$STORE_PATH" \
  --registry acme \
  --description "Acme host health agent" \
  --license Apache-2.0 \
  --maintainer packages@example.com \
  --key-id release

apr verify --registry acme
apr store verify --registry acme --deep

apr release "$RELEASE_VERSION" \
  --registry acme \
  --key-id release \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry \
  --dry-run
```

The release version identifies a snapshot of the complete registry. Allocate
it before the job begins and make retries reuse the same value. A positional
release version has no `v` prefix.

Treat a changed dry-run plan as a reason to stop. It can indicate that another
publisher changed the authoring clone, a package closure moved, or a retry is
not operating on the same release state.

## Publish the release

After an approval or policy gate, execute the same release without
`--dry-run`:

```sh
apr release "$RELEASE_VERSION" \
  --registry acme \
  --key-id release \
  --cache-key "$CACHE_SIGNING_KEY_FILE" \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry

apr validate --registry acme --jobs 32
```

`CACHE_SIGNING_KEY_FILE` names a protected file whose contents use Nix's
`name:base64-secret` format. If the job is interrupted, inspect the authoring
state and public origin before using `--resume`; resume only when the immutable
artifacts still match the intended release.

The release pipeline uploads immutable objects before mutable pointers. A
successful command does not replace an external availability probe. Read the
public release and a representative NAR through the same hostname consumers
use before advancing a channel.

## Advance a canary ring

For later releases, move a bounded number of partitions:

```sh
apr channel advance stable "$RELEASE_VERSION" \
  --registry acme \
  --count 8 \
  --key-id release

apr origin upload \
  --registry acme \
  --upload-url s3://acme-packages/registry

apr --json channel status stable --registry acme
```

The standalone advance changes the local static surface; `origin upload` is
required before consumers can observe it. `--count 8` advances eight
additional partitions, so blindly retrying the pair can expand a rollout.
Record the channel map before and after each step and make the automation
decide whether the requested ring already moved.

Use explicit partitions when a stable set of canary hosts is required:

```sh
apr channel advance stable "$RELEASE_VERSION" \
  --registry acme \
  --partitions 0x00,0x10,0x20,0x30 \
  --key-id release
apr origin upload --registry acme \
  --upload-url s3://acme-packages/registry
```

## Gate later rings

Between rings, evaluate host and application signals for the partitions that
actually received the release. At minimum, check:

- package installation and activation success;
- failed systemd units and service-specific health;
- crash, error-rate, and latency changes;
- registry, cache, and download failures;
- the public channel map and release signature.

Advance the next ring only from an explicit deployment record containing the
registry, release, channel, current map, requested change, and observations.
Use `apr --json` and `aos --json hub ...` output as machine inputs rather than
parsing tables.

`apr` does not provide a wall-clock scheduler or a distributed publisher lock.
Those belong in the release controller. The controller must serialize writers
and must not schedule `channel advance` without the matching upload and public
verification steps.

## Stop or recover a rollout

Channel movement is monotonic. To stop a bad release:

1. stop all scheduled advances;
2. retain the before-and-after channel maps;
3. identify affected partitions and hosts;
4. publish a corrected package in a higher registry release;
5. advance affected partitions to that release;
6. revoke or remove the bad realization where incident policy requires it.

Do not point partitions backward. Consumers retain a monotonic release floor
and reject rollback. Follow [Manage registry trust and incidents](trust.md)
when a signing key or published realization is compromised.
