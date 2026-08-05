# Stage and schedule updates

A channel divides consumers into 256 stable buckets, `00` through `ff`. Each
bucket points to a signed registry release. A host chooses and persists its
bucket; the publisher chooses which buckets advance.

Channels require the generated static origin to be readable over HTTP or HTTPS.
They are not available from a filesystem-only or smart-Git-only registry.

## Initialize a channel

Initialize all buckets at a known good release while publishing it:

```sh
apr release 2026.8.0 \
  --registry acme \
  --key-id release \
  --channel stable \
  --init-channel \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

Consumers opt into the channel when the registry is configured:

```sh
apm registry add https://packages.example.com/acme/ \
  --name acme \
  --channel stable \
  --trust-key 'acme:Ed25519:BASE64_KEY'
```

The selected bucket and monotonic release floor are durable consumer state.
Refreshing metadata does not randomly move a host between rollout rings.

## Start a staged release

Advance eight buckets in the same ordered publication that creates the next
release:

```sh
apr release 2026.8.1 \
  --registry acme \
  --key-id release \
  --channel stable \
  --count 8 \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

`--count 8` means eight additional lowest-numbered buckets that do not already
point at `2026.8.1`. It does not mean “make the target total eight.” Repeating
the command with another `--count 8` advances eight more.

For named canary rings, select exact buckets in decimal or hexadecimal:

```sh
apr channel advance stable 2026.8.1 \
  --registry acme \
  --partitions 0x00,0x10,0x20,0x30 \
  --key-id release
apr origin upload \
  --registry acme \
  --upload-url s3://acme-packages/registry
```

Exactly one of `--count` and `--partitions` is required for an advance. A
standalone `apr channel advance` changes the local static surface; follow it
with `apr origin upload` so consumers can see the new pointers.

Inspect the map at any point:

```sh
apr channel status stable --registry acme
aos hub registry channel acme/cdn stable \
  --hub https://hub.example.com
```

The Hub command is a read operation against an indexed hosted registry. Use the
local `apr` status as the producer source of truth before upload and the Hub or
public origin as the post-upload view.

## Schedule later rings

`apr` deliberately has no wall-clock scheduler. Use the organization's CI,
release controller, or a systemd timer to run one serialized, audited step:

```sh
apr channel advance stable 2026.8.1 \
  --registry acme \
  --count 24 \
  --key-id release
apr origin upload \
  --registry acme \
  --upload-url s3://acme-packages/registry
apr channel status stable --registry acme
```

An unattended job should:

1. verify the exact target release and current channel map;
2. acquire the organization's single-publisher lock;
3. obtain a short-lived upload credential and signing-key access;
4. advance a bounded number of buckets;
5. upload the static origin;
6. check the public channel map and package health before recording success.

Use JSON output for machine checks and retain it with the deployment record:

```sh
apr --json channel status stable --registry acme
aos --json hub registry channel acme/cdn stable \
  --hub https://hub.example.com
```

Do not schedule `apr channel advance` without the matching upload step. The
local command can succeed while the public registry remains unchanged.

## Complete or stop a rollout

Advance all remaining buckets by asking for up to 256 additional buckets:

```sh
apr channel advance stable 2026.8.1 \
  --registry acme \
  --count 256 \
  --key-id release
apr origin upload --registry acme \
  --upload-url s3://acme-packages/registry
```

Advances are monotonic. Do not point a bucket back to an older release; clients
retain a release floor and reject rollback. To stop a bad rollout, stop
advancing it, publish a corrected release with a higher version, and advance
affected buckets to that release. See [Manage trust and incidents](trust.md)
for removing or revoking the bad package metadata as part of the fix-forward
release.
