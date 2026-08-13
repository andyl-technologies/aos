# Host a registry

Consumers need two read surfaces:

- the registry origin, containing Git objects, refs, signed releases, and
  optional channel partition files;
- one or more binary caches, containing narinfo and NAR files.

They may share one URL and storage prefix. Upload credentials are a producer
concern; consumers verify signed registry state even when the read surface is
public.

`--upload-url` names where `apr` writes. `--cache-url` names the public URL
committed into `registry.toml` for consumers. These differ whenever the write
path is S3, SFTP, a local document root, or an AOS Hub upload endpoint.

## Choose a topology

| Topology | Producer URL | Consumer URL | Rollout channels |
| --- | --- | --- | --- |
| Shared filesystem | Git push plus `file:///srv/aos/acme-cache` | `file:///srv/aos/acme.git` | No; use branch, tag, or version tracking |
| Static web server | `file:///srv/www/acme` or HTTP PUT | `https://packages.example.com/acme/` | Yes |
| Object storage and CDN | `s3://bucket/acme` | CDN HTTPS origin | Yes |
| SFTP deployment | `sftp://deploy@host/srv/www/acme` | HTTPS web origin | Yes |
| Smart Git | Git push / `git+ssh://...` | `git+ssh://...` | No; channels need the static HTTP surface |
| AOS Hub | Hub-provided HTTP upload URL | Hub registry URL | Yes |

## Shared filesystem

For a network mount, removable medium, or single-machine registry, use a bare
SHA-256 Git repository for metadata and a directory for cache objects:

```sh
git init --bare --object-format=sha256 /srv/aos/acme.git
git -C "$HOME/.local/share/apm/registries/acme" \
  remote add origin file:///srv/aos/acme.git

apr release 1.0.0 \
  --registry acme \
  --key-id initial \
  --cache-url file:///srv/aos/acme-cache \
  --upload-url file:///srv/aos/acme-cache

apr push --registry acme --branch stable --set-upstream
git -C "$HOME/.local/share/apm/registries/acme" \
  push origin refs/tags/1.0.0
```

Consumers add the same path with a trust key:

```sh
apm registry add file:///srv/aos/acme.git \
  --name acme \
  --branch stable \
  --trust-key 'acme:Ed25519:BASE64_KEY'
```

The generated upload directory is an HTTP distribution surface, not a bare Git
repository; do not point a `file://` consumer at it. Filesystem Git origins
support branch, tag, version, and default-head tracking. Channel partition
selection is fetched over HTTP and is not available for a `file://` registry.

## Static HTTP from a document root

Upload to the server's document root and serve the result byte-for-byte:

```sh
apr release 1.0.0 \
  --registry acme \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url file:///srv/www/packages/acme
```

The web server must support `GET` and `HEAD`, preserve paths and bytes, and
serve dot-free Git object paths without rewriting them to an application
index. Do not enable directory auto-indexing as a substitute for the generated
`info/refs` files. A TLS-terminating reverse proxy or CDN can sit in front.

Registry sync does not have a general consumer-side HTTP credential flag.
Serve the read surface publicly or restrict it at the network layer. Signatures
and hashes provide authenticity; HTTP access control is not a replacement for
them.

For a generic writable HTTP endpoint, `apr` uses `HEAD` to probe and `PUT` to
write. Supply Basic authentication or headers as needed:

```sh
export AOS_HTTP_PASSWORD='replace-me'
apr origin upload \
  --registry acme \
  --upload-url https://upload.example.com/acme/ \
  --http-user publisher
```

`--header 'Authorization: Bearer ...'` is repeatable. Put credentials in an
environment or secret runner rather than shell history.

## S3-compatible storage and a CDN

The S3 upload URL names a bucket and optional prefix. The public cache URL is
the HTTPS origin or CDN that reads that prefix:

```sh
export AWS_REGION=us-west-2
apr release 2026.8.0 \
  --registry acme \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

Use `--s3-profile` for a named local credentials profile and `--s3-endpoint`
or `S3_ENDPOINT` for an S3-compatible service. The uploader sets cache metadata
appropriate to immutable objects and mutable pointers. Configure the CDN to
honor it; channel and ref files must not receive the same long lifetime as NARs
and content-addressed Git objects.

## SFTP or SSH deployment

SFTP is a write transport to a directory that another service exposes over
HTTPS:

```sh
apr release 2026.8.0 \
  --registry acme \
  --key-id initial \
  --cache-url https://packages.example.com/acme/ \
  --upload-url sftp://deploy@origin.example.com/srv/www/acme \
  --ssh-key /secure/deploy/acme_ed25519
```

`ssh://` is accepted as an alias for the upload backend. Password authentication
uses `AOS_SSH_PASSWORD` or `--ssh-ask-pass`; key authentication is better for
unattended publishers.

## Smart Git

Prefix HTTPS or SSH Git consumer URLs with `git+` so `apm` selects the smart
transport:

```sh
apm registry add git+ssh://git@code.example.com/acme/registry.git \
  --name acme \
  --branch stable \
  --trust-key 'acme:Ed25519:BASE64_KEY'
```

Use `apr push` for branches and Git for signed tag refs. Smart Git does not
serve the channel partition files or the binary cache. Host those separately,
or publish a complete static HTTPS origin for production consumers.

## AOS Hub

Create or select a registry in the Hub, attach a complete storage placement,
scan it, and promote it to write authority. Obtain a short-lived token with
`publish` access to the registry. The Hub accepts one complete APR surface as
an atomic publication: content-addressed payloads are written before mutable
refs, and refs become visible only after every required placement verifies the
declared bytes.

Stage the release locally first. A filesystem destination contains the Git
origin, image objects, and binary-cache objects in the exact paths consumers
will request:

```sh
publication_root="$(mktemp -d)"

apr release 2026.8.0 \
  --registry acme \
  --key-id initial \
  --cache-url https://hub.example.com/acme/cdn/ \
  --upload-url "file://${publication_root}"
```

Then upload that surface through the Hub's placement-aware transaction:

```sh
export AOS_HUB=https://hub.example.com
export AOS_TOKEN='<short-lived access token>'

aos hub registry publish upload acme/cdn \
  --root "${publication_root}"
```

The CLI inventories regular files beneath the root, rejects symlinks and
non-machine paths, hashes every object, derives the immutable generation from
the complete canonical object manifest, and binds the transaction to the
current ready publication. For a separately reviewed or externally generated
inventory, pass
`--manifest publication.json`; every declared size and digest is still checked
against the local file before upload.

Use the exact public URL reported by your Hub; deployment prefixes can differ.
The local staging directory may be removed after the publication reports
`ready`.

Continue with [Operate AOS Hub](../aos-hub/) for native and Worker deployment,
storage bindings, IAM, backup, and monitoring.

## Persist non-secret producer defaults

After the registry has a consumer configuration, save destinations and backend
settings with `apr origin config`:

```sh
apr origin config \
  --registry acme \
  --upload-url s3://acme-packages/registry \
  --s3-region us-west-2 \
  --s3-profile registry-prod

apr origin config --registry acme
```

`apr release`, `apr cache generate`, and `apr origin upload` use the saved
upload URLs when no `--upload-url` is passed. CLI flags and environment values
override saved settings. Although token and password fields can be stored, do
not persist long-lived plaintext credentials; use environment injection or a
short-lived token.

Clear a field explicitly:

```sh
apr origin config --registry acme --unset s3-profile
apr origin config --registry acme --unset upload-urls
```

Repeat `--upload-url` to publish to mirrors. Immutable files go to every
destination before mutable pointers are updated. Treat a partial mirror failure
as an incomplete release and repair it before advancing a channel further.
