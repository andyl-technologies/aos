# OCI container registry compatibility

AOS Hub exposes standard OCI Distribution endpoints on an explicitly configured
OCI delivery authority. The control-plane URL shown by `aos hub` is not a
registry fallback. Copy the repository's `distribution_reference` from the Hub
console or `aos hub registry container repository show` and use that exact
authority.

## Rollout gates

OCI capabilities are disabled by default and enabled independently. Native and
Worker deployments use the same variables:

| Capability | Native `serve` flag | Environment / Worker variable |
| --- | --- | --- |
| Pull and discovery | `--oci-pull-enabled` | `HUB_OCI_PULL_ENABLED=true` |
| Push and discovery | `--oci-push-enabled` | `HUB_OCI_PUSH_ENABLED=true` |
| Verified AOS publication | `--oci-verified-publication-enabled` | `HUB_OCI_VERIFIED_PUBLICATION_ENABLED=true` |
| Repository, tag, and retention mutations | `--oci-administration-enabled` | `HUB_OCI_ADMINISTRATION_ENABLED=true` |
| Garbage collection | `--oci-gc-enabled` | `HUB_OCI_GC_ENABLED=true` |

For Worker installs, pass the corresponding flags to `aos-hub worker deploy`
or `install`; the generated Wrangler configuration records every value
explicitly. The checked-in development `wrangler.toml` keeps all five false.

These are server-side gates, not presentation hints. Pull and push are enforced
again at Distribution discovery, token exchange, and the exact manifest, blob,
tag, referrer, or upload handler. Verified publication, administration, and GC
are enforced in the shared Connect service used by native and Worker runtimes,
so a caller cannot bypass a disabled console control by invoking the RPC path
directly. Repository, tag, manifest, provenance, publication, and retention
reads stay available under their normal visibility and authorization rules when
administration is disabled. GC plan, apply, and run-detail/list reads all
require the GC gate.

Push does not require enabling public pull. When push is enabled and pull is
disabled, authenticated `HEAD` probes for manifests and blobs are treated as
push preflights. `GET`, tag listing, and referrer discovery remain unavailable.
This permits Docker-family push clients without granting repository readers a
pull path.

## Public Web browsing

When pull is enabled, a public registry exposes its container catalog on the
same anonymous, no-JavaScript browse surface as packages and system images:

```text
/<organization>/<registry>/-/containers
```

The Containers navigation item lists active repositories and their exact OCI
Distribution references. Repository pages list current tags; tag and manifest
pages expose immutable digests, media types, sizes, and runnable platforms.
Each repository and tag view includes copyable Docker, nerdctl, and AOS pull
commands derived from the server-selected delivery authority.

Private and internal registries retain the normal browse visibility rules and
are never made public by these routes. Publication sessions, retention policy,
garbage collection, and mutation controls remain in the authenticated registry
settings console at `/<organization>/<registry>/-/settings/containers`.

## Docker

```sh
docker login registry.example.com
docker pull registry.example.com/aos:stable
docker image inspect registry.example.com/aos:stable --format '{{json .RepoDigests}}'
docker push registry.example.com/team/example:manual
```

Docker requests a repository-scoped bearer token and verifies the returned
manifest and blob digests. Private registries require Hub credentials with the
matching read or publish permission.

## Podman

```sh
podman login registry.example.com
podman pull registry.example.com/aos:stable
podman image inspect registry.example.com/aos:stable --format '{{.Digest}}'
podman push localhost/example:latest registry.example.com/team/example:manual
```

Keep TLS verification enabled. Configure a trusted private CA through Podman's
normal certificate-directory mechanism rather than using `--tls-verify=false`.

## nerdctl

```sh
nerdctl login registry.example.com
nerdctl pull registry.example.com/aos:stable
nerdctl image inspect registry.example.com/aos:stable
nerdctl push registry.example.com/team/example:manual
```

The selected containerd namespace owns nerdctl's local image state; Hub token,
digest, and authorization behavior is otherwise the same as Docker.

## ORAS

```sh
oras login registry.example.com
oras manifest fetch --descriptor registry.example.com/aos:stable
oras discover registry.example.com/aos@sha256:ROOT_DIGEST
oras pull registry.example.com/aos@sha256:ROOT_DIGEST
```

Use a digest when inspecting release evidence. A mutable manual tag is not a
signed AOS release identity. `oras discover` exposes OCI 1.1 referrers; AOS-aware
verification additionally checks the Hub provenance response and signed release
metadata.

## Client expectations

- The Hub supports `/v2/` discovery, repository-scoped token exchange,
  manifests and indexes, blobs, resumable uploads, tags, and OCI 1.1 referrers.
- Range, conditional, digest, and content-type behavior is identical in native
  and Worker deployments because both use the shared Distribution service.
- Repository names are local to one registry authority. A digest that exists in
  another repository or tenant is not discoverable through this authority.
- Clients must follow the upload `Location` returned by the Hub and must not
  synthesize a control-plane or storage URL.
- Verified AOS publication is a separate Connect transaction after ordinary OCI
  bytes have reached every required placement.

Container administration and garbage collection examples are in the
[OCI GC runbook](../../plans/registry/oci-gc-runbook.md).
