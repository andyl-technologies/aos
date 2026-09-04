# Configure package registries

An AOS registry is a package catalog, signed history, and one or more binary
caches. A registry tells APM which package and system-image realizations are
authorized; a cache or AOS Hub transports their bytes.

This guide is for people configuring registries on an AOS host. Registry
maintainers should use [Operate an AOS package registry](../registry/README.md).
Package runtime confinement is a separate control described in [Understand the
package sandbox](package-sandbox.md).

## Start with the built-in registry

AOS images seed the public `andyl` registry at
`https://cdn.aos.andyl.org/`. Its URL, stable channel, priority, bootstrap
cache endpoints, and Ed25519 trust anchor are part of the read-only image under
`/etc/apm`.

On Secure Boot plus dm-verity images, the firmware verifies the signed UKI, the
UKI authenticates the dm-verity root hash, and dm-verity authenticates the root
containing that registry key. This makes the baked key an authenticated first-
contact anchor rather than trust obtained from the registry itself. See [Use
Secure Boot and verify package trust](secure-boot.md) for the complete chain.

Inspect the configured registries before installing packages:

```sh
apm registry list
apm update --system --registry andyl
apm search curl --system --registry andyl
apm show curl --system --registry andyl
```

The public golden image remains an early preview. Verify the registry URL and
key fingerprint against the release record for the exact image being used.

## Distinguish access from trust

Several controls protect different boundaries:

| Control | What it establishes |
| --- | --- |
| HTTPS and certificate validation | The client reached the expected transport endpoint without an ordinary network interception |
| Hub token or registry credential | The caller may read or administer a private service |
| Registry signing key | The selected registry history and catalog were authorized by that registry owner |
| TUF metadata | Role separation, signed release metadata, and freshness for moving release selections |
| Store realization graph | The exact NAR identity and closure relationships authorized by the signed release |
| Narinfo signature | Authorization for stock Nix substitution through the cache protocol |
| Package sandbox | What an activated exposed service may do after installation |

A valid TLS connection or bearer token does not make package content trusted.
A valid registry signature authenticates an owner and exact bytes; it does not
prove that the program is benign. Keep signature verification and package
policy enabled even for an internal HTTPS service.

In the current preview, the implemented TUF path assigns its top-level roles to
the active registry keys. Canonical production publication remains gated on a
separately bootstrapped, threshold-authenticated TUF root and role-separated
online and offline keys. Do not infer production TUF role isolation merely
because `tuf/` metadata is present.

## Add another public registry

Obtain the registry's public trust line through a channel independent of the
registry endpoint. Confirm its fingerprint with the registry owner before the
first synchronization:

```sh
apm registry --system add https://packages.example.com/acme/ \
  --name acme \
  --priority 100 \
  --trust-key 'acme:Ed25519:BASE64_KEY'

apm update --system --registry acme
apm show acme-agent --system --registry acme
```

Do not download the key from an unauthenticated registry URL and then use it to
authenticate that same response. That is circular trust. Suitable independent
channels include a signed organizational configuration, an image release
record, an authenticated administrator channel, or an in-person fingerprint
exchange.

Signature verification fails closed by default. `--no-verify` exists for an
isolated local development registry and must not appear in an installation,
upgrade, or fleet configuration.

## Configure an internal registry

For a fleet, declare the internal registry in the image or in authenticated
`host.nix` rather than configuring every machine interactively:

```nix
{
  aos.apm.registries.acme = {
    url = "https://packages.acme.example/production/";
    channel = "stable";
    priority = 900;
    required = true;
    trustKeys = [
      "acme:Ed25519:BASE64_CURRENT_KEY"
      "acme:Ed25519:BASE64_NEXT_KEY"
    ];
    caches = [
      {
        url = "https://cache.acme.example/";
        priority = 100;
      }
    ];
  };
}
```

An image definition writes this seed under `/etc/apm`. Authenticated runtime
configuration can place the corresponding effective policy in the writable
system overlay. Multiple keys support a planned rotation overlap; they are
public material, not signing secrets.

An internal AOS Hub can serve the registry and cache. The preferred production
boundary keeps registry, cache, TUF, and Secure Boot private signing keys
outside it. Hub-hosted signing is an explicit lower-assurance choice that makes
the Hub part of the signing boundary. See [Trust an internal AOS Hub
deployment](../aos-hub/trust.md).

## Understand configuration scope and precedence

Registry configuration is layered:

| Path | Scope |
| --- | --- |
| `/etc/apm` | Read-only definitions and trust seeds supplied by the image |
| `/var/lib/apm/config` | Writable machine-wide overlay |
| `~/.config/apm` | Writable configuration for the current user |

Use `apm registry --system ...` for machine-wide packages, configuration
generations, and image upgrades. A user-scope registry does not configure those
operations. Stock images do not yet provision all storage needed for
unprivileged user-profile mutation; see [AOS support status](support-status.md).

A higher-precedence definition can disable a registry baked into `/etc/apm`.
Removing the seed itself requires an image rebuild, while authenticated
`host.nix` can deliberately render an empty or disabled system overlay. Treat
such a change as a trust-policy mutation and retain a recovery path.

## Use priorities deliberately

Higher numeric priority wins. Resolution chooses the highest-priority registry
containing a package name before comparing versions in lower-priority
registries. Therefore an internal registry containing `openssl` overrides the
built-in registry's `openssl`, even when the public catalog has a newer
version.

Inspect resolution before relying on an override:

```sh
apm registry list
apm policy openssl --system
apm show openssl --system --registry acme
apm show openssl --system --registry andyl
```

Use unique names for unrelated internal packages. Reuse a public package name
only when the internal catalog intentionally owns the override and its ABI and
update policy are compatible with all consumers.

An explicit selection is stronger than priority and keeps dependency
resolution within the selected registry:

```sh
apm search acme-agent --system --registry acme
apm install acme-agent --registry acme --dry-run
```

For machine-wide ordinary packages, use the desired-state workflow in [Manage
packages with APM](packages.md). The direct
`apm install PACKAGE --system --registry ...` form is reserved for a package
marked as the system sysroot.

## Understand registry verification

On synchronization, APM starts from the pinned key set, verifies the selected
signed history, enforces name binding and continuity, and accepts in-band key
roster changes only after the old trust has authenticated them. Moving release
selection also uses signed TUF metadata where present, plus stored freshness
and anti-rollback state.

After selecting a package, APM walks the signed `store/` realization graph.
Every Nix closure member must match the blessed NAR hash and size before import.
The Hub and cache may choose where bytes are served from, but they cannot
choose different accepted bytes without detection.

A narinfo may also carry a cache-role Ed25519 signature. Stock Nix uses that
signature as its substitution authority. APM's normal package admission remains
rooted in the registry release and complete realization graph; do not weaken
that validation merely because a cache is signed.

## Inspect a package before activation

Registry verification establishes origin and exact content. Inspect the
service privilege contract separately:

```sh
apm show acme-agent --system --registry acme
apm info acme-agent --system --permissions
apm policy acme-agent --system
```

Review the selected registry as well as the computed confinement label. A
trusted internal registry can publish a package whose declared privileges make
it `unconfined`; cryptographic trust does not override local package policy.

## Handle private registries

Private registries add access control but use the same content-verification
model. Supply the documented Hub or transport credential without placing it in
the image, repository, Nix store, registry metadata, or shell history. Prefer
short-lived, registry-scoped tokens delivered through the deployment's secret
manager.

Use HTTPS whenever a bearer token is present. A token should identify the
registry and permitted operation; a credential for one internal registry
should not authorize another registry or production administration.

## Rotate and revoke trust

A planned registry-key rotation begins with a release authenticated by an old
trusted key whose signed roster contains both old and new public keys. After
that overlap has reached the fleet, a surviving key can authenticate retirement
of the old key. Image-baked anchors may retain the old public key temporarily;
the verified in-band roster masks a retired key until a later image removes it.

If the only trusted registry key is compromised, no safe in-band self-
revocation exists. Stop synchronization and package rollout, obtain a new
anchor independently, and distribute it through a newly trusted image or an
authenticated operator procedure. Do not accept rewritten history or disable
verification to recover connectivity.

Disable a registry without deleting its cached state:

```sh
apm registry --system disable acme
apm registry --system enable acme
```

Removing an internal override can immediately change which registry owns a
package name. Review `apm policy`, ABI compatibility, active generations, and
the sysroot lock before making that transition.

## Diagnose verification failures

When synchronization fails, preserve the current accepted state and check:

```sh
apm registry list
apm update --system --registry acme
```

Then determine whether the failure is transport authentication, TLS, an unknown
or retired registry key, non-fast-forward history, stale TUF metadata, a
missing store-graph member, or a NAR mismatch. Do not use `--no-verify` to turn
an unexplained production failure into a successful update.

See [Troubleshoot an AOS host](troubleshooting.md#apm-cannot-verify-a-registry)
and, for registry-owner actions, [Manage registry trust and
incidents](../registry/trust.md).
