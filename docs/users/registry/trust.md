# Manage registry trust and incidents

Registry reads are normally public. Security comes from an out-of-band trust
anchor, signed Git history, signed release and channel tags, verified store
realizations, and optional signed narinfo. Upload authentication controls who
can write the serving surface; it does not replace those checks.

These controls authenticate the publisher and exact content; they do not prove
that a package is benign. Runtime confinement is a separate defense-in-depth
control for services activated through a package's `expose` contract, and a
package can declare permissions that weaken or remove that boundary. Review the
confinement model in [Understand the package sandbox](../aos/package-sandbox.md)
in addition to establishing registry trust. Consumer-side registry selection
and bootstrap are documented in [Configure package registries](../aos/registries.md);
this guide owns the producer's key and incident procedures.

## Keep the keys straight

| Credential | Format | Purpose |
| --- | --- | --- |
| Registry maintainer key | OpenSSH Ed25519 private key | Signs commits, releases, channels, and realization changes |
| Registry trust line | `name:Ed25519:BASE64` | Public bootstrap anchor distributed to consumers |
| Nix cache key | `name:base64-secret` | Optionally signs narinfo files |
| Upload credential | S3, SSH, HTTP, or AOS Hub credential | Authorizes writes to storage |
| AOS Hub access token | Short-lived bearer token | Authorizes Hub administration |

Do not reuse the maintainer key as an SSH login key or upload credential. Keep
the Nix cache key separate as well; the formats and verification roles differ.

## Bootstrap trust

Deliver the first public trust line independently of the registry it secures.
The strongest normal path is to bake it into an image:

```nix
{
  aos.apm.registries.acme = {
    url = "https://packages.example.com/acme/";
    trustKeys = ["acme:Ed25519:BASE64_KEY"];
    priority = 900;
    required = true;
  };
}
```

For an existing host, pin the key while adding the registry:

```sh
apm registry --system add https://packages.example.com/acme/ \
  --name acme \
  --priority 900 \
  --trust-key 'acme:Ed25519:BASE64_KEY'
```

Confirm the fingerprint through a second trusted channel before the first
sync. Do not fetch a key from the same unauthenticated origin and treat that as
verification.

After bootstrap, a synchronization accepts a new registry head only when its
commit is signed by a currently trusted key and is a fast-forward from the last
verified history. A verified `keys.toml` roster can then add or revoke trust
keys in band.

`--no-verify` and `required = false` disable this chain. Limit them to
throwaway local development registries.

## Protect producer access

- Keep private maintainer keys outside the registry clone and its static
  publication directory.
- Prefer a secret manager command or a protected absolute key path registered
  with `apr keys register`.
- Give CI a scoped upload credential and only the signing key needed for its
  role.
- Protect the smart Git stable branch and release tags from force pushes.
- Serialize release and channel publishers.
- Record `apr diff`, release plans, public channel state, and Hub audit entries
  with each change.
- Use short-lived Hub upload credentials minted for one registry.

The local registry configuration may store upload passwords and tokens, but
that is a convenience rather than a good production secret boundary. Prefer
environment injection from the job's credential provider.

## Rotate a maintainer key without downtime

Start while the old key is still trusted and available. Generate the successor,
append it to the committed roster, and have the old key sign that commit:

```sh
apr keys generate 2026-q4 \
  --registry acme \
  --add \
  --key-id 2026-q2
apr keys list --registry acme
```

Publish a release signed by the existing key so consumers verify the roster
change and pin both active keys:

```sh
apr release 2026.8.0 \
  --registry acme \
  --key-id 2026-q2 \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

After the overlap has reached the fleet, retire the old key with the survivor:

```sh
apr keys retire 2026-q2 \
  --registry acme \
  --vouched-by 2026-q4 \
  --key-id 2026-q4 \
  --reason "planned rotation"
```

Retirement keeps at least one active survivor and re-signs affected release
and channel tags by default. Publish the updated static origin and a new
release with the survivor:

```sh
apr release 2026.8.1 \
  --registry acme \
  --key-id 2026-q4 \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

When more than one survivor remains, `--vouched-by` is required. Do not use
`--no-resign` unless a reviewed recovery plan will re-sign every item printed
by the command before publication.

For image-baked trust, include both public keys during the overlap. A verified
in-band roster masks a retired key even if an older read-only image anchor
still names it. Remove the old baked anchor in the next normal image once fleet
coverage permits.

## Respond to a compromised maintainer key

Stop publication, revoke its upload and Git credentials, preserve the current
origin and audit logs, and determine the last known-good signed head.

If a different active key was already present and remained secure, use that
survivor to retire the compromised key, inspect the re-sign plan, publish a new
release, and verify the public roster from a clean consumer.

If the compromised key was the only trusted key, there is no safe in-band
self-revocation: an attacker holding that key could authorize the same change.
Distribute a new anchor out of band through a rebuilt image or an independently
authenticated operator procedure, pin it in the writable trust store, and move
consumers to a reviewed known-good history. Treat this as a fleet trust-root
incident, not an ordinary registry release.

Do not force-push a rewritten history into existing consumers and assume the
problem is solved. Fast-forward and monotonic state checks are designed to
reject that ambiguity.

## Remove a bad package version

First decide whether the metadata is merely undesirable or the bytes are
unsafe.

To stop offering one package version in future registry releases:

```sh
apr unpublish acme-agent 2.4.0 \
  --registry acme \
  --key-id release \
  --message "remove acme-agent 2.4.0"
```

Omit the version to remove the package entry entirely. This changes the next
registry snapshot; it does not erase immutable older releases or uninstall an
already deployed package.

If a blessed store realization must no longer verify, revoke it too:

```sh
apr store revoke /nix/store/HASH-acme-agent-2.4.0 \
  --registry acme \
  --key-id release \
  --message "revoke compromised acme-agent realization"
apr store verify --registry acme
```

Then release and upload the correction at a higher registry version. For a
channel rollout, advance affected buckets forward to that release:

```sh
apr release 2026.8.2 \
  --registry acme \
  --key-id release \
  --channel stable \
  --count 256 \
  --cache-url https://packages.example.com/acme/ \
  --upload-url s3://acme-packages/registry
```

Do not delete old release objects or move channel buckets backward. Existing
hosts may need an explicit package or OS upgrade, and incident responders may
need the immutable release for forensics. Publish a fixed package version,
advance to a higher registry release, and verify the deployed state.

`apr validate --fix` can prune metadata whose artifacts are missing from every
advertised cache, but it leaves an uncommitted repair. Review the diff and sign
the resulting commit; do not use it as a substitute for a deliberate
unpublish or realization revocation.
