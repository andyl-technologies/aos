# RootMount–SourceProvider production qualification

The optional RootMount connector currently supports an authenticated session,
observation of an original pending Acquire, and descriptor-free readback of a
Reserved Inventory. Before it consumes the first cold Inventory, it checks the
complete recovered barrier set against the sole protected Mount journal. Every
barrier must still be a Reserved Inventory with its original canonical signed
request and digest. This check grants no source or Mount Apply authority.

SourceRoot consume remains closed for two concrete reasons:

- The service modules do not provision the role-local protected authority trees
  loaded from `/var/lib/aos/sandbox-mount/source-provider-authority` and
  `/var/lib/aos/source-provider/authority`. The former is only an opt-in
  precondition; Provider's systemd credentials currently install the signed
  catalog locator and manifest, not either authority tree. The fixed loaders
  fail closed if their trees are absent or invalid.
- `ProductionSourceProviderStorageReadbackV1` implements authenticated Storage
  readback only. Its descriptor-bearing and mutating backend methods return
  `Unavailable`, so the production daemon cannot complete an Acquire with a
  `SourceRoot`. Wiring Mount's dormant descriptor-consume methods to this
  route would claim an effect and custody proof the runtime cannot provide.

## External authority file contract

The deployment authority must install the two role-local directories before
enabling `aos.sandbox.mountBroker.sourceProviderSession` or starting
`aos-source-providerd`. AOS does not generate these credentials or copy them
from the Nix store or a shared service credential. Installation and rotation
must preserve the protected format and keep the services stopped until each
complete directory is in place.

| Role | Fixed directory | Local signing keys |
| --- | --- | --- |
| RootMount | `/var/lib/aos/sandbox-mount/source-provider-authority` | `root-mount-hello-signing-key`, `root-mount-record-signing-key` |
| Provider | `/var/lib/aos/source-provider/authority` | `provider-hello-signing-key`, `provider-outcome-signing-key` |

Each directory contains exactly its two local keys plus
`source-provider-manifest`, `source-provider-trust`, and `current-route`; extra
entries are rejected. The directory must be root-owned, have a group ID equal
to the service's effective GID, and have mode `0550`. Each child must be a
root-owned regular file in that same group, mode `0440`, with one link.
Symlinks are rejected.
The manifest is exactly 752 canonical `AOSPSEC1` bytes, the route exactly
224 canonical `AOSPRTE1` bytes, and the trust file a bounded canonical
`AOSPTRS2` record. Each local key is exactly 48 bytes: a nonzero 16-byte key
ID followed by a nonzero 32-byte Ed25519 seed. The four signer references,
trust heads, route, peer identities, and local public keys must agree under
the protected loader's checks. Do not place either role's private keys in the
other role's directory.

The corresponding unit's `ExecStartPre` runs
`--check-source-provider-authority` against only its own fixed directory. A
missing or invalid directory fails unit startup. The daemon reopens and
revalidates the same role files before using a carrier, so the precheck cannot
grant authority or mask replacement between startup stages. Provider's
protected `provider.journal` and Mount's protected `mount.journal` remain
separate from these five-file directories and have their own fixed owners.

The local file check cannot certify the deployment's MAC and capability
policy against socket-file-description delegation or unauthorized subject
nomination. That policy and cross-process peer authentication remain separate
requirements; successful `ExecStartPre` is not a readiness or effect grant.

Production enablement needs an explicit provisioning contract for both fixed
trees, including role-local signing keys, trust and route material, peer
execution policy, and protected journal ownership. It also needs a Provider
backend that can acquire and reopen a real protected SourceRoot, a RootMount
manager-control handoff with authoritative presence and absence readback, and
crash tests covering each ambiguous boundary before source-backed Apply can
be admitted. A signed hello, filesystem path, catalog publication, or
Inventory alone cannot substitute for these proofs.
