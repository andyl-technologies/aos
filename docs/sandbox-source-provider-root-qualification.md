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

Production enablement needs an explicit provisioning contract for both fixed
trees, including role-local signing keys, trust and route material, peer
execution policy, and protected journal ownership. It also needs a Provider
backend that can acquire and reopen a real protected SourceRoot, a RootMount
manager-control handoff with authoritative presence and absence readback, and
crash tests covering each ambiguous boundary before source-backed Apply can
be admitted. A signed hello, filesystem path, catalog publication, or
Inventory alone cannot substitute for these proofs.
