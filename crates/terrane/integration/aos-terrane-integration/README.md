# Terrane host administration

`aos-terrane-host` provides explicit host administration and the authenticated,
read-only project-quota broker. It requires Linux project quotas and host-root
administration. Terrane's unprivileged content and publisher roles query the
broker after enrollment.

Create a fresh partition with:

```text
aos-terrane-host initialize --config host.toml --ledger enrollment.toml --roles roles.toml
```

The host configuration uses the `HostConfig` schema in
[`src/host/mod.rs`](src/host/mod.rs). List every allocation class for every
owner, including a separate `administrative-root`. Use finite, distinct nonzero
projects, complete allowed client UIDs, and an explicit configuration epoch.
Both public and private domains need their own allocation roots and projects.

The protected role plan supplies every owner exactly once:

```toml
version = 1

[[owners]]
owner_id = "cache-public"
domain = "public"
publisher_uid = 841
publisher_gid = 841
content_uid = 840
content_gid = 845
cache_state_gid = 844
chunk_seed = [
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
]
```

Choose the actual role identities and immutable CDC seed for the installation.
The publisher and content UIDs must differ and appear in the host configuration's
allowed client UIDs. The cache-state group must exclude the publisher.

Before initialization, create each administrative root as an empty root-owned
mode 0700 directory on the payload filesystem. Every payload root must be absent,
its existing parent root-owned mode 0700, and its project unused. Keep the ledger
and role plan outside all allocation roots. Their existing parents must have
protected root custody. The command creates the SDK's protected `control` child
under each administrative root; callers do not create bucket metadata themselves.

Initialization checks the entire partition before creating its first bucket.
It creates real SDK genesis state and consumes the creator receipts in the same
process, then durably records permanent claims and enrollment intent before
changing project assignments or custody. A failure can leave newly created roots
or incomplete enrollment. Preserve those paths and claims for administrative
recovery; initialization refuses replay.

After success, the administrator can explicitly publish traversal access to the
payload parents, preserving each bucket's final public or private permissions.
Initialization leaves those parents mode 0700. Start the quota broker with:

```text
aos-terrane-host serve --config host.toml --ledger enrollment.toml
```

The broker rechecks the durable claims, current directory identities, final
custody, filesystem and finite quota configuration. Enrollment and broker startup
do not grant full host-tier serving readiness; cache recovery, publisher Resume
and the configured service composition have separate validation requirements.
