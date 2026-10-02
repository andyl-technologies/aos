# Publication fixture environment

The active External publisher preserves the guest's inherited home. Each source
uses its existing private publisher root for `XDG_CONFIG_HOME`, `XDG_DATA_HOME`
and `XDG_CACHE_HOME`. APR resolves these roots through `ProfileScope::User` in
`aos-package/src/types.rs`; registry keys and the actual signed registry stay at
the same existing paths beneath that root.

APR's initial registry commit receives all four command-scoped `GIT_AUTHOR_*`
and `GIT_COMMITTER_*` values supported by `registry_ops/git.rs`. After creation,
the fixture writes the same identity into the actual registry's local Git
configuration and removes those command-scoped overrides. It writes no global
Git configuration and changes neither the guest home nor process user identity.

The ordinary FIFO probe and concurrent publication supervisors select the same
private XDG roots. Their explicit publication surface, registry, Worker origin,
provider-policy file and upload/admission journals retain their existing values.
The sparse interruption helper still privately captures and replays the actual
selected child's complete environment; no synthetic home is substituted.

The focused checks execute the actual environment statements from the selected
guest programs. They verify inherited-home continuity, per-invocation separation,
and the initial identity using AOS-built Git. This is local source/environment
validation, not an executed APR release, SDK effect or five-machine result.
