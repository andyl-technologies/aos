# Operate Terrane

Terrane stores immutable content and signed, branchable filesystem snapshots.
The local CLI initializes a file bucket, commits directories, forks and merges
branches, compares authorized metadata, audits entry provenance and committed
history, and checks out
pinned snapshots through the SDK surface.

- [Use a local repository](local-repository.md)
- [Initialize host quota partitions and start the quota broker](../../../crates/terrane/integration/aos-terrane-integration/README.md)
- [Track RFC implementation and qualification](../../rfcs/0024-terrane/integration/05-implementation-plan.md)

Host administration and local repository initialization are separate operations.
A quota-broker enrollment establishes physical allocation custody; serving a
native cache additionally requires publisher recovery, acknowledged Resume and
validated service composition. The implementation plan records the accepted
milestones and the runtime work still required for warehouse, CI-cache and
sandbox deployments.
