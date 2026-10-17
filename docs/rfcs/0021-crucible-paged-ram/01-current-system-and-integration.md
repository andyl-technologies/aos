# 01 - Informative integration context

The contract does not depend on the location or current behavior of particular
source files. The [companion source inventory](../../plans/crucible-paged-ram/current-state.md)
preserves the historical QEMU integration analysis at source revision
`9d8ab78dff67348bbb38e2eda609eca67e413561`. It identifies allocation,
observation, fault, fork, capture, transfer, and supervision integration points;
it is not a claim about the implementation at a later revision.

The [companion implementation plan](../../plans/crucible-paged-ram/README.md)
tracks the initial QEMU-SIM delivery separately from the proposed gem5 and KVM
profiles. The normative logical memory contract is in chapters 02 through 09;
[chapter 14](14-implementation-profiles.md) allocates its obligations to each
implementation and operating mode. No source inventory qualifies a capability.
