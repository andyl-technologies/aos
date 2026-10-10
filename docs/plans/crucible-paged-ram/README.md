# Crucible paged RAM implementation documents

These documents are informative engineering plans for
[the paged RAM contract](../../rfcs/0021-crucible-paged-ram/README.md).
They separate historical source analysis and delivery work from the normative
logical format, custody, timing, capture, and release requirements.

| Document | Purpose |
| --- | --- |
| [Source inventory](current-state.md) | Historical integration analysis at the explicitly identified source baseline; source paths are not implementation evidence. |
| [Initial implementation sequence](phased-implementation.md) | QEMU-SIM work packages, dependencies, and stop/go evidence. |
| [Profile roadmap](profile-roadmap.md) | Shared foundations, initial QEMU-SIM delivery, and separately gated future gem5/KVM implementations. |
| [Qualification plan](qualification-plan.md) | Profile-specific positive and causal negative cases, ownership, and unavailable evidence. |
| [Requirement inventory](requirement-map.tsv) | Complete unique requirement/owner/profile/case allocation; design references, not executable certification. |
| [Historical validation](historical-design-validation.md) | Original dated document/build results, including failures; no current-source qualification claim. |

QEMU-SIM is the initial implementation target. Its implementation qualification
and CPU/elapsed-time parity remain in progress. gem5 and KVM are proposed
profiles, with no implemented or qualified capability claimed here. All tests
and benchmarks used for this work run locally, with remote builders disabled.
No passing source, format, or component test fills an unexecuted deployment gate.

The related simulation-node contract is a proposed design reviewed at
[revision 9f5015bd](https://github.com/andyl-technologies/aos/blob/9f5015bd5a1813b6c9383f64a81d763882f094c2/docs/rfcs/0025-crucible-node-contract/README.md).
Those pinned coordinates support this plan's terminology; they do not claim
that the proposed node-provider APIs or additional implementations have shipped.
