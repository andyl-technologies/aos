# T-FUSE-1 acceptance audit

This audit covers the complete T-FUSE-1 requirement range, FUSE-7 through
FUSE-12. The task remains **open**. The owning gate is being qualified from
frozen checkpoint `32727e80b301da6733fee47fd7298e4384e655f8`; a started build
and earlier component results do not establish acceptance.

The normative requirements are in
[the structural-index specification](../../spec/27-surface-fuse.md#the-structural-index).
The owning gate is `checks.terrane.gates.fuse-index-roundtrip`, defined in
[`fuse-index.nix`](../../../../../tests/terrane/gates/fuse-index.nix).

| Requirement | Implementation inspected | Evidence required for acceptance |
| --- | --- | --- |
| FUSE-7: compile each distinct root from metadata, without fetching object bodies; cache by root and format version | `structural_index/compiled.rs` constructs `IndexKey` only from checked canonical trees or nodes and the compiled format version. `host_cache/owner/surface_index/scoped.rs` accepts an SDK `PreparedRootRead`, submits its checked metadata to the original physical owner and finishes the same Read before returning. `host_cache/owner/surface_index.rs` stores the derived projection in its separate version/root namespace. | Canonical node and graft compilation cases, including body-free compilation, plus the physical-owner and scoped-disclosure guests. Check actual original-inode reuse and signed-root/domain refusal, rather than accepting a supplied root tag. |
| FUSE-8: binary path lookup and contiguous direct-child iteration without per-entry allocation | `Index::lookup` in `structural_index.rs` performs binary search. `Entry::children` and `Children::next` scan the checked child-index run and borrow entries. Validation rejects forged parent relationships and overlapping or incomplete runs before exposing the reader. | Exact nested-tree, hostile-layout and allocation-counter cases in the retained structural test artifact. Preserve the D-132 child-index layout and check the executed selectors against the frozen source inventory. |
| FUSE-9: read-only mapping after actual immutable, verified sealing | `structural_index/mapping.rs` rejects writable, O_PATH, nonregular, empty and oversized descriptors; measures fs-verity; checks stable size and the expected root; then owns the read-only mapping. `prepare_surface_mapping` duplicates the originally admitted inode and closes current authorization before disclosure. | The sealed-mapping guest and scoped-disclosure guest, including unsealed/wrong-measurement/wrong-root refusal and actual original descriptor custody. A codec roundtrip or decoded seal record alone is insufficient. |
| FUSE-10: separate index capacity and eviction; retain a live exposure lease | `host_cache/owner/surface_index.rs` funds admission under separate index policy. `surface_index/exposure.rs` persists the original index binding before acknowledging an exposure and prevents renewal of a draining generation. `surface_index/eviction.rs` refuses retained receipts and live exposures; draining unlink preserves external custody and charges until independently observed closure. | All four physical-owner scenarios plus exposure-pressure and admission-pressure guests. Require real grace, preserved unrelated obligations, retained-mapping charges, final unmap and exact capacity recovery. Receipt drop, expiry or pathname absence alone does not prove closure. |
| FUSE-11: preserve inline chunk identity or object identity and logical size; resolve manifests at file open | `structural_index/tree.rs` copies typed `ContentRef` and file size without accepting a manifest or content reader. `host_cache/owner/surface_index/scoped.rs` checks the prepared file's commit, root, physical domain, path, typed content and size against the mapped entry before physical pin effects. Actual file preparation remains with the original repository/cache owner. | Exact typed-reference/size roundtrip cases and scoped original sealed-file handoff. Verify no chunk-range table is substituted into the structural projection and that mismatched scope refuses before pin effects. |
| FUSE-12: recursively inline grafts and preserve the governing root | `structural_index/tree.rs` expands each graft occurrence at its full namespace prefix, checks its actual canonical root and ancestor chain, preserves referenced-root properties and distinct overrides, and records the governing root. | Nested and repeated graft cases, absent/misbound graft refusal, maximum-depth refusal and checked property lookup. Equal root hashes at distinct graft occurrences must not merge hard-link inode sets. |

Implementation paths in this table are relative to
`crates/terrane/linux/terrane-linux/src/`.

## Qualification boundary

The owning gate has six prerequisites: `codec`, `sealed-mapping`,
`physical-owner`, `scoped-disclosure`, `exposure-pressure` and
`admission-pressure`. The physical-owner aggregate contains four independent
native scenarios, so the complete gate requires eight native guest results as
well as the pure codec execution. Native filesystem, device, confinement and
cache-lifetime operations execute only inside those guests. Existing actor and
guest deadlines remain authoritative.

Before acceptance, inspect the terminal gate receipt and its immutable output
links, every actual guest serial result, the original scenario assertions,
retained Cargo artifacts and executable hashes, and all immutable source inputs.
The receipt must bind unchanged before/after tracked source to the exact frozen
checkpoint. Review the implementation and requirement rows above together with
that evidence; a green aggregate or registry entry alone is insufficient.

This task does not establish complete FUSE-worker startup, passthrough, writable
exposures, privileged broker registration or the four-role deployment. Their
separate requirements and open tasks remain in the implementation plan.
