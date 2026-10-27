# T-FUSE-1 acceptance audit

This audit covers the complete T-FUSE-1 requirement range, FUSE-7 through
FUSE-12. The task is **accepted** at frozen checkpoint
`291e811320bb0fe824b2fc9477f5cd0fc18ebd18`. The strengthened owning gate and
mandatory application-target compilation pass with complete source/artifact
review. The new authenticated native manifest-open scenario closes the earlier
FUSE-11 evidence gap while retaining all eight original guest scenarios.

The normative requirements are in
[the structural-index specification](../../spec/27-surface-fuse.md#the-structural-index).
The owning gate is `checks.terrane.gates.fuse-index-roundtrip`, defined in
[`fuse-index.nix`](../../../../../tests/terrane/gates/fuse-index.nix).

| Requirement | Implementation inspected | Reviewed acceptance evidence |
| --- | --- | --- |
| FUSE-7: compile each distinct root from metadata, without fetching object bodies; cache by root and format version | `structural_index/compiled.rs` constructs `IndexKey` only from checked canonical trees or nodes and the compiled format version. `host_cache/owner/surface_index/scoped.rs` accepts an SDK `PreparedRootRead`, submits its checked metadata to the original physical owner and finishes the same Read before returning. `host_cache/owner/surface_index.rs` stores the derived projection in its separate version/root namespace. | Canonical node and graft compilation cases, including body-free compilation, plus the physical-owner and scoped-disclosure guests. Check actual original-inode reuse and signed-root/domain refusal, rather than accepting a supplied root tag. |
| FUSE-8: binary path lookup and contiguous direct-child iteration without per-entry allocation | `Index::lookup` in `structural_index.rs` performs binary search. `Entry::children` and `Children::next` scan the checked child-index run and borrow entries. Validation rejects forged parent relationships and overlapping or incomplete runs before exposing the reader. | Exact nested-tree, hostile-layout and allocation-counter cases in the retained structural test artifact. Preserve the D-132 child-index layout and check the executed selectors against the frozen source inventory. |
| FUSE-9: read-only mapping after actual immutable, verified sealing | `structural_index/mapping.rs` rejects writable, O_PATH, nonregular, empty and oversized descriptors; measures fs-verity; checks stable size and the expected root; then owns the read-only mapping. `prepare_surface_mapping` duplicates the originally admitted inode and closes current authorization before disclosure. | The sealed-mapping guest and scoped-disclosure guest, including unsealed/wrong-measurement/wrong-root refusal and actual original descriptor custody. A codec roundtrip or decoded seal record alone is insufficient. |
| FUSE-10: separate index capacity and eviction; retain a live exposure lease | `host_cache/owner/surface_index.rs` funds admission under separate index policy. `surface_index/exposure.rs` persists the original index binding before acknowledging an exposure and prevents renewal of a draining generation. `surface_index/eviction.rs` refuses retained receipts and live exposures; draining unlink preserves external custody and charges until independently observed closure. | All four physical-owner scenarios plus exposure-pressure and admission-pressure guests. Require real grace, preserved unrelated obligations, retained-mapping charges, final unmap and exact capacity recovery. Receipt drop, expiry or pathname absence alone does not prove closure. |
| FUSE-11: preserve inline chunk identity or object identity and logical size; resolve manifests at file open | `structural_index/tree.rs` copies typed `ContentRef` and file size without accepting a manifest or content reader. `host_cache/owner/surface_index/scoped.rs` checks the prepared file's commit, root, physical domain, path, typed content and size against the mapped entry before physical pin effects. Actual file preparation remains with the original repository/cache owner. | Exact typed-reference/size roundtrip cases, scoped original sealed-file handoff and the independent authenticated native manifest-open guest. The mapped entry retains only typed identity and logical size; actual CDC ranges resolve during Serve open, after zero content reads during index construction and selection. Original scope refusals precede pin effects. |
| FUSE-12: recursively inline grafts and preserve the governing root | `structural_index/tree.rs` expands each graft occurrence at its full namespace prefix, checks its actual canonical root and ancestor chain, preserves referenced-root properties and distinct overrides, and records the governing root. | Nested and repeated graft cases, absent/misbound graft refusal, maximum-depth refusal and checked property lookup. Equal root hashes at distinct graft occurrences must not merge hard-link inode sets. |

Implementation paths in this table are relative to
`crates/terrane/linux/terrane-linux/src/`.

## Reviewed qualification

The owning gate retains `codec`, `sealed-mapping`, `physical-owner`,
`scoped-disclosure`, `exposure-pressure` and `admission-pressure`, and adds
`manifest-open`. The physical-owner aggregate contains four independent native
scenarios. The complete strengthened gate therefore requires nine native guest
results and the pure codec execution. Native filesystem, device, confinement
and cache-lifetime operations execute only inside those guests. All original
actor, guest and supervisor deadlines and assertions remain unchanged.

The complete gate passes in 724.607 seconds. Its immutable output is
`/nix/store/489v1zzr71kmkslvarcc5x4lnvp4mb98-terrane-gate-fuse-index-roundtrip-0.1.0`.
Review matches every one of the 8,233 immutable source files, all seven exact
prerequisite links, all 82 exact pure selectors, the retained pure-test ELF,
three immutable native images and their seven actual Cargo executables, and
every original native scenario's final witness. All nine independent guests
report PASS and successful Firecracker exit. The codec ELF's SHA-256 is
`db60e02459aa95b443b2a93bdf0e36adc200bee56e32831714c6c88f1130e07d`.
The completed review repeats the source check after inspecting all artifacts.

The independent manifest-open guest also passes in 648.045 seconds. Its actual
configured owner and genuinely signed multi-chunk repository prove zero
manifest and chunk reads during index compilation, mapping and file selection;
exactly one manifest resolution during actual native file open; complete
verified bytes; the original measured fs-verity inode and durable exposure
binding; closing Read before handoff; and warm reuse without another manifest
or chunk read. The retained descriptor remains readable after both consumer
leases release. Review checks all three exact witnesses, original publisher
and quota controls, the actual private read-only namespace and actor deadline,
the source-bound initial-enrollment image and the original surface image.

Mandatory application-target compilation passes in 727.920 seconds, with all
8,233 immutable source files, 190 test executables and 59 packages independently
matched. This is compilation evidence, separate from native execution.

The earlier gate at `32727e80b301da6733fee47fd7298e4384e655f8` passed all six
then-existing prerequisites, 82 pure cases and eight native guests, but lacked
the manifest-open clause. That reviewed checkpoint and its explicit incomplete
audit remain in history. The new proof retains its full scope and establishes
the missing clause rather than treating the earlier aggregate as sufficient.

Acceptance is limited to T-FUSE-1. It does not establish complete FUSE-worker
startup, passthrough, writable exposures, privileged broker registration or the
four-role deployment. Those separate requirements and tasks remain open. Final
T6 qualification still owns the complete integrated trunk regression run.
