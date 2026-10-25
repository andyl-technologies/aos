# T-FUSE-1 acceptance audit

This audit covers the complete T-FUSE-1 requirement range, FUSE-7 through
FUSE-12. The task remains **open**. The owning gate passes at frozen checkpoint
`32727e80b301da6733fee47fd7298e4384e655f8`, with the complete evidence review
recorded below. FUSE-11 now has a direct manifest-open candidate wired into the owning gate.
Its native qualification and evidence review remain pending; the earlier green
aggregate does not establish that missing clause.

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

The reviewed checkpoint has six prerequisites: `codec`, `sealed-mapping`,
`physical-owner`, `scoped-disclosure`, `exposure-pressure` and
`admission-pressure`. The physical-owner aggregate contains four independent
native scenarios, so the complete gate requires eight native guest results as
well as the pure codec execution. Native filesystem, device, confinement and
cache-lifetime operations execute only inside those guests. Existing actor and
guest deadlines remain authoritative.

The complete gate passes in 1,433.832 seconds. Its immutable output is
`/nix/store/mjzdmcfx0zpcahabnvr2sjvhwpqmnjwv-terrane-gate-fuse-index-roundtrip-0.1.0`.
Review verifies unchanged before/after tracked inputs, every one of the 8,229
immutable source files, all six prerequisite links, all 82 exact pure selectors,
the retained pure-test ELF, both immutable native images and their six actual
Cargo artifacts, and every original native scenario's final witness. All eight
independent guests report PASS and successful Firecracker exit. The codec ELF's
SHA-256 is `50fc69f67a6d17ffe18f2a1b721a472b2dfc128064d93536881536a144339e96`.

The scoped worker's file oracle explicitly accepts inline content and rejects
manifests. Typed manifest identity/size roundtrips establish index storage, but
do not establish FUSE-11's serve-side manifest resolution at file-open time.
The owning gate needs an actual authenticated manifest-file open and original
backing handoff, with the manifest read deferred until that open and no chunk
ranges embedded in the index. That proof must keep the complete existing gate
as prerequisites. Until its native result and source/artifact review pass,
T-FUSE-1 stays open despite the green current aggregate.

The strengthened gate adds `manifest-open` as a seventh prerequisite while
retaining all six original prerequisites and their eight guests. Its independent
`native-configured-manifest-open` guest uses the actual configured physical
owner and a genuinely signed, multi-chunk repository. It requires zero manifest
and chunk reads during index compilation, mapping and file selection; exactly
one manifest resolution at actual native file open; verified complete bytes;
the original measured fs-verity inode and durable exposure binding; closing
Read before handoff; and warm reuse without another manifest or chunk read.
It also reads the retained descriptor after releasing both consumer leases.
The guest retains the original actor, guest and supervisor bounds. This covers
the Serve-side open independently of privileged kernel registration, which
remains a separate outstanding obligation. Strict all-feature/all-target Linux
Clippy, both supervisor AST checks, Nix derivation evaluation and plan ownership
checks pass. Native results, the complete strengthened gate and their full
source/artifact reviews are still pending; no task acceptance changes.

This task does not establish complete FUSE-worker startup, passthrough, writable
exposures, privileged broker registration or the four-role deployment. Their
separate requirements and open tasks remain in the implementation plan.
