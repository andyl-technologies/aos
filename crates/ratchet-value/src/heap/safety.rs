//! Unsafe-discipline manifest for the heap and GC surface.
//!
//! Tier A already owns the value-runtime `mmap`/`munmap`, memory-advice, and
//! resident-memory probing boundaries. Later Tier B collector work may need more
//! unsafe machinery for moving objects and stack-map integration. This module
//! pins the standing controls for that surface so new unsafe operations cannot
//! appear in heap sources without an explicit review update.

/// Crate-level lint required for heap and GC unsafe code.
pub const HEAP_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

/// Comment prefix required beside each unsafe operation.
pub const HEAP_SAFETY_COMMENT_PREFIX: &str = "// SAFETY:";

/// Audit tooling required before future unsafe heap or GC code ships.
pub const HEAP_UNSAFE_AUDIT_TOOLS: &[HeapUnsafeAuditTool] = &[
    HeapUnsafeAuditTool::GcFuzzTarget,
    HeapUnsafeAuditTool::Miri,
    HeapUnsafeAuditTool::AddressSanitizer,
    HeapUnsafeAuditTool::UndefinedBehaviorSanitizer,
    HeapUnsafeAuditTool::ThreadSanitizer,
    HeapUnsafeAuditTool::Loom,
];

/// Heap operations that remain innately unsafe after local validation.
pub const HEAP_INNATE_UNSAFE_OPERATIONS: &[HeapInnateUnsafeOperation] = &[
    HeapInnateUnsafeOperation::AnonymousMemoryMapping,
    HeapInnateUnsafeOperation::MemoryAdviceRange,
    HeapInnateUnsafeOperation::ResidentMemoryProbe,
    HeapInnateUnsafeOperation::RegionPopHandoff,
    HeapInnateUnsafeOperation::AllocatorFreeMemoryRelease,
    HeapInnateUnsafeOperation::FlatObjectPayloadAccess,
    HeapInnateUnsafeOperation::ContiguousAddressReservation,
    HeapInnateUnsafeOperation::SharedReservationObjectPublication,
];

/// Required audit tools for heap and GC unsafe code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapUnsafeAuditTool {
    /// A GC-specific fuzz target exercises moving-collector edge cases.
    GcFuzzTarget,
    /// Miri checks undefined behavior on supported safe-tree executions.
    Miri,
    /// AddressSanitizer checks invalid memory accesses on supported targets.
    AddressSanitizer,
    /// UndefinedBehaviorSanitizer checks supported UB classes in native builds.
    UndefinedBehaviorSanitizer,
    /// ThreadSanitizer checks data races in concurrent heap and collector paths.
    ThreadSanitizer,
    /// Loom checks modeled concurrent protocols such as future collector races.
    Loom,
}

/// Heap operations that need explicit unsafe fences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapInnateUnsafeOperation {
    /// Creates and releases anonymous memory mappings for arena chunks.
    AnonymousMemoryMapping,
    /// Builds raw byte ranges for memory-advice syscalls.
    MemoryAdviceRange,
    /// Queries process resident memory through platform-specific libc APIs.
    ResidentMemoryProbe,
    /// Rewinds a region after the caller proves all later heap handles are dead.
    RegionPopHandoff,
    /// Asks the process allocator to return dirty-but-free pages to the OS
    /// (`malloc_trim` on glibc targets).
    AllocatorFreeMemoryRelease,
    /// Writes, reads, and drops flat header-plus-payload heap objects in
    /// place inside store-owned arena chunks (RFC-0007 doc 30 stage FV-1).
    FlatObjectPayloadAccess,
    /// Reserves one contiguous virtual range, derives checked in-range
    /// addresses from compressed offsets, and releases the exact mapping.
    ContiguousAddressReservation,
    /// Places, resolves, and drops immutable shared objects after compact
    /// reservation-index registry publication proves their exact type.
    SharedReservationObjectPublication,
}

/// Standing controls required before unsafe heap or GC code can land.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapUnsafeDiscipline {
    crate_lint: &'static str,
    safety_comment_prefix: &'static str,
    second_reviewer_required: bool,
    audit_tools: &'static [HeapUnsafeAuditTool],
    innate_unsafe_operations: &'static [HeapInnateUnsafeOperation],
}

impl HeapUnsafeDiscipline {
    /// Creates the standing heap unsafe-discipline manifest.
    pub const fn new(
        crate_lint: &'static str,
        safety_comment_prefix: &'static str,
        second_reviewer_required: bool,
        audit_tools: &'static [HeapUnsafeAuditTool],
        innate_unsafe_operations: &'static [HeapInnateUnsafeOperation],
    ) -> Self {
        Self {
            crate_lint,
            safety_comment_prefix,
            second_reviewer_required,
            audit_tools,
            innate_unsafe_operations,
        }
    }

    /// Returns the crate-level lint required by the unsafe fence.
    pub const fn crate_lint(self) -> &'static str {
        self.crate_lint
    }

    /// Returns the required local invariant-comment prefix.
    pub const fn safety_comment_prefix(self) -> &'static str {
        self.safety_comment_prefix
    }

    /// Returns whether a second reviewer is required for new unsafe blocks.
    pub const fn second_reviewer_required(self) -> bool {
        self.second_reviewer_required
    }

    /// Returns required audit tools for future unsafe heap and GC work.
    pub const fn audit_tools(self) -> &'static [HeapUnsafeAuditTool] {
        self.audit_tools
    }

    /// Returns the currently recognized innately unsafe heap operations.
    pub const fn innate_unsafe_operations(self) -> &'static [HeapInnateUnsafeOperation] {
        self.innate_unsafe_operations
    }
}

/// Returns the standing unsafe-discipline manifest for heap and GC code.
pub const fn heap_unsafe_discipline() -> HeapUnsafeDiscipline {
    HeapUnsafeDiscipline::new(
        HEAP_UNSAFE_CRATE_LINT,
        HEAP_SAFETY_COMMENT_PREFIX,
        true,
        HEAP_UNSAFE_AUDIT_TOOLS,
        HEAP_INNATE_UNSAFE_OPERATIONS,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = heap_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), HEAP_UNSAFE_CRATE_LINT);
        assert_eq!(
            discipline.safety_comment_prefix(),
            HEAP_SAFETY_COMMENT_PREFIX
        );
        assert!(discipline.second_reviewer_required());
        assert_eq!(discipline.audit_tools(), HEAP_UNSAFE_AUDIT_TOOLS);
        assert_eq!(
            discipline.innate_unsafe_operations(),
            HEAP_INNATE_UNSAFE_OPERATIONS
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::Miri)
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::AddressSanitizer)
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::UndefinedBehaviorSanitizer)
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::ThreadSanitizer)
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::Loom)
        );
        assert!(
            discipline
                .audit_tools()
                .contains(&HeapUnsafeAuditTool::GcFuzzTarget)
        );
    }

    #[test]
    fn crate_root_declares_unsafe_operation_lint() {
        let crate_root = include_str!("../lib.rs");

        assert!(
            crate_root
                .lines()
                .any(|line| line.trim() == HEAP_UNSAFE_CRATE_LINT)
        );
    }

    #[test]
    fn current_heap_sources_keep_unsafe_boundaries_allowlisted() {
        let heap_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("heap");
        let mut findings = Vec::new();

        for source_path in rust_sources(&heap_root) {
            let relative_path = source_path
                .strip_prefix(&heap_root)
                .expect("heap source is below heap root");
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            for (line_number, line) in source.lines().enumerate() {
                let code = code_without_line_comments_or_ordinary_strings(line);
                for token in code_tokens(&code) {
                    if !matches!(token, "unsafe" | "extern" | "transmute") {
                        continue;
                    }

                    if !is_allowed_heap_unsafe_file(relative_path, token) {
                        findings.push(format!(
                            "{}:{} contains `{token}`",
                            source_path.display(),
                            line_number + 1
                        ));
                        continue;
                    }

                    if token != "unsafe" {
                        continue;
                    }

                    if unsafe_token_occurrences(&code) > 1 {
                        findings.push(format!(
                            "{}:{} contains multiple unsafe operations on one line",
                            source_path.display(),
                            line_number + 1
                        ));
                        continue;
                    }

                    if unsafe_operation_line_kind(&code).is_none() {
                        findings.push(format!(
                            "{}:{} contains unclassified unsafe token",
                            source_path.display(),
                            line_number + 1
                        ));
                    }
                }
            }
        }

        assert!(
            findings.is_empty(),
            "heap sources contain unreviewed unsafe-boundary tokens:\n{}",
            findings.join("\n")
        );
    }

    #[test]
    fn reviewed_heap_unsafe_lines_keep_safety_comments_and_counts() {
        let heap_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("heap");

        // resident.rs count 4 -> 6: the `getrusage` peak resident-memory probe
        // added one `unsafe` libc call plus one `assume_init` on its output,
        // both under the reviewed `ResidentMemoryProbe` innate operation.
        // advice.rs count 12 -> 13: the glibc `malloc_trim(0)` call under the
        // reviewed `AllocatorFreeMemoryRelease` innate operation.
        // arena.rs count 12 -> 13 (doc 30 unsafe-placement enforcement): the
        // safe cross-crate region-pop handoff delegates to the sealed unsafe
        // rewind after the owning runtime invalidates its typed side table;
        // opaque arena handles carry no Rust references across the handoff.
        // flat.rs count 0 -> 5 (RFC-0007 doc 30 stage FV-1): the flat-object
        // store's sealed in-place operations under the reviewed
        // `FlatObjectPayloadAccess` innate operation — one placement write
        // (`alloc`), one header-word read (`kind_at`), two shared-reference
        // constructions over validated objects (`resolve`, `iter`), and one
        // `drop_in_place` sweep in `Drop`.
        // flat.rs count 5 -> 8 (doc 30 FV-1 lists + FV-1b bytes-inline): the
        // trailing-bytes allocation's inline byte copy and placement write
        // (`alloc_with_trailing_bytes`), plus the exclusive payload
        // reconstruction behind `&mut self` (`resolve_mut`, the collector
        // writeback door), all under `FlatObjectPayloadAccess`.
        // flat/bytes.rs count 0 -> 3 (doc 30 FV-1b): the `FlatBytes` inline
        // byte witness — one `from_raw_parts` read over the sealed
        // construction contract (`as_slice`) and the `Send`/`Sync` impls
        // justified by post-construction immutability, all under
        // `FlatObjectPayloadAccess`.
        // flat.rs count 8 -> 11 (doc 30 FV-3 worker-domain pops): the
        // lexical-region pop (`pop_region`) — one `drop_in_place` over each
        // popped object (registry-truncated so it cannot be revisited), one
        // header kind-word wipe making stale resolutions fail the magic check
        // loudly, and the owned-arena rewind call whose reachability proof is
        // the evaluator's retained-edge validation, all under
        // `FlatObjectPayloadAccess`.
        // flat.rs count 11 -> 12 (doc 30 FV-4 inline arrays): the
        // trailing-array allocation's placement write
        // (`alloc_with_trailing`), the typed analog of
        // `alloc_with_trailing_bytes`'s object-head write, under
        // `FlatObjectPayloadAccess`.
        // flat.rs count 12 -> 8 + flat/alloc.rs count 0 -> 4 (doc 30 FV-4,
        // module-size split): the four allocation-door operations (the plain
        // and trailing-array object-head placement writes, and the
        // trailing-bytes inline copy plus its object-head write) moved
        // verbatim into `flat/alloc.rs`; resolution, iteration, pops, and
        // drop stay in `flat.rs`. No operation was added or changed.
        // flat.rs count 8 -> 9 (B2 structural writeback): the exclusive
        // header reconstruction behind `&mut self` repairs the staged
        // structural-hash word after collector payload relocation, under the
        // existing `FlatObjectPayloadAccess` operation.
        // flat.rs count 9 -> 6 + flat/region_ops.rs count 0 -> 3 (doc 30 FV-4
        // dual-ended reservation): the existing drop, header wipe, and sealed
        // rewind operations moved verbatim with lexical-region methods. No
        // unsafe operation was added or changed.
        // flat/slice.rs count 0 -> 5 (doc 30 FV-4): the `FlatSlice` inline
        // element witness — one `from_raw_parts` read over the sealed
        // construction contract (`as_slice`), the `Send`/`Sync` impls
        // justified by post-construction immutability (the `FlatBytes`
        // pattern), and the tail writer's bounds-checked
        // `copy_nonoverlapping` plus in-allocation cursor advance
        // (`write_slice`), all under `FlatObjectPayloadAccess`.
        // flat/value_tail.rs count 0 -> 3 (doc 30 FV-5): one shared object
        // reference reconstructed from an exact live registry entry, one
        // shared `Value` slice reconstructed after the private tail flag,
        // header length, and reservation extent validate the initialized run,
        // and one exclusive object/tail block behind `&mut self`, all under
        // `FlatObjectPayloadAccess`.
        // reservation.rs count 0 -> 7 (doc 30 Candidate-C substrate): one
        // anonymous 4-GiB mapping, one defensive unmap for a null successful
        // mapping, two checked in-range address derivations (allocation and
        // compressed-index decode), the exact-range drop unmap, and the
        // mapping owner's Send/Sync contracts, all under the reviewed
        // `ContiguousAddressReservation` operation.
        // flat/shared.rs count 0 -> 3 (doc 30 Candidate-C shared adoption):
        // object placement, exact-slot typed resolution, and payload
        // destruction before unmapping are one reviewed lifecycle operation,
        // all under
        // `SharedReservationObjectPublication`.
        for (file_name, expected_count) in [
            ("advice.rs", 13usize),
            ("arena.rs", 13usize),
            ("flat.rs", 6usize),
            ("flat/alloc.rs", 4usize),
            ("flat/bytes.rs", 3usize),
            ("flat/region_ops.rs", 3usize),
            ("flat/slice.rs", 5usize),
            ("flat/shared.rs", 3usize),
            ("flat/value_tail.rs", 3usize),
            ("resident.rs", 6usize),
            ("reservation.rs", 7usize),
        ] {
            let source_path = heap_root.join(file_name);
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            let lines = source.lines().collect::<Vec<_>>();
            let mut unsafe_lines = 0usize;

            for (line_number, line) in lines.iter().enumerate() {
                let code = code_without_line_comments_or_ordinary_strings(line);
                let unsafe_tokens = unsafe_token_occurrences(&code);
                if unsafe_tokens == 0 {
                    continue;
                }
                assert_eq!(
                    unsafe_tokens,
                    1,
                    "{}:{} contains multiple unsafe operations on one line",
                    source_path.display(),
                    line_number + 1
                );
                let Some(kind) = unsafe_operation_line_kind(&code) else {
                    continue;
                };
                unsafe_lines = unsafe_lines.saturating_add(unsafe_tokens);
                match kind {
                    UnsafeOperationLineKind::UnsafeFn => assert!(
                        preceding_doc_block_contains(&lines, line_number, "# Safety"),
                        "{}:{} unsafe fn is missing nearby # Safety docs",
                        source_path.display(),
                        line_number + 1
                    ),
                    UnsafeOperationLineKind::UnsafeBlock | UnsafeOperationLineKind::UnsafeImpl => {
                        assert!(
                            preceding_safety_comment_binds(&lines, line_number),
                            "{}:{} unsafe operation is missing nearby SAFETY comment",
                            source_path.display(),
                            line_number + 1
                        );
                    }
                }
            }

            assert_eq!(
                unsafe_lines, expected_count,
                "{file_name} unsafe operation count changed; update the heap safety review"
            );
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum UnsafeOperationLineKind {
        UnsafeFn,
        UnsafeBlock,
        UnsafeImpl,
    }

    fn is_allowed_heap_unsafe_file(relative_path: &Path, token: &str) -> bool {
        if matches!(token, "extern" | "transmute") {
            return false;
        }

        matches!(
            relative_path.to_str(),
            Some(
                "advice.rs"
                    | "arena.rs"
                    | "flat.rs"
                    | "flat/alloc.rs"
                    | "flat/bytes.rs"
                    | "flat/region_ops.rs"
                    | "flat/slice.rs"
                    | "flat/shared.rs"
                    | "flat/value_tail.rs"
                    | "reservation.rs"
                    | "resident.rs"
            )
        )
    }

    fn unsafe_operation_line_kind(code: &str) -> Option<UnsafeOperationLineKind> {
        let trimmed = code.trim_start();
        if trimmed.starts_with("unsafe fn")
            || (trimmed.starts_with("pub") && trimmed.contains("unsafe fn"))
        {
            return Some(UnsafeOperationLineKind::UnsafeFn);
        }
        if trimmed.starts_with("unsafe impl") {
            return Some(UnsafeOperationLineKind::UnsafeImpl);
        }
        if trimmed.contains("unsafe {") {
            return Some(UnsafeOperationLineKind::UnsafeBlock);
        }
        None
    }

    fn rust_sources(root: &Path) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        collect_rust_sources(root, &mut sources);
        sources.sort();
        sources
    }

    fn collect_rust_sources(path: &Path, sources: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("source directory is readable") {
                collect_rust_sources(&entry.expect("source entry is readable").path(), sources);
            }
            return;
        }

        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path.to_path_buf());
        }
    }

    fn code_without_line_comments_or_ordinary_strings(line: &str) -> String {
        let mut code = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        let mut escaped = false;

        while let Some(ch) = chars.next() {
            if !in_string && ch == '/' && chars.peek() == Some(&'/') {
                break;
            }

            if ch == '"' && !escaped {
                in_string = !in_string;
                code.push(' ');
            } else if in_string {
                code.push(' ');
            } else {
                code.push(ch);
            }

            escaped = ch == '\\' && !escaped;
            if ch != '\\' {
                escaped = false;
            }
        }

        code
    }

    fn code_tokens(code: &str) -> impl Iterator<Item = &str> {
        code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|token| !token.is_empty())
    }

    fn unsafe_token_occurrences(code: &str) -> usize {
        code_tokens(code).filter(|token| *token == "unsafe").count()
    }

    fn preceding_doc_block_contains(lines: &[&str], line_number: usize, needle: &str) -> bool {
        let mut index = line_number;
        while index > 0 {
            index -= 1;
            let trimmed = lines[index].trim_start();
            if trimmed.starts_with("///") {
                if trimmed.contains(needle) {
                    return true;
                }
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            break;
        }
        false
    }

    fn preceding_safety_comment_binds(lines: &[&str], line_number: usize) -> bool {
        let mut index = line_number;
        let mut saw_comment = false;
        let mut saw_safety = false;
        while index > 0 {
            index -= 1;
            let trimmed = lines[index].trim_start();
            if trimmed.starts_with("#[") {
                if saw_comment {
                    return saw_safety;
                }
                continue;
            }
            if trimmed.starts_with("//") {
                saw_comment = true;
                saw_safety |= trimmed.contains("SAFETY:");
                continue;
            }
            return saw_comment && saw_safety;
        }
        saw_comment && saw_safety
    }
}
