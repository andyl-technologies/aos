//! Crate-to-spec ownership index for Crucible.
//!
//! RFC-0010 file 27 section 6 defines the owning spec files for each Crucible
//! runtime crate. This module is the executable copy consumed by
//! `gate:harness-lint` so crate-root docs and the RFC table stay aligned.

/// A crate-root entry in the RFC-0010 spec ownership index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrateSpecIndexEntry {
    /// Cargo package name for the Crucible crate.
    pub package: &'static str,
    /// Crate root file relative to the package directory.
    pub root: &'static str,
    /// Semantic implementation contract rendered in the crate-root overview.
    pub descriptive_contract: &'static str,
    /// Additional owning document paths relative to the repository root.
    pub additional_spec_paths: &'static [&'static str],
    /// RFC-0010 file numbers that own the crate's implementation contract.
    pub spec_files: &'static [&'static str],
    /// Supplemental non-RFC-0010 ownership rendered after the RFC-0010 files.
    pub supplemental_spec: Option<&'static str>,
    /// Whether RFC-0010 file 27 section 6 contains this crate as a table row.
    pub section_6_row: bool,
}

/// The canonical crate-to-spec index in workspace package order.
pub const CRATE_SPEC_INDEX: &[CrateSpecIndexEntry] = &[
    CrateSpecIndexEntry {
        package: "crucible-cas",
        descriptive_contract: "Content-addressed objects, durable references, authenticated closures, and bounded storage operations",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["35"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-sqlite-heap",
        descriptive_contract: "Integer-only native SQLite allocator limits and usage controls",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &[],
        supplemental_spec: None,
        section_6_row: false,
    },
    CrateSpecIndexEntry {
        package: "crucible-sim",
        descriptive_contract: "Deterministic randomness, counters, and virtual-time primitives",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["04", "08", "09"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-assert",
        descriptive_contract: "Deterministic assertion vocabulary and canonical subject identities",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["18"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-shmem",
        descriptive_contract: "Versioned shared-memory layouts, checked offsets, and process ownership",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["13"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-protocol",
        descriptive_contract: "Versioned control messages, bounded codecs, and descriptor exchange",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["14", "16"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-ram",
        descriptive_contract: "Paged RAM logical identity, persistent Merkle trees, and independent write epochs",
        additional_spec_paths: &[
            "docs/rfcs/0021-crucible-paged-ram/02-logical-ram-and-merkle-format.md",
            "docs/rfcs/0021-crucible-paged-ram/03-write-tracking-and-fingerprints.md",
        ],
        root: "src/lib.rs",
        spec_files: &[],
        supplemental_spec: Some("RFC-0021 files 02, 03"),
        section_6_row: false,
    },
    CrateSpecIndexEntry {
        package: "crucible-device",
        descriptive_contract: "Deterministic device queues and modeled I/O lifecycles",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["15"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-qemu",
        descriptive_contract: "Host-side QEMU process control, deterministic execution, and exact-state ownership",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["10", "11"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-qemu-plugin",
        descriptive_contract: "GPL-side guest observation, deterministic execution fences, and host paging",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["11", "12"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-debug-gateway",
        descriptive_contract: "Authenticated interactive debugging across the process boundary",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["36"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-guest",
        descriptive_contract: "Optional guest markers, typed selectable requests, and introspection helpers",
        additional_spec_paths: &[
            "docs/rfcs/0020-crucible-campaigns/02-selectables-and-choice-protocol.md",
        ],
        root: "src/lib.rs",
        spec_files: &["16"],
        supplemental_spec: Some("RFC-0020 file 02"),
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible",
        descriptive_contract: "Pure execution model, scheduling, faults, assertions, and replay identity",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["05", "06", "07", "08", "17", "18", "19"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-campaign",
        descriptive_contract: "Campaign identity, typed graph storage, planning, and distributed executor contracts",
        additional_spec_paths: &[
            "docs/rfcs/0020-crucible-campaigns/01-campaign-data-model.md",
            "docs/rfcs/0020-crucible-campaigns/02-selectables-and-choice-protocol.md",
            "docs/rfcs/0020-crucible-campaigns/04a-coordinator-executor-contract.md",
            "docs/rfcs/0020-crucible-campaigns/06-storage-replication-and-gc.md",
            "docs/rfcs/0020-crucible-campaigns/09-security-compatibility-and-operations.md",
        ],
        root: "src/lib.rs",
        spec_files: &[],
        supplemental_spec: Some("RFC-0020 files 01, 02, 04a, 06, 09"),
        section_6_row: false,
    },
    CrateSpecIndexEntry {
        package: "crucible-linux-resource",
        descriptive_contract: "Linux physical containment, host admission, and operational supervision",
        additional_spec_paths: &[
            "docs/rfcs/0020-crucible-campaigns/04a-coordinator-executor-contract.md",
            "docs/rfcs/0020-crucible-campaigns/06-storage-replication-and-gc.md",
        ],
        root: "src/lib.rs",
        spec_files: &[],
        supplemental_spec: Some("RFC-0020 files 04a, 06"),
        section_6_row: false,
    },
    CrateSpecIndexEntry {
        package: "crucible-s3-store",
        descriptive_contract: "Authenticated remote object storage and durable reference coordination",
        additional_spec_paths: &[
            "docs/rfcs/0020-crucible-campaigns/06-storage-replication-and-gc.md",
        ],
        root: "src/lib.rs",
        spec_files: &[],
        supplemental_spec: Some("RFC-0020 file 06"),
        section_6_row: false,
    },
    CrateSpecIndexEntry {
        package: "crucible-session",
        descriptive_contract: "Session control and lifecycle coordination at quantum boundaries",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["20"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-api",
        descriptive_contract: "Host lifecycle composition, exact checkpoints, and temporal graph APIs",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["21"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-daemon",
        descriptive_contract: "Campaign execution services, worker ownership, and host resource supervision",
        additional_spec_paths: &[
            "docs/rfcs/0020-crucible-campaigns/04a-coordinator-executor-contract.md",
        ],
        root: "src/lib.rs",
        spec_files: &["20", "21"],
        supplemental_spec: Some("RFC-0020 file 04a"),
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-cli",
        descriptive_contract: "Operator commands for execution, campaigns, debugging, and storage maintenance",
        additional_spec_paths: &[],
        root: "src/main.rs",
        spec_files: &["23"],
        supplemental_spec: None,
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-harness",
        descriptive_contract: "Executable conformance gates, independent replay checks, and ownership inventories",
        additional_spec_paths: &[],
        root: "src/lib.rs",
        spec_files: &["24", "27"],
        supplemental_spec: None,
        section_6_row: false,
    },
];

/// Returns every Crucible crate spec-index entry in workspace order.
#[must_use]
pub fn crate_spec_index() -> &'static [CrateSpecIndexEntry] {
    CRATE_SPEC_INDEX
}

/// Finds a crate spec-index entry by Cargo package name.
#[must_use]
pub fn find_crate_spec(package: &str) -> Option<&'static CrateSpecIndexEntry> {
    CRATE_SPEC_INDEX
        .iter()
        .find(|entry| entry.package == package)
}
