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
    /// RFC-0010 file numbers that own the crate's implementation contract.
    pub spec_files: &'static [&'static str],
    /// Whether RFC-0010 file 27 section 6 contains this crate as a table row.
    pub section_6_row: bool,
}

/// The canonical crate-to-spec index in workspace package order.
pub const CRATE_SPEC_INDEX: &[CrateSpecIndexEntry] = &[
    CrateSpecIndexEntry {
        package: "crucible-cas",
        root: "src/lib.rs",
        spec_files: &["35"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-sim",
        root: "src/lib.rs",
        spec_files: &["04", "08", "09"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-assert",
        root: "src/lib.rs",
        spec_files: &["18"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-shmem",
        root: "src/lib.rs",
        spec_files: &["13"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-protocol",
        root: "src/lib.rs",
        spec_files: &["14", "16"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-device",
        root: "src/lib.rs",
        spec_files: &["15"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-qemu",
        root: "src/lib.rs",
        spec_files: &["10", "11"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-qemu-plugin",
        root: "src/lib.rs",
        spec_files: &["11", "12"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-guest",
        root: "src/lib.rs",
        spec_files: &["16"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible",
        root: "src/lib.rs",
        spec_files: &["05", "06", "07", "08", "17", "18", "19"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-session",
        root: "src/lib.rs",
        spec_files: &["20"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-api",
        root: "src/lib.rs",
        spec_files: &["21"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-daemon",
        root: "src/lib.rs",
        spec_files: &["20", "21"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-cli",
        root: "src/main.rs",
        spec_files: &["23"],
        section_6_row: true,
    },
    CrateSpecIndexEntry {
        package: "crucible-harness",
        root: "src/lib.rs",
        spec_files: &["24", "27"],
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
