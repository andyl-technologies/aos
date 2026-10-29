//! Inventory of Crucible workspace crates and their crate roots.
//!
//! Workspace-wide lints (`gate:harness-lint`, the rustdoc bar, and the
//! engineering-hygiene checks) iterate this list instead of discovering crates
//! by directory name, so adding a Crucible crate is an explicit, reviewed edit
//! and the package-set check can reject unlisted crates.

/// A Crucible workspace crate and the file that holds its crate root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrucibleCrate {
    /// Cargo package name for the Crucible crate.
    pub package: &'static str,
    /// Crate root file relative to the package directory.
    pub root: &'static str,
}

/// Every Crucible crate in workspace package order.
pub const CRUCIBLE_CRATES: &[CrucibleCrate] = &[
    library("crucible-store"),
    library("crucible-determinism"),
    library("crucible-qemu-shmem"),
    library("crucible-qemu-protocol"),
    library("crucible-device"),
    library("crucible-qemu-host"),
    library("crucible-qemu-plugin"),
    library("crucible-qemu-debug-gateway"),
    library("crucible-guest"),
    library("crucible-engine"),
    library("crucible-campaign"),
    library("crucible-store-s3"),
    library("crucible-session"),
    library("crucible-control-client"),
    library("crucible-control-server"),
    library("crucible-control-api"),
    library("crucible-daemon"),
    CrucibleCrate {
        package: "crucible-cli",
        root: "src/main.rs",
    },
    library("crucible-test-support"),
];

/// Builds an entry for a library crate rooted at `src/lib.rs`.
const fn library(package: &'static str) -> CrucibleCrate {
    CrucibleCrate {
        package,
        root: "src/lib.rs",
    }
}

/// Returns every Crucible crate in workspace package order.
#[must_use]
pub fn crucible_crates() -> &'static [CrucibleCrate] {
    CRUCIBLE_CRATES
}

/// Finds a Crucible crate by Cargo package name.
#[must_use]
pub fn find_crucible_crate(package: &str) -> Option<&'static CrucibleCrate> {
    CRUCIBLE_CRATES
        .iter()
        .find(|entry| entry.package == package)
}
