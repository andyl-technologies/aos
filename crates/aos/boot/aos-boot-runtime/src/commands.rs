//! Process entry points for retained boot tools.
//!
//! Arguments and standard streams follow the existing installed executable
//! contracts. The operations validate their pinned tools and authenticated
//! inputs before changing boot state.

use std::path::PathBuf;

use anyhow::{Result, ensure};

/// Executes selected boot-platform operations from process arguments and input.
///
/// # Errors
///
/// Returns an error for invalid arguments, unauthenticated input, unavailable
/// pinned tools, or a failed boot-state operation.
pub fn run_boot_platform() -> Result<()> {
    crate::boot_platform::run_from_process()
}

/// Stages an authenticated image into the inactive immutable root slot.
///
/// # Errors
///
/// Returns an error for invalid input, artifact or identity mismatches, unsafe
/// storage, failed pinned tools, or a failed durable publication.
pub fn run_image_stage() -> Result<()> {
    crate::image_stage::run_from_process()
}

/// Emits verified image measurement evidence from process arguments.
///
/// # Errors
///
/// Returns an error for invalid arguments, mismatched measurements, unavailable
/// verifier tools, or a failed read or output operation.
pub fn run_image_evidence() -> Result<()> {
    crate::measurement_index::run(&std::env::args().skip(1).collect::<Vec<_>>())
}

/// Restores journal-owned store transport using the selected immutable Nix tool.
///
/// # Errors
///
/// Returns an error for invalid arguments, unsafe tool or journal paths,
/// invalid retained transport, or failed store restoration.
pub fn run_initrd_store() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 4
            && arguments[0] == "--nix-store"
            && arguments[2] == "--state-directory",
        "initrd store restoration requires the selected Nix tool and journal directory"
    );

    let nix_store = PathBuf::from(&arguments[1]);
    aos_nix::executable::validate_store_executable(&nix_store, "--nix-store")?;
    let journal = PathBuf::from(&arguments[3]);
    ensure!(
        journal.is_absolute(),
        "initrd journal directory is not absolute"
    );

    crate::initrd_store::restore(&nix_store, &journal)
}
