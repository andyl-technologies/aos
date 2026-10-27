//! Pre-effect storage admission for the same original selected launch capsule.
//!
//! Protocol histories and constructor/argv ownership use the provider history
//! ceiling. Image and region backings use resident admission. Descriptor aliases
//! retain the same backing rather than creating another image allocation.

use std::io;
use std::mem::size_of;

use super::{QemuOriginalWholeLaunch, QemuWholeLaunchCustody};
use crate::QemuLaunchCommand;
use crate::native_staged_control::NativeStagedControlTransport;
use crate::spawn::{QemuChildProcessContract, QemuPreparedRunDirectory, QemuSpawnError};

/// Retains checked constructor storage obligations without source authority.
#[derive(Clone, Copy, Debug)]
pub(super) struct SelectedStorage {
    pub(super) provider_history_bytes: u64,
    pub(super) resident_bytes: u64,
    pub(super) argument_storage_bytes: u64,
}

impl SelectedStorage {
    pub(super) fn admit(
        command: &QemuLaunchCommand,
        run_directory: &QemuPreparedRunDirectory,
        region_bytes: u64,
        contract: &QemuChildProcessContract,
        additional_provider_history_bytes: u64,
    ) -> Result<Self, QemuSpawnError> {
        let plan = command.plugin_setup_plan();
        let selection = plan
            .whole_constructor()
            .ok_or_else(|| refusal("selected constructor storage is absent"))?;
        let profile = selection.profile();
        let launch = selection
            .launch2()
            .map_err(super::super::whole_setup::protocol_error)?;
        let setup_bytes = u64::try_from(
            plan.encoded_len()
                .map_err(super::super::whole_setup::protocol_error)?,
        )
        .map_err(|_| refusal("selected setup length overflows resident admission"))?;
        let actor_bytes = u64::try_from(
            NativeStagedControlTransport::required_setup_backing_bytes(profile)
                .map_err(super::super::whole_setup::protocol_error)?,
        )
        .map_err(|_| refusal("selected actor length overflows resident admission"))?;
        let argument_storage_bytes = argument_storage_bound(command)?;
        let metadata = size_of::<QemuOriginalWholeLaunch>()
            .checked_add(size_of::<QemuWholeLaunchCustody>())
            .and_then(|bytes| bytes.checked_add(size_of::<NativeStagedControlTransport>()))
            .and_then(|bytes| bytes.checked_add(run_directory.path.capacity()))
            .ok_or_else(|| refusal("selected capsule metadata overflows storage admission"))?;

        // Nested encoding, the full composite and its sealed backing can
        // coexist. Boxing may transiently copy the composite once more; three
        // full extents cover that peak without charging FD aliases again.
        let provider_history_bytes = setup_bytes
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(additional_provider_history_bytes))
            .and_then(|bytes| bytes.checked_add(actor_bytes))
            .and_then(|bytes| bytes.checked_add(argument_storage_bytes))
            .and_then(|bytes| bytes.checked_add(metadata as u64))
            .ok_or_else(|| refusal("selected provider storage overflows its admission"))?;
        if provider_history_bytes > profile.compute.provider_history_byte_limit {
            return Err(refusal(
                "selected capsule exceeds its provider history ceiling",
            ));
        }

        let images = launch.assets.iter().try_fold(0_u64, |bytes, asset| {
            bytes
                .checked_add(asset.byte_length)
                .ok_or_else(|| refusal("original image backings overflow resident admission"))
        })?;
        // Native private history is an independent reservation. The native
        // constructor must still authenticate its actual copies and closure;
        // this host arithmetic grants neither readiness nor execution credit.
        let resident_bytes = command
            .resource_requirements()
            .guest_memory_bytes()
            .checked_add(images)
            .and_then(|bytes| bytes.checked_add(region_bytes))
            .and_then(|bytes| bytes.checked_add(provider_history_bytes))
            .and_then(|bytes| bytes.checked_add(profile.compute.native_history_byte_limit))
            .ok_or_else(|| refusal("selected resident storage overflows its admission"))?;
        if resident_bytes > contract.maximum_resident_bytes {
            return Err(refusal("selected backings exceed admitted resident memory"));
        }
        Ok(Self {
            provider_history_bytes,
            resident_bytes,
            argument_storage_bytes,
        })
    }

    pub(super) fn validate_arguments(
        &self,
        executable: &str,
        arguments: &[String],
    ) -> Result<(), QemuSpawnError> {
        let actual = argument_bytes(executable, arguments)?;
        if actual > self.argument_storage_bytes {
            return Err(refusal(
                "actual selected argv exceeds its pre-effect reservation",
            ));
        }
        Ok(())
    }
}

fn argument_storage_bound(command: &QemuLaunchCommand) -> Result<u64, QemuSpawnError> {
    // These are the complete possible guarded FD prefixes and sealed-image
    // replacements. Adding them without subtracting original paths bounds both
    // explicit and implicit BIOS forms before any argument copy is allocated.
    const ADDITIONS: [&str; 14] = [
        "-add-fd",
        "fd=6,set=1,opaque=crucible-vmstate",
        "-add-fd",
        "fd=7,set=2,opaque=crucible-root-overlay-read",
        "-add-fd",
        "fd=8,set=2,opaque=crucible-root-overlay-write",
        "-bios",
        "/proc/self/fd/12",
        "/proc/self/fd/10",
        "/proc/self/fd/11",
        "/proc/self/fd/12",
        "name=opt/crucible/seed,file=/proc/self/fd/13",
        "file.filename=/dev/fdset/1",
        "file=/dev/fdset/2",
    ];
    let original = argument_bytes(command.executable(), command.args())?;
    let added = ADDITIONS.iter().try_fold(0_u64, |bytes, argument| {
        bytes
            .checked_add(argument.len() as u64 + 1)
            .ok_or_else(|| refusal("selected argv framing overflows storage admission"))
    })?;
    let added_metadata = (ADDITIONS.len() as u64)
        .checked_mul((size_of::<String>() + size_of::<usize>()) as u64)
        .ok_or_else(|| refusal("selected argc metadata overflows storage admission"))?;
    original
        .checked_add(added)
        .and_then(|bytes| bytes.checked_add(added_metadata))
        // Guarded rewriting, pinned argv and Command's temporary argument
        // representation may coexist. Their originals are never renewed.
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or_else(|| refusal("selected argv peak overflows storage admission"))
}

fn argument_bytes(executable: &str, arguments: &[String]) -> Result<u64, QemuSpawnError> {
    arguments
        .iter()
        .try_fold(executable.len() as u64 + 1, |bytes, argument| {
            bytes.checked_add(argument.len() as u64 + 1)
        })
        .and_then(|bytes| {
            arguments
                .len()
                .checked_add(2)
                .and_then(|count| count.checked_mul(size_of::<String>() + size_of::<usize>()))
                .and_then(|metadata| bytes.checked_add(metadata as u64))
        })
        .ok_or_else(|| refusal("selected argv extent overflows storage admission"))
}

fn refusal(message: &'static str) -> QemuSpawnError {
    super::super::whole_setup::protocol_error(io::Error::other(message))
}
