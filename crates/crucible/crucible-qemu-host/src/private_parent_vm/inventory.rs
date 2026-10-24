//! Reads installed image floors after the original Whole purpose is reserved.
//!
//! The immutable operator selects this descriptor from the post-fixup image
//! builder. Its mapping and file extents are lower bounds, not allocation peaks
//! or a source of entitlement. The enclosing original reservation already owns
//! the reader, JSON storage and controls before this module opens the file.

use super::ParentFailure;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_INVENTORY_BYTES: u64 = 1 << 20;

#[derive(Deserialize)]
struct Inventory {
    schema: String,
    architecture: String,
    page_bytes: u64,
    initial_images: Vec<String>,
    processes: Vec<Process>,
    unique_file_bytes: u64,
    admission: bool,
    complete_loader_or_stack_bound: bool,
}

#[derive(Deserialize)]
struct Process {
    executable: String,
    load_bytes_without_sharing: u64,
}

pub(super) fn installed_floor(path: &Path, qemu: &str) -> Result<(u64, u64), ParentFailure> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(ParentFailure::Io)?;
    let metadata = file.metadata().map_err(ParentFailure::Io)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_INVENTORY_BYTES
    {
        return Err(ParentFailure::CompiledInput("immutable image descriptor"));
    }

    let length = usize::try_from(metadata.len())
        .map_err(|_| ParentFailure::CompiledInput("image descriptor extent"))?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(ParentFailure::Io)?;
    let inventory: Inventory = serde_json::from_slice(&bytes).map_err(ParentFailure::Inventory)?;
    if inventory.schema != "crucible.private-image-inventory.v1"
        || inventory.architecture != "x86_64-linux"
        || inventory.page_bytes != 4096
        || inventory.admission
        || inventory.complete_loader_or_stack_bound
        || inventory.initial_images != [qemu]
        || inventory.processes.len() != 1
        || inventory.processes[0].executable != qemu
    {
        return Err(ParentFailure::CompiledInput("installed image identity"));
    }
    Ok((
        inventory.processes[0].load_bytes_without_sharing,
        inventory.unique_file_bytes,
    ))
}
