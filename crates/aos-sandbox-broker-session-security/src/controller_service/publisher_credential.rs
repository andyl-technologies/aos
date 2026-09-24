//! Bounded systemd credential reads for the publisher service and policy source.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{Mode, OFlags, open};

/// Reports an absent or unsafe required publisher credential.
pub(super) struct PublisherCredentialErrorV1;

/// Reads one private regular credential by its fixed deployment name.
pub(super) fn read_required_credential(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, PublisherCredentialErrorV1> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(PublisherCredentialErrorV1)?;
    let directory = Path::new(&directory);
    if !directory.is_absolute() {
        return Err(PublisherCredentialErrorV1);
    }
    let descriptor = open(
        &directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PublisherCredentialErrorV1)?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| PublisherCredentialErrorV1)?;
    let process_uid = rustix::process::geteuid().as_raw();
    let length = usize::try_from(metadata.len()).map_err(|_| PublisherCredentialErrorV1)?;
    if !metadata.is_file()
        || !(minimum..=maximum).contains(&length)
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != process_uid)
        || metadata.mode() & 0o077 != 0
    {
        return Err(PublisherCredentialErrorV1);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| PublisherCredentialErrorV1)?;
    if file
        .read(&mut [0_u8; 1])
        .map_err(|_| PublisherCredentialErrorV1)?
        != 0
    {
        return Err(PublisherCredentialErrorV1);
    }
    Ok(bytes)
}
