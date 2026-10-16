//! Holds peer-issued receipts only after independent native descriptor checks.
//!
//! Constructors are visible only to the concrete authenticated client. Borrowed
//! files alone carry no root or publication authority; consumers retain the
//! complete receipt for its actual layout guard and checked claim.

use std::{
    fs::File,
    io::{Seek, SeekFrom},
    sync::Arc,
};

use rustix::fs::{FileType, OFlags};
use terrane::host::publication::{PublicationClaim, VerityBinding};

use super::super::{Error, socket::ReceivedPacket};
use crate::host_cache::NativeHostLayout;

/// A peer probe whose empty unlinked inode has an independently measured seal.
///
/// This proves kernel sealing on the retained root device. It does not grant
/// canonical content or writable cache admission authority.
pub struct PeerSealProbe {
    file: File,
    binding: VerityBinding,
    layout: Arc<NativeHostLayout>,
}

impl PeerSealProbe {
    /// Borrows the actual measured probe inode without releasing root custody.
    pub fn handle(&self) -> &File {
        &self.file
    }

    /// Borrows the independently measured kernel binding.
    pub fn binding(&self) -> &VerityBinding {
        &self.binding
    }

    /// Borrows the retained inspected root and its live provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout> {
        &self.layout
    }
}

/// A peer's readonly inline object checked against actual plaintext and root.
///
/// The file, independently measured kernel seal, validated claim and retained
/// root guard remain together. The publisher-issued token is a lifecycle name;
/// it does not independently authorize content or another inode.
pub struct PeerPublishedObject {
    file: File,
    binding: VerityBinding,
    layout: Arc<NativeHostLayout>,
    claim: PublicationClaim,
    incarnation: [u8; 32],
}

impl PeerPublishedObject {
    /// Borrows the verified inode while retaining its root guard and claim.
    pub fn handle(&self) -> &File {
        &self.file
    }

    /// Borrows the independently measured kernel binding.
    pub fn binding(&self) -> &VerityBinding {
        &self.binding
    }

    /// Borrows the actual domain and plaintext identity checked for this inode.
    pub fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Borrows the retained inspected root and its live provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout> {
        &self.layout
    }

    /// Borrows the authenticated publisher's opaque retained-inode token.
    pub fn incarnation(&self) -> &[u8; 32] {
        &self.incarnation
    }
}

pub(super) fn probe(
    received: ReceivedPacket,
    layout: Arc<NativeHostLayout>,
    publisher_uid: u32,
) -> Result<PeerSealProbe, Error> {
    let (file, binding, stat) = checked_file(received, &layout, publisher_uid)?;
    if stat.st_nlink != 0 || stat.st_size != 0 {
        return Err(Error::Invalid("probe must be empty and unlinked"));
    }
    Ok(PeerSealProbe {
        file,
        binding,
        layout,
    })
}

pub(super) fn published(
    received: ReceivedPacket,
    layout: Arc<NativeHostLayout>,
    publisher_uid: u32,
    claim: PublicationClaim,
) -> Result<PeerPublishedObject, Error> {
    let incarnation: [u8; 32] = received
        .packet
        .body_incarnation
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid("publisher body incarnation"))?;
    let (mut file, binding, stat) = checked_file(received, &layout, publisher_uid)?;
    if stat.st_nlink == 0 || u64::try_from(stat.st_size).ok() != Some(claim.plaintext_size()) {
        return Err(Error::Invalid("canonical inode link or plaintext length"));
    }
    file.seek(SeekFrom::Start(0))?;
    claim.verify_reader(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    layout.recheck()?;

    Ok(PeerPublishedObject {
        file,
        binding,
        layout,
        claim,
        incarnation,
    })
}

fn checked_file(
    mut received: ReceivedPacket,
    layout: &NativeHostLayout,
    publisher_uid: u32,
) -> Result<(File, VerityBinding, rustix::fs::Stat), Error> {
    layout.recheck()?;
    if received.files.len() != 1 {
        return Err(Error::Invalid("peer receipt descriptor count"));
    }
    let file = received
        .files
        .pop()
        .ok_or(Error::Invalid("missing peer file"))?;
    let stat = rustix::fs::fstat(&file)?;
    let flags = rustix::fs::fcntl_getfl(&file)?;
    let root_device = layout.directory_binding("layout-root")?.0;
    if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != publisher_uid
        || stat.st_dev != root_device
    {
        return Err(Error::Invalid("peer file ownership, device or access"));
    }
    let binding = crate::verity::measure(&file)?;
    if u32::from(binding.algorithm) != received.packet.verity_algorithm
        || binding.digest != received.packet.verity_digest
    {
        return Err(Error::Invalid("peer kernel seal mismatch"));
    }
    Ok((file, binding, stat))
}
