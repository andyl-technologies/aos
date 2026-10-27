//! Binds readonly read members to original admission stamps and complete bytes.
//!
//! This binding is available only from a retained physical admission member.
//! It grants neither policy protection nor permission to remove an allocation.

use super::io::{FileStamp, PendingFile};
use crate::{host_cache::NativeHostLayout, host_quota::NativeProject};
use rustix::fs::{self, OFlags};
use std::{
    fs::File,
    io,
    os::unix::fs::{FileExt, MetadataExt},
    sync::Arc,
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains one readonly original with its admitted bytes and native binding.
pub(super) struct ReadMember {
    /// Original readonly open description, never a caller-supplied descriptor.
    pub(super) file: File,
    /// Device, inode and original length captured from this actual member.
    pub(super) inode: (u64, u64, u64),
    /// Shared verified admission bytes, checked against the complete original.
    pub(super) expected: Arc<Vec<u8>>,
    stamp: FileStamp,
    mode: u32,
}

impl ReadMember {
    /// Binds an original member while its actual policy custody is held.
    ///
    /// # Errors
    /// Refuses changed native custody, an absent original or descriptor failure.
    pub(super) fn bind(
        original: &PendingFile,
        expected: Arc<Vec<u8>>,
        stamp: FileStamp,
    ) -> io::Result<Self> {
        let file = original
            .readonly
            .as_ref()
            .ok_or_else(|| invalid("original admission read descriptor absent"))?
            .try_clone()?;
        let metadata = file.metadata()?;
        Ok(Self {
            file,
            inode: (metadata.dev(), metadata.ino(), metadata.len()),
            expected,
            stamp,
            mode: metadata.mode() & 0o7777,
        })
    }

    /// Checks original inode custody without embedded state or job locks.
    ///
    /// # Errors
    /// Refuses changed stamps, root, ownership, mode, links, length or project.
    pub(super) fn check_native(
        &self,
        layout: &NativeHostLayout<HostDomainLocation>,
        project: u32,
        uid: u32,
        gid: u32,
    ) -> io::Result<()> {
        self.stamp.check(&self.file)?;
        let metadata = self.file.metadata()?;
        if self.inode.0 != layout.directory_binding("layout-root")?.0
            || (metadata.dev(), metadata.ino(), metadata.len()) != self.inode
            || usize::try_from(metadata.len()).ok() != Some(self.expected.len())
            || metadata.uid() != uid
            || metadata.gid() != gid
            || !metadata.is_file()
            || metadata.nlink() != 1
            || !matches!(self.mode, 0o640 | 0o660)
            || metadata.mode() & 0o7777 != self.mode
            || fs::fcntl_getfl(&self.file)?.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
            || NativeProject::inspect(&self.file)?.project_id != project
        {
            return Err(invalid("read changed original native admission member"));
        }
        Ok(())
    }

    /// Compares the complete original file using a fixed scratch window.
    ///
    /// # Errors
    /// Refuses offset overflow, native read failure or any changed byte.
    pub(super) fn check_bytes(&self) -> io::Result<()> {
        let mut scratch = [0_u8; 8192];
        for (position, expected) in self.expected.chunks(scratch.len()).enumerate() {
            let offset = position
                .checked_mul(scratch.len())
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or_else(|| invalid("original member verification offset overflow"))?;
            self.file
                .read_exact_at(&mut scratch[..expected.len()], offset)?;
            if &scratch[..expected.len()] != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "original admission member bytes changed",
                ));
            }
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
