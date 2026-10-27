//! Preserves original rejected inode custody without replacing earlier quarantine.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;

use rustix::fs;
#[cfg(feature = "tokio")]
use terrane_format::identity::Descriptor;
use terrane_sdk::host::publication::PublicationClaim;

use super::{NativePublisher, adoption, compare_inode, invalid, name};

impl NativePublisher {
    /// Opens only the original publisher-owned quarantined inode read-only.
    ///
    /// No content, seal or lifecycle claim follows from this observation. The
    /// consumer must check its actual project and retained namespace identity.
    #[cfg(feature = "tokio")]
    pub(in crate::publisher_io) fn inspect_quarantined_sealed(
        &self,
        descriptor: &Descriptor,
        incarnation: Option<&[u8; 32]>,
    ) -> io::Result<File> {
        self.confinement.check_current()?;
        let name = quarantine_name(descriptor, incarnation);
        // O_PATH classification precedes the readable open so an unexpected
        // special file is never opened as a device or a blocking FIFO.
        let file = adoption::open_candidate(&self.quarantine, &name, &self.sealed)?;
        let metadata = file.metadata()?;
        if metadata.nlink() != 1 || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600) {
            return Err(invalid("unsafe quarantined sealed inode custody"));
        }
        self.quarantine.sync_all()?;
        Ok(file)
    }

    /// Moves an independently rejected canonical entry to scoped quarantine.
    ///
    /// The canonical entry must still match the retained rejected inode. The
    /// target directory comes from trusted configuration, not a request pathname.
    /// Cache policy retains quarantine until scrub confirms
    /// another good copy or the configured retention expires.
    ///
    /// # Errors
    /// Returns invalid target custody, cross-device, missing source, conflicting
    /// quarantine name or directory synchronization errors.
    pub fn quarantine_rejected(
        &mut self,
        claim: &PublicationClaim,
        rejected: &File,
        quarantine: &File,
    ) -> io::Result<()> {
        self.quarantine_named(claim, rejected, quarantine, &name(claim))
    }

    #[cfg(feature = "tokio")]
    pub(in crate::publisher_io) fn quarantine_registered(
        &mut self,
        claim: &PublicationClaim,
        original: &File,
        incarnation: &[u8; 32],
    ) -> io::Result<()> {
        let target = self.quarantine.try_clone()?;
        let name = quarantine_name(claim.descriptor(), Some(incarnation));
        self.quarantine_named(claim, original, &target, &name)
    }

    fn quarantine_named(
        &mut self,
        claim: &PublicationClaim,
        rejected: &File,
        quarantine: &File,
        target_name: &str,
    ) -> io::Result<()> {
        self.confinement.check_current()?;
        self.check_claim(claim)?;
        let target = quarantine.metadata()?;
        if !target.is_dir()
            || target.mode() & 0o002 != 0
            || target.dev() != self.sealed.metadata()?.dev()
        {
            return Err(invalid("unsafe quarantine directory or filesystem"));
        }
        let shard = self.shard(claim)?;
        let name = name(claim);
        let canonical = adoption::open_candidate(&shard, &name, &self.sealed)?;
        compare_inode(rejected, &canonical)?;
        fs::renameat_with(
            &shard,
            name.as_str(),
            quarantine,
            target_name,
            fs::RenameFlags::NOREPLACE,
        )?;
        shard.sync_all()?;
        quarantine.sync_all()
    }
}

/// Encodes a scoped quarantine name; the optional suffix carries no authority.
#[cfg(feature = "tokio")]
pub(crate) fn quarantine_name(descriptor: &Descriptor, incarnation: Option<&[u8; 32]>) -> String {
    let mut name: String = descriptor
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if let Some(incarnation) = incarnation {
        name.push('.');
        name.push_str(
            &incarnation
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
    }
    name
}
