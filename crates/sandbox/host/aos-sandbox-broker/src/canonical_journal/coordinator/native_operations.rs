//! Keeps existing descriptor-producing mechanics on sealed native coordinators.
//!
//! Passive read views cannot produce descriptors. Only actual closed C/R/Source
//! writers and the ordinary native adapter implement this port. Their trusted
//! upper caller retains its existing complete financial, child and confinement
//! gates at every original frontier. These operations certify no role success.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::owner::NativeJournal;
use aos_sandbox_journal::protected_storage::{
    FileIdentity, OriginalFileMetadataV1, ProtectedFailure, ProtectedJournalLocation,
    inspect_original_file_metadata,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::receiving::root_invocation::RootInvocationOriginalV1;
use super::invocation_cursor::enter_root_read;

/// Borrows named native operations without exposing actual files or location.
///
/// This has no public constructor, File/FD getter, payment callback, native
/// tuple adoption or semantic grant. Descriptor destinations are the actual
/// already-paid legacy recipients, not new reusable receiving permissions.
pub struct CanonicalWriterNativeOperationsV1<'owner, P> {
    native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
    location: Option<&'owner ProtectedJournalLocation<P>>,
    invocation: Option<&'owner RootInvocationOriginalV1>,
}

impl<P> Copy for CanonicalWriterNativeOperationsV1<'_, P> {}

impl<P> Clone for CanonicalWriterNativeOperationsV1<'_, P> {
    fn clone(&self) -> Self { *self }
}

impl<'owner, P> CanonicalWriterNativeOperationsV1<'owner, P> {
    pub(crate) const fn from_parts(
        native: &'owner NativeJournal<RecordNamespace, JournalLimits>,
        location: Option<&'owner ProtectedJournalLocation<P>>,
        invocation: Option<&'owner RootInvocationOriginalV1>,
    ) -> Self { Self { native, location, invocation } }

    /// Bounds actual inline operation-view carriers before entry.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)
    }

    /// Duplicates the SAME lock description at its existing confined-loan site.
    ///
    /// # Errors
    /// Rejects an occupied destination or preserves the original duplicate error.
    pub fn copy_confined_lock_description_into(self, output: &mut Option<File>) -> io::Result<()> {
        let mut guard = enter_root_read(self.invocation)?;
        if output.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "lock destination is occupied"));
        }
        let result = self.native.lock_file().try_clone();
        match result {
            Ok(file) => { *output = Some(file); Ok(()) },
            Err(cause) => {
                if let Some(guard) = guard.as_mut() { guard.refuse(); }
                Err(cause)
            }
        }
    }

    /// Fills Nix's actual child and HELLO lock slots in their original order.
    ///
    /// # Errors
    /// Retains each reached duplicate in its destination before later refusal.
    /// Preserves duplicate-then-duplicate-then-original-metadata ordering.
    pub fn duplicate_nix_lock_pair_into(
        self, child: &mut Option<OwnedFd>, hello: &mut Option<OwnedFd>,
    ) -> io::Result<OriginalFileMetadataV1> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = (|| {
            if child.is_some() || hello.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Nix lock destinations are occupied"));
            }
            aos_sandbox_journal::protected_storage::duplicate_nix_lock_pair_original_v1(
                self.native.lock_file(), child, hello,
            )
        })();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Samples the original complete lock metadata for existing recipient checks.
    ///
    /// # Errors
    /// Preserves the sole native inspection error without duplicating a file.
    pub fn lock_metadata(self) -> io::Result<OriginalFileMetadataV1> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = inspect_original_file_metadata(self.native.lock_file());
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Runs the exact positioned content-plus-EOF reader on the SAME data file.
    ///
    /// # Errors
    /// Preserves native error, short read and trailing-byte classes and partial
    /// caller output. No retry, extra probe or fresh file opening is added.
    pub fn read_exact_positioned_retaining_cause(
        self, output: &mut [u8],
    ) -> Result<(), aos_sandbox_linux::protected_file::ExactReadFailure> {
        let mut guard = enter_root_read(self.invocation)
            .map_err(|_| aos_sandbox_linux::protected_file::ExactReadFailure::Read)?;
        let result = aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            self.native.file(), output,
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Reads the existing fixed evidence label from Directory, Journal and Lock.
    ///
    /// The comparison label remains the actual upper policy's supplied DATA.
    ///
    /// # Errors
    /// Preserves the first native xattr failure or original boundary refusal.
    pub fn require_original_labels<E: ProtectedFailure>(self, expected: &[u8]) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| E::BOUNDARY)?;
        let result = (|| {
            let location = self.location.ok_or(E::BOUNDARY)?;
            enum Descriptor<'file, P> {
                Directory(&'file ProtectedJournalLocation<P>),
                File(&'file File),
            }
            for descriptor in [
                Descriptor::Directory(location),
                Descriptor::File(self.native.file()),
                Descriptor::File(self.native.lock_file()),
            ] {
                let mut context = [0_u8; 256];
                let length = match descriptor {
                    Descriptor::Directory(location) =>
                        location.directory_xattr("security.selinux", &mut context[..]),
                    Descriptor::File(file) =>
                        rustix::fs::fgetxattr(file, "security.selinux", &mut context[..]),
                }.map_err(aos_sandbox_journal::protected_storage::rustix_io::<E>)?;
                let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
                if actual != expected { return Err(E::BOUNDARY); }
            }
            Ok(())
        })();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }
    /// Observes the actual retained directory's complete metadata DATA.
    ///
    /// # Errors
    /// Preserves native inspection failure without lending a directory file.
    pub fn directory_metadata(self) -> io::Result<OriginalFileMetadataV1> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = self.location.ok_or_else(|| io::Error::new(
            io::ErrorKind::PermissionDenied, "protected journal location is absent",
        ))?.directory_metadata();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Observes the original directory's Linux mount identity.
    ///
    /// # Errors
    /// Preserves the existing mount inspection error or rejects closed entry.
    #[cfg(target_os = "linux")]
    pub fn directory_mount_id(self)
        -> Result<aos_sandbox_linux::inventory::MountId, aos_linux_descriptors::Error>
    {
        let mut guard = enter_root_read(self.invocation).map_err(|source|
            aos_linux_descriptors::Error::Syscall { operation: "Root journal invocation", source })?;
        let location = self.location.ok_or(aos_linux_descriptors::Error::WrongDescriptorType {
            expected: "protected journal directory",
        })?;
        let result = location.directory_mount_id();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Reads the original directory attribute for the unchanged upper predicate.
    ///
    /// # Errors
    /// Preserves the original xattr errno or rejects a closed invocation.
    pub fn directory_xattr(self, name: &str, bytes: &mut [u8]) -> Result<usize, rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.directory_xattr(name, bytes);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Opens the original fixed Nix input into its actual retained destination.
    ///
    /// # Errors
    /// Preserves the existing UID-zero, no-create/no-truncate protected opener.
    pub fn open_nix_named_original<E: ProtectedFailure>(
        self, name: &str, output: &mut Option<File>,
    ) -> Result<(), E> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| E::BOUNDARY)?;
        let result = self.location.ok_or(E::BOUNDARY)?.open_named_original(
            name, 0, false, false, false, output,
        );
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Delegates the existing `open_named_child` syscall frontier to the same directory.
    ///
    /// Actual upper publication, financial and recipient gates stay unchanged.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn open_named_child(self, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.open_named_child(name);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Delegates the existing `inspect_staged_name` syscall frontier to the same directory.
    ///
    /// Actual upper publication, financial and recipient gates stay unchanged.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn inspect_staged_name(self, name: &str) -> Result<rustix::fs::Stat, rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.inspect_staged_name(name);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Delegates the existing `open_exclusive_stage` syscall frontier to the same directory.
    ///
    /// Actual upper publication, financial and recipient gates stay unchanged.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn open_exclusive_stage(self, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.open_exclusive_stage(name);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Delegates the existing `publish_exclusive_stage` syscall frontier to the same directory.
    ///
    /// Actual upper publication, financial and recipient gates stay unchanged.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn publish_exclusive_stage(self, temporary: &str, output: &str) -> Result<(), rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.publish_exclusive_stage(temporary, output);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

    /// Opens the same directory's resumable stage without truncation.
    ///
    /// Existing financial, publication and recipient gates remain with the
    /// actual upper owner. Creation is exclusive; this supplies no approval.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn open_resumable_stage(
        self,
        name: &str,
        create_new: bool,
    ) -> Result<OwnedFd, rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?
            .open_resumable_stage(name, create_new);
        if result.is_err() {
            if let Some(guard) = guard.as_mut() {
                guard.refuse();
            }
        }
        result
    }

    /// Delegates the existing `sync_directory` syscall frontier to the same directory.
    ///
    /// Actual upper publication, financial and recipient gates stay unchanged.
    ///
    /// # Errors
    /// Preserves the original errno or rejects absent/closed native custody.
    #[cfg(target_os = "linux")]
    pub fn sync_directory(self) -> Result<(), rustix::io::Errno> {
        let mut guard = enter_root_read(self.invocation).map_err(|_| rustix::io::Errno::PERM)?;
        let result = self.location.ok_or(rustix::io::Errno::PERM)?.sync_directory();
        if result.is_err() {
            if let Some(guard) = guard.as_mut() { guard.refuse(); }
        }
        result
    }

}
