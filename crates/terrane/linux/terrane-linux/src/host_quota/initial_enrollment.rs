//! Owns native first administrative enrollment and receipt-bound metadata changes.
//!
//! Fresh administrative operations retain the actual creator receipt, original
//! exclusions and protected project claim. Receipt-bound setters track actual
//! administrative effects; they grant no final custody, accounting, readiness
//! or completed-enrollment authority.
//!
//! Fresh creator evidence cannot be obtained from an existing bucket or decoded
//! registration records.

mod inspection;
mod setters;

use super::{DomainProvisioningGuard, NativeProject};
use std::{
    fs::{File, Metadata},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};
use terrane_format::{
    bucket::StoreProfile,
    gc::publication::{BackendBinding, PublicationTransaction},
};
use terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment;

const MAX_ENTRIES: usize = 1024;

/// Specifies host administrative ownership and permission intent for one inode.
///
/// These values are configuration data, never evidence of a durable claim or
/// privilege. Receipt-bound setters independently check native custody and the
/// complete current preimage before applying this intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialCustody {
    /// Intended native user identifier.
    pub uid: u32,
    /// Intended native group identifier.
    pub gid: u32,
    /// Intended permission and special bits, bounded to `0o7777`.
    pub mode: u32,
}

/// Retains a fresh creator, exclusive host guard and actual scaffold events.
///
/// Only [`Self::create`] constructs this value. It grants no final custody,
/// ready-state, quota credit, recovery completion or general bucket authority.
/// Administrative callers must durably publish the complete first global claim
/// and enrollment ledger before invoking any project or custody setter.
pub struct NativeInitialHostScaffold {
    initial: NativeInitialBucketEnrollment,
    guard: DomainProvisioningGuard,
    identity: Arc<()>,
    directories: Vec<Entry>,
    files: Vec<Entry>,
    faulted: bool,
}

struct Entry {
    path: PathBuf,
    descriptor: File,
    original: Metadata,
    current: Metadata,
    original_project: NativeProject,
    current_project: NativeProject,
    bytes: Option<Vec<u8>>,
    created: bool,
}

#[derive(Clone)]
struct Key {
    owner: Arc<()>,
    index: usize,
}

/// Selects one original regular file within its owning scaffold transaction.
///
/// A key cannot be constructed from a path or descriptor or reused with another
/// receipt. Possession alone grants no project or custody mutation.
#[derive(Clone)]
pub struct InitialFileKey(Key);

/// Selects one retained directory within its owning scaffold transaction.
#[derive(Clone)]
pub struct InitialDirectoryKey(Key);

/// Borrows one original or actually created directory and its full preimage.
pub struct InitialDirectory<'a> {
    entry: &'a Entry,
    key: InitialDirectoryKey,
}

/// Borrows one original regular leaf and its exact immutable creator bytes.
pub struct InitialFile<'a> {
    entry: &'a Entry,
    key: InitialFileKey,
}

impl NativeInitialHostScaffold {
    /// Consumes genuine fresh enrollment and same-root exclusive host custody.
    ///
    /// The original receipt is verified before effects. Only fixed missing host
    /// directories are created; existing unrecognized entries are rejected.
    /// Subsequent checks use the exact extended namespace and actual creation
    /// events, rather than replaying the original pre-expansion receipt checker.
    /// Partial creation is intentionally left fail closed for administration.
    ///
    /// # Errors
    /// Refuses non-host root, another or shared guard, stale original evidence,
    /// unsafe preimages, unexpected entries, unsupported project inspection,
    /// creation races and native I/O or synchronization failure.
    pub fn create(
        initial: NativeInitialBucketEnrollment,
        guard: DomainProvisioningGuard,
    ) -> io::Result<Self> {
        inspection::create(initial, guard)
    }

    /// Rechecks the complete retained namespace at its current declared phase.
    ///
    /// Run this before persisting the complete first global claim and ledger.
    /// Successful receipt-bound setters advance only their actual target's
    /// expected metadata; any uncertain setter permanently faults the receipt.
    ///
    /// # Errors
    /// Refuses changed names, inodes, metadata, project attributes or bytes,
    /// missing host/exclusive custody, unexpected entries and native failures.
    pub fn recheck(&self) -> io::Result<()> {
        inspection::recheck(self)
    }

    /// Borrows the original successfully created bucket root.
    pub fn root(&self) -> &Path {
        self.initial.root()
    }

    /// Borrows the original external protected-control root.
    pub fn control(&self) -> &Path {
        self.initial.control()
    }

    /// Returns the original checked creator UID, which must be initial host zero.
    pub fn operator_uid(&self) -> u32 {
        self.initial.operator_uid()
    }

    /// Borrows the original root and coordination inode binding.
    pub fn binding(&self) -> &BackendBinding {
        self.initial.binding()
    }

    /// Borrows the original registered store and chunk profile.
    pub fn profile(&self) -> &StoreProfile {
        self.initial.profile()
    }

    /// Borrows the canonical acknowledged empty genesis as data only.
    pub fn genesis(&self) -> &PublicationTransaction {
        self.initial.genesis()
    }

    /// Iterates the bounded complete retained directory set.
    pub fn directories(&self) -> impl Iterator<Item = InitialDirectory<'_>> {
        self.directories
            .iter()
            .enumerate()
            .map(move |(index, entry)| InitialDirectory {
                entry,
                key: InitialDirectoryKey(Key {
                    owner: Arc::clone(&self.identity),
                    index,
                }),
            })
    }

    /// Iterates the bounded complete original regular-file set.
    pub fn files(&self) -> impl Iterator<Item = InitialFile<'_>> {
        self.files
            .iter()
            .enumerate()
            .map(move |(index, entry)| InitialFile {
                entry,
                key: InitialFileKey(Key {
                    owner: Arc::clone(&self.identity),
                    index,
                }),
            })
    }
}

impl InitialDirectory<'_> {
    /// Returns the transaction-bound selector for this directory.
    pub fn key(&self) -> InitialDirectoryKey {
        self.key.clone()
    }

    /// Borrows its fixed canonical path.
    pub fn path(&self) -> &Path {
        &self.entry.path
    }

    /// Borrows the actual retained directory descriptor.
    pub fn descriptor(&self) -> &File {
        &self.entry.descriptor
    }

    /// Borrows the complete original preimage before administrative setters.
    pub fn observed_metadata(&self) -> &Metadata {
        &self.entry.original
    }

    /// Borrows the expected metadata after actual tracked effects.
    pub fn current_metadata(&self) -> &Metadata {
        &self.entry.current
    }

    /// Borrows the original project assignment used by the first ledger.
    pub fn observed_project(&self) -> &NativeProject {
        &self.entry.original_project
    }

    /// Reports an actual successful directory creation event in this transaction.
    pub fn created(&self) -> bool {
        self.entry.created
    }
}

impl InitialFile<'_> {
    /// Returns the transaction-bound selector for this original file.
    pub fn key(&self) -> InitialFileKey {
        self.key.clone()
    }

    /// Borrows the original canonical path.
    pub fn path(&self) -> &Path {
        &self.entry.path
    }

    /// Borrows the actual original read-only file descriptor.
    pub fn descriptor(&self) -> &File {
        &self.entry.descriptor
    }

    /// Borrows the complete original preimage before administrative setters.
    pub fn observed_metadata(&self) -> &Metadata {
        &self.entry.original
    }

    /// Borrows the expected metadata after actual tracked effects.
    pub fn current_metadata(&self) -> &Metadata {
        &self.entry.current
    }

    /// Borrows the original project assignment used by the first ledger.
    pub fn observed_project(&self) -> &NativeProject {
        &self.entry.original_project
    }

    /// Borrows the exact original creator bytes, never caller assertions.
    pub fn expected_bytes(&self) -> &[u8] {
        self.entry.bytes.as_deref().unwrap_or(&[])
    }

    /// Reports membership in the original external protected-control namespace.
    ///
    /// # Errors
    /// Returns an error when the supplied scaffold belongs to another receipt.
    pub fn is_private(&self, scaffold: &NativeInitialHostScaffold) -> io::Result<bool> {
        if !Arc::ptr_eq(&self.key.0.owner, &scaffold.identity) {
            return Err(io::Error::other("file belongs to another initial scaffold"));
        }
        Ok(self.entry.path.starts_with(scaffold.control()))
    }
}

#[cfg(all(test, feature = "native-test-fixtures"))]
mod tests;

/// Requires actual host UID zero in the initial host user namespace.
///
/// Administrative enrollment calls this before registry writes or scaffold
/// creation. Success establishes this immediate process precondition only;
/// creator evidence, exclusion and durable claims remain separate obligations.
///
/// # Errors
/// Refuses a noninitial user namespace, another effective user identity or
/// failure to inspect the actual native namespace boundary.
pub fn require_initial_host_root() -> std::io::Result<()> {
    super::require_host_root_namespace_boundary()?;
    if !rustix::process::geteuid().is_root() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "initial enrollment requires actual host UID zero",
        ));
    }
    Ok(())
}
