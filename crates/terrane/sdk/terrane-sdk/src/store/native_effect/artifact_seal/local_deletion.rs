//! Owns closed native local-v1 incarnation and durable absence observations.
//!
//! Protected intent remains data until a genuine current producer supplies its
//! complete retained Frame. Native results originate only after descriptor,
//! journal and bounded witness verification under those actual exclusions.

use super::{
    CreationJournal, FencePolicy, File, JournalState, MetadataStamp, NativeEffectFailure, Path,
    PathBuf, Plan, Worker, absent_name, checked_protected, create_staging, journal_path,
    open_native,
};
use crate::pack::PackIndexSnapshot;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, mpsc};
use terrane_format::gc::{ArtifactBinding, DeleteOperation, DeletePhase};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[path = "local_deletion/effects.rs"]
pub(crate) mod effects;
#[path = "local_deletion/observation.rs"]
pub(crate) mod observation;

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// Retains independently opened ownership evidence without a public constructor.
pub(crate) struct NativeLocalDeletion {
    root: PathBuf,
    control: PathBuf,
    operation: DeleteOperation,
    snapshot: PackIndexSnapshot,
    artifacts: [Artifact; 3],
    journals: [Protected; 3],
    intent: Protected,
}

impl NativeLocalDeletion {
    /// Borrows the canonical operation independently read by the actual worker.
    pub(crate) fn operation(&self) -> &DeleteOperation {
        &self.operation
    }

    /// Borrows the independently verified retained detached-index witness.
    pub(crate) fn snapshot(&self) -> &PackIndexSnapshot {
        &self.snapshot
    }

    /// Checks the actual present restore pair against this executor-owned receipt.
    ///
    /// # Errors
    /// Refuses another namespace, inventory, journal association or absent artifact.
    pub(super) fn check_restore_association(
        &self,
        root: &Path,
        control: &Path,
        inventory: &terrane_format::bucket::PackInventoryEntry,
        journals: &[Option<Vec<u8>>; 3],
        keys: &[String; 3],
        owner: u32,
    ) -> Result<(), NativeEffectFailure> {
        self.recheck()?;
        let authorization = &self.operation.authorization;
        if self.root != root
            || self.control != control
            || self.intent.owner != owner
            || inventory.pack_id != authorization.pack_id
            || self
                .artifacts
                .iter()
                .any(|artifact| artifact.file.is_none())
            || matches!(self.operation.phase, DeletePhase::Done)
        {
            return Err(invalid("cancellation pair lacks its present local owner").into());
        }
        for (index, version) in authorization.artifacts.iter().enumerate() {
            if keys[index] != version.key
                || journals[index].as_deref() != Some(self.journals[index].bytes.as_slice())
            {
                return Err(invalid("cancellation pair journal association changed").into());
            }
        }
        if authorization.artifacts[0].binding
            != (ArtifactBinding::Pack {
                digest: inventory.pack_hash,
                size: inventory.pack_size,
            })
            || authorization.artifacts[1].binding
                != (ArtifactBinding::Index {
                    digest: inventory.index_hash,
                    size: inventory.index_size,
                })
        {
            return Err(invalid("cancellation pair inventory differs from exact owner").into());
        }
        Ok(())
    }

    /// Rechecks names, exact bodies and descriptor identities without acquiring locks.
    ///
    /// # Errors
    /// Refuses replacement, recreation, changed ownership or unavailable observations.
    pub(crate) fn recheck(&self) -> Result<(), NativeEffectFailure> {
        self.intent.check()?;
        for journal in &self.journals {
            journal.check()?;
        }
        for artifact in &self.artifacts {
            artifact.check()?;
        }
        Ok(())
    }
}

struct Protected {
    path: PathBuf,
    file: File,
    stamp: MetadataStamp,
    bytes: Vec<u8>,
    owner: u32,
}

impl Protected {
    fn check(&self) -> io::Result<()> {
        let mut file = self.file.try_clone()?;
        checked_protected(&mut file, &self.path, self.stamp, &self.bytes, self.owner)
    }
}

struct Artifact {
    path: PathBuf,
    file: Option<File>,
    observation: Option<ArtifactObservation>,
    bounded_body: Option<Vec<u8>>,
    owner: u32,
}

impl Artifact {
    fn check(&self) -> io::Result<()> {
        match (&self.file, self.observation) {
            (Some(file), Some(observation)) => {
                let named = ArtifactObservation::checked(&std::fs::symlink_metadata(&self.path)?)?;
                let actual = ArtifactObservation::checked(&file.metadata()?)?;
                FencePolicy::Payload { owner: self.owner }.validate(named.stamp)?;
                if named != observation || actual != observation {
                    return Err(invalid("owned artifact incarnation changed"));
                }
                if let Some(expected) = &self.bounded_body {
                    let mut opened = file.try_clone()?;
                    opened.seek(SeekFrom::Start(0))?;
                    let mut actual = vec![0; expected.len()];
                    opened.read_exact(&mut actual)?;
                    if &actual != expected {
                        return Err(invalid("owned bounded artifact body changed"));
                    }
                }
                if ArtifactObservation::checked(&file.metadata()?)? != observation
                    || ArtifactObservation::checked(&std::fs::symlink_metadata(&self.path)?)?
                        != observation
                {
                    return Err(invalid(
                        "owned artifact changed during bounded verification",
                    ));
                }
                Ok(())
            }
            (None, None) => absent_name(&self.path),
            _ => Err(invalid("incomplete owned observation")),
        }
    }
}

// Descriptor and name observations retain modification continuity, including
// nanosecond change time so a same-inode rewrite cannot preserve the receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArtifactObservation {
    stamp: MetadataStamp,
    length: u64,
    modified: std::time::SystemTime,
    changed: (i64, i64),
}

impl ArtifactObservation {
    #[cfg(unix)]
    fn checked(metadata: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            stamp: MetadataStamp::checked(metadata)?,
            length: metadata.len(),
            modified: metadata.modified()?,
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn checked(_metadata: &std::fs::Metadata) -> io::Result<Self> {
        Err(invalid("native owned artifact observations unavailable"))
    }
}

/// Retains an executor-observed physical journal replacement for continuity.
///
/// Its construction follows the exact rename, before directory durability. It
/// grants no restore permission or durable acknowledgment.
pub(super) struct CancelledJournal {
    replacement: Protected,
    original: Vec<u8>,
}

impl CancelledJournal {
    /// Borrows verified replacement bytes and duplicates the actual descriptor.
    ///
    /// # Errors
    /// Refuses a changed replacement or failed descriptor duplication.
    pub(super) fn replacement(&self) -> io::Result<(&Path, File, &[u8])> {
        self.replacement.check()?;
        Ok((
            &self.replacement.path,
            self.replacement.file.try_clone()?,
            &self.replacement.bytes,
        ))
    }

    /// Borrows the exact retained pre-replacement journal body.
    pub(super) fn original(&self) -> &[u8] {
        &self.original
    }
}

/// Delegates actual native effects for the finite owning qualification cases.
#[cfg(all(test, feature = "tokio", unix))]
#[path = "../../../gc/runner/tests/local_deletion/support/fs.rs"]
pub(crate) mod test_fs;
