//! Preserves original payload ancestry and whole-value reads through effects.
//!
//! These operation-local recipes carry physical observations, not actor or
//! publication authority. The caller retains its actual held namespace and
//! freshly checks selected authority before completing a history walk.

use super::{
    BucketBinding, ExactRead, FencePolicy, Frame, LocalFs, MetadataStamp, ParentFence, Path,
    PathBuf, StoreFailure, copy_parents, corrupt, io_failure,
};
use crate::bucket::publication::receipts::RecordRead;

/// Captures ordered original ancestors before the payload body is consumed.
pub(crate) struct PayloadReadCapture {
    path: PathBuf,
    parents: Vec<ParentFence>,
    owner: u32,
}

/// Retains the exact original payload recipe without granting mutation authority.
pub(crate) struct RetainedPayloadRead {
    read: ExactRead,
}

impl PayloadReadCapture {
    /// Observes and validates each original ancestor before descending further.
    ///
    /// # Errors
    /// Refuses noncanonical paths, unsafe or unavailable ancestors and metadata.
    /// A missing ancestor refuses this scoped optimization; retained absence
    /// is supported only when every original ancestor exists.
    pub(crate) async fn capture<F: LocalFs + BucketBinding>(
        fs: &F,
        path: &Path,
        owner: u32,
    ) -> Result<Self, StoreFailure> {
        let mut parents = Vec::new();
        for path in super::super::parent_paths(path).map_err(io_failure)? {
            let metadata = fs.symlink_metadata(&path).await.map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor { owner }
                .validate(stamp)
                .map_err(io_failure)?;
            parents.push(ParentFence { path, stamp });
        }
        Ok(Self {
            path: path.to_owned(),
            parents,
            owner,
        })
    }

    /// Attaches the original ancestors to the independently observed leaf.
    ///
    /// # Errors
    /// Refuses another path, incomplete presence data or unsafe payload policy.
    pub(crate) fn finish(self, observed: &RecordRead) -> Result<RetainedPayloadRead, StoreFailure> {
        if self.path != observed.path() {
            return Err(corrupt());
        }
        let metadata = observed
            .metadata()
            .map(MetadataStamp::checked)
            .transpose()
            .map_err(io_failure)?;
        if observed.bytes().is_some() != metadata.is_some() {
            return Err(corrupt());
        }
        let policy = FencePolicy::Payload { owner: self.owner };
        if let Some(stamp) = metadata {
            policy.validate(stamp).map_err(io_failure)?;
        }
        Ok(RetainedPayloadRead {
            read: ExactRead {
                path: self.path,
                expected: observed.bytes().map(<[u8]>::to_vec),
                identity: metadata.map(|stamp| stamp.identity),
                metadata,
                policy,
                owner: self.owner,
                parents: self.parents,
            },
        })
    }
}

impl RetainedPayloadRead {
    async fn ancestors<F: LocalFs + BucketBinding>(&self, fs: &F) -> Result<(), StoreFailure> {
        for parent in &self.read.parents {
            let metadata = fs
                .symlink_metadata(&parent.path)
                .await
                .map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor {
                owner: self.read.owner,
            }
            .validate(stamp)
            .map_err(io_failure)?;
            if !stamp.same_incarnation(parent.stamp) {
                return Err(corrupt());
            }
        }
        Ok(())
    }

    fn matches(
        &self,
        bytes: Option<&[u8]>,
        metadata: Option<&std::fs::Metadata>,
    ) -> Result<(), StoreFailure> {
        let stamp = metadata
            .map(MetadataStamp::checked)
            .transpose()
            .map_err(io_failure)?;
        if let Some(stamp) = stamp {
            self.read.policy.validate(stamp).map_err(io_failure)?;
        }
        let same_incarnation = match (stamp, self.read.metadata) {
            (Some(actual), Some(expected)) => actual.same_incarnation(expected),
            (None, None) => true,
            _ => false,
        };
        if bytes != self.read.expected.as_deref() || !same_incarnation {
            return Err(corrupt());
        }
        Ok(())
    }

    /// Checks original ancestry, incarnation, policy and complete actual bytes.
    ///
    /// Native body reads use the existing blocking reader lane. A binding that
    /// declines that optional lane keeps the complete conservative scalar read.
    /// The caller separately refreshes selected and current authority.
    ///
    /// # Errors
    /// Refuses changed original ancestors, leaf policy, incarnation or body,
    /// invalid layout and unavailable actual reads.
    pub(crate) async fn revalidate<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        self.ancestors(fs).await?;
        if let Some(record) = fs
            .read_ordinary_record(crate::store::NativeOrdinaryRead::for_leaf(&self.read.path))
            .await
            .map_err(io_failure)?
        {
            match record.into_outcome() {
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::Present(bytes, metadata) => {
                    self.matches(Some(&bytes), Some(&metadata))?;
                }
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::Absent => self.matches(None, None)?,
                #[cfg(all(feature = "tokio", unix))]
                crate::store::OrdinaryReadOutcome::InvalidLayout => return Err(corrupt()),
            }
        } else {
            match fs.symlink_metadata(&self.read.path).await {
                Ok(before) => {
                    self.matches(self.read.expected.as_deref(), Some(&before))?;
                    let bytes = fs
                        .read_nofollow(&self.read.path)
                        .await
                        .map_err(io_failure)?;
                    let after = fs
                        .symlink_metadata(&self.read.path)
                        .await
                        .map_err(io_failure)?;
                    self.matches(Some(&bytes), Some(&after))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.matches(None, None)?
                }
                Err(error) => return Err(io_failure(error)),
            }
        }
        self.ancestors(fs).await
    }
}

impl Frame {
    /// Imports the original physical recipe without recapturing its ancestors.
    ///
    /// # Errors
    /// Refuses another configured owner or policy and changed original parents.
    pub(super) fn retained_payload_read(
        &mut self,
        retained: &RetainedPayloadRead,
    ) -> Result<(), StoreFailure> {
        let read = &retained.read;
        if read.owner != self.owner || read.policy != (FencePolicy::Payload { owner: self.owner }) {
            return Err(corrupt());
        }
        for parent in &read.parents {
            if self
                .parents
                .get(&parent.path)
                .is_some_and(|(stamp, owner)| {
                    *owner != read.owner || !stamp.same_incarnation(parent.stamp)
                })
            {
                return Err(corrupt());
            }
            self.parents
                .insert(parent.path.clone(), (parent.stamp, read.owner));
        }
        self.reads.push(ExactRead {
            path: read.path.clone(),
            expected: read.expected.clone(),
            identity: read.identity,
            metadata: read.metadata,
            policy: read.policy,
            owner: read.owner,
            parents: copy_parents(&read.parents),
        });
        Ok(())
    }
}
