//! Captures complete physical names and exact reads for retained publication.

use super::super::parent_paths;
use super::{
    BucketBinding, ExactRead, FencePolicy, Frame, LocalFs, MetadataStamp, NamedFence,
    NativeEffectFailure, NativeFsEffect, ParentFence, Path, PathBuf, Plan, SelectedObservation,
    StoreFailure, copy_parents, corrupt, io_failure, unsupported,
};
use crate::bucket::publication::receipts::RecordRead;
use std::{collections::BTreeMap, sync::Arc};
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::BackendBinding;

/// Preserves exact native binding bytes without a Unicode conversion.
fn native_path(bytes: Vec<u8>) -> Result<PathBuf, StoreFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        Err(unsupported())
    }
}

impl Frame {
    /// Captures every ordered ancestor under its independently configured owner.
    ///
    /// # Errors
    /// Rejects incomplete metadata batches, unsafe ancestry, changed captured
    /// incarnations, noncanonical paths, and unavailable metadata reads.
    pub(super) async fn parents<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        path: &Path,
        owner: u32,
    ) -> Result<Vec<ParentFence>, StoreFailure> {
        let paths = parent_paths(path).map_err(io_failure)?;
        let observations = fs
            .symlink_metadata_batch(&paths)
            .await
            .map_err(io_failure)?;
        if paths.len() != observations.len() {
            return Err(unsupported());
        }

        let mut result = Vec::with_capacity(paths.len());
        for (path, observation) in paths.into_iter().zip(observations) {
            let stamp =
                MetadataStamp::checked(&observation.map_err(io_failure)?).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor { owner }
                .validate(stamp)
                .map_err(io_failure)?;
            if self
                .parents
                .get(&path)
                .is_some_and(|(previous, _)| !stamp.same_incarnation(*previous))
            {
                return Err(corrupt());
            }
            self.parents.insert(path.clone(), (stamp, owner));
            result.push(ParentFence { path, stamp });
        }
        Ok(result)
    }

    /// Binds a checked name to its actual incarnation and retained descriptor.
    ///
    /// # Errors
    /// Rejects unsafe or changed ancestry and names, mismatched exclusions, and
    /// unavailable metadata or descriptor observations.
    pub(super) async fn name<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        path: PathBuf,
        identity: (u64, u64),
        policy: FencePolicy,
        descriptor: Option<usize>,
    ) -> Result<(), StoreFailure> {
        let parents = self.parents(fs, &path, policy.configured_owner()).await?;
        let metadata = fs.symlink_metadata(&path).await.map_err(io_failure)?;
        let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
        policy.validate(stamp).map_err(io_failure)?;
        if stamp.identity != identity {
            return Err(corrupt());
        }
        if let Some(index) = descriptor {
            let actual = self.exclusions.get(index).ok_or_else(corrupt)?;
            let opened = MetadataStamp::checked(&actual.file.metadata().map_err(io_failure)?)
                .map_err(io_failure)?;
            if !opened.same_incarnation(stamp) {
                return Err(corrupt());
            }
        }
        self.names.push(NamedFence {
            path,
            stamp,
            policy,
            parents,
            descriptor,
        });
        Ok(())
    }

    /// Captures a previously checked whole-value read and its physical preimage.
    ///
    /// # Errors
    /// Rejects unsafe or changed ancestors, invalid leaf protection, mismatched
    /// byte and metadata presence, and unavailable metadata reads.
    pub(super) async fn observed_read<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        path: &Path,
        bytes: Option<&[u8]>,
        metadata: Option<&std::fs::Metadata>,
        policy: FencePolicy,
    ) -> Result<(), StoreFailure> {
        let owner = policy.configured_owner();
        let parents = self.parents(fs, path, owner).await?;
        let stamp = metadata
            .map(MetadataStamp::checked)
            .transpose()
            .map_err(io_failure)?;
        if let Some(stamp) = stamp {
            policy.validate(stamp).map_err(io_failure)?;
        }
        if bytes.is_some() != stamp.is_some() {
            return Err(corrupt());
        }
        self.reads.push(ExactRead {
            path: path.to_owned(),
            expected: bytes.map(<[u8]>::to_vec),
            identity: stamp.map(|stamp| stamp.identity),
            metadata: stamp,
            policy,
            owner,
            parents,
        });
        Ok(())
    }

    /// Captures ordered present selected recipes using one complete parent batch.
    ///
    /// No metadata entry or duplicate is omitted. Each record's parent checks
    /// still precede its original leaf-policy and whole-value presence checks.
    async fn selected_reads<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        reads: &[RecordRead],
        root: &Path,
        control: &Path,
        owner: u32,
    ) -> Result<(), StoreFailure> {
        if reads.iter().any(|read| read.retained_payload().is_some()) {
            for read in reads {
                let policy = if read.path().starts_with(control) {
                    FencePolicy::ProtectedRecord { owner }
                } else if read.path().starts_with(root) {
                    FencePolicy::Payload { owner }
                } else {
                    return Err(corrupt());
                };
                let retained = read.retained_payload().ok_or_else(unsupported)?;
                self.retained_record_read(retained, policy)?;
            }
            return Ok(());
        }
        let mut paths = Vec::new();
        let mut lengths = Vec::with_capacity(reads.len());
        for read in reads {
            let parents = parent_paths(read.path()).map_err(io_failure)?;
            lengths.push(parents.len());
            paths.extend(parents);
        }
        let observations = fs
            .symlink_metadata_batch(&paths)
            .await
            .map_err(io_failure)?;
        if observations.len() != paths.len() {
            return Err(unsupported());
        }
        let mut entries = paths.into_iter().zip(observations);
        for (read, length) in reads.iter().zip(lengths) {
            let policy = if read.path().starts_with(control) {
                FencePolicy::ProtectedRecord { owner }
            } else if read.path().starts_with(root) {
                FencePolicy::Payload { owner }
            } else {
                return Err(corrupt());
            };
            let mut parents = Vec::with_capacity(length);
            for (path, observation) in entries.by_ref().take(length) {
                let stamp = MetadataStamp::checked(&observation.map_err(io_failure)?)
                    .map_err(io_failure)?;
                FencePolicy::ProtectedAncestor { owner }
                    .validate(stamp)
                    .map_err(io_failure)?;
                if self
                    .parents
                    .get(&path)
                    .is_some_and(|(previous, _)| !stamp.same_incarnation(*previous))
                {
                    return Err(corrupt());
                }
                self.parents.insert(path.clone(), (stamp, owner));
                parents.push(ParentFence { path, stamp });
            }
            let stamp = read
                .metadata()
                .map(MetadataStamp::checked)
                .transpose()
                .map_err(io_failure)?;
            if let Some(stamp) = stamp {
                policy.validate(stamp).map_err(io_failure)?;
            }
            if read.bytes().is_some() != stamp.is_some() {
                return Err(corrupt());
            }
            self.reads.push(ExactRead {
                path: read.path().to_owned(),
                expected: read.bytes().map(<[u8]>::to_vec),
                identity: stamp.map(|stamp| stamp.identity),
                metadata: stamp,
                policy,
                owner,
                parents,
            });
        }
        Ok(())
    }

    /// Captures actual exact bytes with leaf and complete parent observations.
    ///
    /// # Errors
    /// Rejects unsafe or changed nodes and ancestors and unavailable reads.
    /// An exact missing leaf or parent returns explicit absence.
    pub(super) async fn actual_read<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        path: &Path,
        policy: FencePolicy,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        // The captured parent list and both leaf observations are retained in
        // the worker. These bytes choose no logical authority; the sealed
        // transition separately fixes whether the name may be mutated.
        // A missing parent proves absence of the leaf. Retain that exact
        // missing name with every earlier checked ancestor, so creating it in
        // another worker invalidates the same complete projection.
        let owner = policy.configured_owner();
        for parent in parent_paths(path).map_err(io_failure)? {
            match fs.symlink_metadata(&parent).await {
                Ok(metadata) => {
                    let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
                    FencePolicy::ProtectedAncestor { owner }
                        .validate(stamp)
                        .map_err(io_failure)?;
                    if self
                        .parents
                        .get(&parent)
                        .is_some_and(|(previous, _)| !stamp.same_incarnation(*previous))
                    {
                        return Err(corrupt());
                    }
                    self.parents.insert(parent, (stamp, owner));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.observed_read(fs, &parent, None, None, policy).await?;
                    return Ok(None);
                }
                Err(error) => return Err(io_failure(error)),
            }
        }
        let before = match fs.symlink_metadata(path).await {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_failure(error)),
        };
        let bytes = match &before {
            Some(metadata) => {
                policy
                    .validate(MetadataStamp::checked(metadata).map_err(io_failure)?)
                    .map_err(io_failure)?;
                let bytes = fs.read_nofollow(path).await.map_err(io_failure)?;
                let after = fs.symlink_metadata(path).await.map_err(io_failure)?;
                if !MetadataStamp::checked(&after)
                    .map_err(io_failure)?
                    .same_incarnation(MetadataStamp::checked(metadata).map_err(io_failure)?)
                {
                    return Err(corrupt());
                }
                Some(bytes)
            }
            None => None,
        };
        self.observed_read(fs, path, bytes.as_deref(), before.as_ref(), policy)
            .await?;
        Ok(bytes)
    }

    /// Owns the complete refreshed frame for one privately fixed command.
    ///
    /// # Errors
    /// Rejects malformed or incomplete captured parent projections.
    pub(super) fn effect(&self, plan: Plan) -> Result<NativeFsEffect, StoreFailure> {
        // Repeated projection installs can capture the same name many times.
        // Coalesce only identical predicates; distinct policy, descriptor,
        // ancestry or incarnation observations still reach every native check.
        let mut names = Vec::new();
        let mut recorded_names: BTreeMap<&Path, Vec<&NamedFence>> = BTreeMap::new();
        for name in &self.names {
            let recorded = recorded_names.entry(name.path.as_path()).or_default();
            if recorded.contains(&name) {
                continue;
            }
            recorded.push(name);
            names.push(NamedFence {
                path: name.path.clone(),
                stamp: name.stamp,
                policy: name.policy,
                parents: copy_parents(&name.parents),
                descriptor: name.descriptor,
            });
        }

        let mut preimages = Vec::new();
        let mut recorded_reads: BTreeMap<&Path, Vec<&ExactRead>> = BTreeMap::new();
        for read in &self.reads {
            let recorded = recorded_reads.entry(read.path.as_path()).or_default();
            if recorded.contains(&read) {
                continue;
            }
            recorded.push(read);
            preimages.push(ExactRead {
                path: read.path.clone(),
                expected: read.expected.clone(),
                identity: read.identity,
                metadata: read.metadata,
                policy: read.policy,
                owner: read.owner,
                parents: copy_parents(&read.parents),
            });
        }
        // Complete parent names also participate in the executor's final
        // fence after all exact reads. Unchanged leaf bytes cannot hide an
        // ancestor replacement or permission change during those reads.
        for (path, (stamp, owner)) in &self.parents {
            if path == Path::new("/") {
                continue;
            }
            let parents = parent_paths(path)
                .map_err(io_failure)?
                .into_iter()
                .map(|parent| {
                    let (stamp, _) = self.parents.get(&parent).ok_or_else(corrupt)?;
                    Ok(ParentFence {
                        path: parent,
                        stamp: *stamp,
                    })
                })
                .collect::<Result<_, StoreFailure>>()?;
            names.push(NamedFence {
                path: path.clone(),
                stamp: *stamp,
                policy: FencePolicy::ProtectedAncestor { owner: *owner },
                parents,
                descriptor: None,
            });
        }
        Ok(NativeFsEffect {
            exclusions: Arc::clone(&self.exclusions),
            names,
            preimages,
            final_check: self.final_check.clone(),
            plan,
            #[cfg(test)]
            faults: Vec::new(),
            #[cfg(all(test, feature = "tokio"))]
            gates: Vec::new(),
        })
    }

    /// Submits a privately fixed command with owned exclusions and current checks.
    ///
    /// # Errors
    /// Preserves genuine current-check rejection and unsupported or failed
    /// native effects. Failures after submission can be indeterminate.
    pub(super) async fn execute<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        plan: Plan,
    ) -> Result<(), StoreFailure> {
        fs.execute_retained_effect(self.effect(plan)?)
            .await
            .map_err(|error| match error {
                NativeEffectFailure::Rejected(error) => error,
                NativeEffectFailure::Io(error) => io_failure(error),
            })
    }

    /// Captures the physical projection of an actual held selected observation.
    ///
    /// # Errors
    /// Rejects unavailable native paths, mismatched physical bindings, unsafe
    /// retained read metadata or ancestry, and unavailable observations.
    pub(super) async fn observation<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        observed: &SelectedObservation<'_>,
        descriptor: usize,
    ) -> Result<PathBuf, StoreFailure> {
        let owner = observed.configured_operator_uid();
        let BackendBinding::Local {
            root,
            root_device,
            root_inode,
            coordination_device,
            coordination_inode,
        } = observed.state().binding.clone()
        else {
            return Err(unsupported());
        };
        let root = native_path(root)?;
        if root != observed.identity().root()
            || (
                (root_device, root_inode),
                (coordination_device, coordination_inode),
            ) != observed.identity().physical_identity()
        {
            return Err(corrupt());
        }
        self.name(
            fs,
            root.clone(),
            (root_device, root_inode),
            FencePolicy::NamespaceDirectory { owner },
            None,
        )
        .await?;
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| corrupt())?;
        self.name(
            fs,
            root.join(key.lock_name()),
            (coordination_device, coordination_inode),
            FencePolicy::NamespaceCoordination { owner },
            Some(descriptor),
        )
        .await?;

        let registration = observed
            .physical_reads()
            .first()
            .filter(|read| {
                read.path()
                    .file_name()
                    .is_some_and(|name| name == "backend-registration.cbor")
            })
            .ok_or_else(corrupt)?;
        let control = registration.path().parent().ok_or_else(corrupt)?.to_owned();
        self.name(
            fs,
            control.clone(),
            observed.control_identity(),
            FencePolicy::PrivateControlDirectory { owner },
            None,
        )
        .await?;
        let reads = observed.physical_reads();
        let mut position = 0;
        while position < reads.len() {
            let start = position;
            while position < reads.len() && reads[position].bytes().is_some() {
                position += 1;
            }
            if start != position {
                self.selected_reads(fs, &reads[start..position], &root, &control, owner)
                    .await?;
            }
            if let Some(read) = reads.get(position) {
                let policy = if read.path().starts_with(&control) {
                    FencePolicy::ProtectedRecord { owner }
                } else if read.path().starts_with(&root) {
                    FencePolicy::Payload { owner }
                } else {
                    return Err(corrupt());
                };
                if let Some(retained) = read.retained_payload() {
                    read.revalidate_retained(fs).await?;
                    self.retained_record_read(retained, policy)?;
                } else if self.actual_read(fs, read.path(), policy).await?.is_some() {
                    return Err(corrupt());
                }
                position += 1;
            }
        }
        Ok(control)
    }
}
