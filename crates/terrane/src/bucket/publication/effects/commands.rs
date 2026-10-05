//! Submits fixed private staging and projection commands under the retained frame.

use super::{
    BTreeMap, BucketBinding, FencePolicy, Frame, LocalFs, MetadataStamp, Mutability, Path, Plan,
    PortableCurrent, StoreErrorKind, StoreFailure, corrupt, io_failure, unsupported,
};
use terrane_core::bucket::BucketKey;

impl Frame {
    /// Checks or privately creates a fixed staging or projection directory.
    ///
    /// # Errors
    /// Rejects unsafe or changed directories and ancestors, denied current
    /// checks, and unsupported or failed native creation and durability.
    pub(super) async fn directory<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        path: &Path,
        policy: FencePolicy,
    ) -> Result<(), StoreFailure> {
        let _ = self.parents(fs, path, policy.configured_owner()).await?;
        match fs.symlink_metadata(path).await {
            Ok(metadata) => {
                let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
                self.name(fs, path.to_owned(), stamp.identity, policy, None)
                    .await
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.observed_read(
                    fs,
                    path,
                    None,
                    None,
                    FencePolicy::ProtectedRecord { owner: self.owner },
                )
                .await?;
                self.execute(
                    fs,
                    Plan::CreateDirectoryNew {
                        path: path.to_owned(),
                    },
                )
                .await?;
                self.reads.retain(|read| read.path != path);
                let metadata = fs.symlink_metadata(path).await.map_err(io_failure)?;
                let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
                self.name(fs, path.to_owned(), stamp.identity, policy, None)
                    .await
            }
            Err(error) => Err(io_failure(error)),
        }
    }

    /// Installs fixed canonical bytes through private staging and retained rename.
    ///
    /// # Errors
    /// Rejects conflicting immutable or create-once values, changed preimages,
    /// unsafe nodes, denied current checks, and unavailable native durability.
    pub(super) async fn install<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        root: &Path,
        key: &str,
        bytes: &[u8],
        policy: FencePolicy,
        mutability: Mutability,
    ) -> Result<(), StoreFailure> {
        // These arguments are private derived data. Closed checked and backend
        // entry points choose the registered key, bytes and mutation kind.
        let mut parent = root.to_owned();
        let directory_policy = match policy {
            FencePolicy::ProtectedRecord { owner } => {
                FencePolicy::PrivateControlDirectory { owner }
            }
            FencePolicy::Payload { owner } => FencePolicy::NamespaceDirectory { owner },
            _ => return Err(corrupt()),
        };
        for part in Path::new(key).parent().ok_or_else(corrupt)?.components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err(corrupt());
            }
            parent.push(part);
            self.directory(fs, &parent, directory_policy).await?;
        }
        let target = root.join(key);
        let existing = self.actual_read(fs, &target, policy).await?;
        if mutability == Mutability::CreateOnce && existing.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        if existing.as_deref() == Some(bytes) {
            return Ok(());
        }
        if existing.is_some() && mutability != Mutability::CompareAndSwap {
            return Err(corrupt());
        }

        let entropy = fs.random_bytes(16).await.map_err(io_failure)?;
        if entropy.len() != 16 {
            return Err(unsupported());
        }
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = parent.join(format!(".terrane-tmp:{suffix}"));
        if self.actual_read(fs, &temporary, policy).await?.is_some() {
            return Err(corrupt());
        }
        self.execute(
            fs,
            Plan::WriteNew {
                path: temporary.clone(),
                bytes: bytes.to_vec(),
            },
        )
        .await?;
        self.reads.retain(|read| read.path != temporary);
        if self.actual_read(fs, &temporary, policy).await?.as_deref() != Some(bytes) {
            return Err(corrupt());
        }
        self.execute(
            fs,
            Plan::SyncFile {
                path: temporary.clone(),
            },
        )
        .await?;
        let plan = if existing.is_some() {
            Plan::Rename {
                from: temporary.clone(),
                to: target.clone(),
            }
        } else {
            Plan::RenameNoReplace {
                from: temporary.clone(),
                to: target.clone(),
            }
        };
        self.execute(fs, plan).await?;

        // Rebind only names changed by this fixed command after durable worker
        // acknowledgment. Every other selected and consumed preimage survives.
        self.reads
            .retain(|read| read.path != temporary && read.path != target);
        if self.actual_read(fs, &target, policy).await?.as_deref() != Some(bytes) {
            return Err(corrupt());
        }
        Ok(())
    }

    /// Durably projects the selected portable pointer before every logical cache.
    ///
    /// # Errors
    /// Rejects malformed keys, conflicting immutable values, changed physical
    /// preimages, denied current checks, and unavailable native durability.
    pub(super) async fn project<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        root: &Path,
        pointer: &PortableCurrent,
        logical: &BTreeMap<String, Option<Vec<u8>>>,
    ) -> Result<(), StoreFailure> {
        // Portable recovery becomes durable before any materialized logical
        // cache. All repair data comes from this complete selected projection.
        self.install(
            fs,
            root,
            "publication/PORTABLE",
            &pointer.encode().map_err(|_| corrupt())?,
            FencePolicy::Payload { owner: self.owner },
            Mutability::CompareAndSwap,
        )
        .await?;
        for (key, value) in logical {
            let parsed = BucketKey::parse(key).map_err(|_| corrupt())?;
            match value {
                Some(bytes) => {
                    self.install(
                        fs,
                        root,
                        key,
                        bytes,
                        FencePolicy::Payload { owner: self.owner },
                        match parsed.mutability() {
                            Mutability::CreateOnce => Mutability::Immutable,
                            mutability => mutability,
                        },
                    )
                    .await?;
                }
                None if parsed.mutability() == Mutability::CompareAndSwap => {
                    let path = root.join(key);
                    if self
                        .actual_read(fs, &path, FencePolicy::Payload { owner: self.owner })
                        .await?
                        .is_some()
                    {
                        self.execute(fs, Plan::Remove { path: path.clone() })
                            .await?;
                        self.reads.retain(|read| read.path != path);
                        self.observed_read(
                            fs,
                            &path,
                            None,
                            None,
                            FencePolicy::Payload { owner: self.owner },
                        )
                        .await?;
                    }
                }
                None => {}
            }
        }
        Ok(())
    }
}
