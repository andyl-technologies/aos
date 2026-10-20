//! Submits fixed private staging and projection commands under the retained frame.

use super::{
    BTreeMap, BucketBinding, CompletedWrite, FencePolicy, Frame, LocalFs, MetadataStamp,
    Mutability, Path, Plan, PortableCurrent, StoreErrorKind, StoreFailure, corrupt, io_failure,
    unsupported,
};
use std::collections::BTreeSet;
use terrane_format::bucket::BucketKey;

// Bound the additional future staging/target preimages in each complete native
// check. Earlier acknowledged targets retain complete physical predicates.
const MAX_IMMUTABLE_INSTALLS_PER_COHORT: usize = 8;

/// Aggregates one bounded batch's attempted work using process time only.
#[cfg(test)]
struct BatchTimings {
    trace: crate::ref_advance::NativeTrace,
    started: Option<crate::diagnostic_clock::Tick>,
    phase: usize,
    durations: [std::time::Duration; 3],
    rows: usize,
    installs: usize,
    recaptures: usize,
}

#[cfg(test)]
impl BatchTimings {
    fn new(root: &Path, rows: usize) -> Self {
        Self {
            trace: crate::ref_advance::NativeTrace::new(root, "raw-immutable-batch-aggregate"),
            started: std::env::var_os("TERRANE_REF_PHASE_TRACE")
                .is_some()
                .then(crate::diagnostic_clock::tick),
            phase: 0,
            durations: [std::time::Duration::ZERO; 3],
            rows,
            installs: 0,
            recaptures: 0,
        }
    }

    fn phase(&mut self, next: usize) {
        if let Some(started) = self.started {
            self.durations[self.phase] += crate::diagnostic_clock::elapsed(started);
            self.started = Some(crate::diagnostic_clock::tick());
        }
        self.phase = next;
    }
}

#[cfg(test)]
impl Drop for BatchTimings {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        self.durations[self.phase] += crate::diagnostic_clock::elapsed(started);
        self.trace.mark(&format!(
            "aggregate preparation={:?} ack-await={:?} recapture={:?} rows={} prepared-installs={} recapture-attempts={}",
            self.durations[0], self.durations[1], self.durations[2],
            self.rows, self.installs, self.recaptures,
        ));
    }
}

impl Frame {
    /// Completely verifies durable staged payloads before selecting a commit slot.
    ///
    /// # Errors
    /// Rejects any changed input/output body, physical predicate or current
    /// authority, and refuses failed actual directory synchronization.
    pub(super) async fn verify_staged_payloads<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        root: &Path,
    ) -> Result<(), StoreFailure> {
        self.execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await
    }

    /// Reports actual newly created targets after every cohort and recapture.
    ///
    /// This result is ordinary provenance data, never permission or durability
    /// authority. Equal preexisting bodies contribute no created target.
    ///
    /// # Errors
    /// Preserves every install failure and returns no successful partial set.
    pub(super) async fn install_immutable_cohort_tracked<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        root: &Path,
        rows: &[(&str, &[u8])],
        candidates: Option<super::super::immutable_cohort::scope::Candidates>,
    ) -> Result<BTreeSet<std::path::PathBuf>, StoreFailure> {
        let mut staging_names = BTreeSet::new();
        let mut created = BTreeSet::new();
        for batch in rows.chunks(MAX_IMMUTABLE_INSTALLS_PER_COHORT) {
            created.extend(
                self.install_immutable_batch(
                    fs,
                    root,
                    batch,
                    &mut staging_names,
                    candidates
                        .as_ref()
                        .map(|candidates| candidates.cohort(&created)),
                )
                .await?,
            );
        }
        Ok(created)
    }

    /// Acknowledges and actually recaptures one fixed batch before the next.
    async fn install_immutable_batch<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        root: &Path,
        rows: &[(&str, &[u8])],
        staging_names: &mut BTreeSet<std::path::PathBuf>,
        scope: Option<super::super::immutable_cohort::scope::Scope>,
    ) -> Result<BTreeSet<std::path::PathBuf>, StoreFailure> {
        use super::super::immutable_cohort;

        #[cfg(test)]
        let mut timings = BatchTimings::new(root, rows.len());
        let policy = FencePolicy::Payload { owner: self.owner };
        let mut installs = Vec::new();
        let mut completed = Vec::new();
        let mut created = BTreeSet::new();
        for &(key, bytes) in rows {
            let parsed = BucketKey::parse(key).map_err(|_| corrupt())?;
            if parsed.mutability() != Mutability::Immutable {
                return Err(corrupt());
            }
            let mut parent = root.to_owned();
            for part in Path::new(key).parent().ok_or_else(corrupt)?.components() {
                if !matches!(part, std::path::Component::Normal(_)) {
                    return Err(corrupt());
                }
                parent.push(part);
                self.directory(
                    fs,
                    &parent,
                    FencePolicy::NamespaceDirectory { owner: self.owner },
                )
                .await?;
            }
            let target = root.join(key);
            let existing = self.actual_read(fs, &target, policy).await?;
            if existing.as_deref() == Some(bytes) {
                continue;
            }
            if existing.is_some() {
                return Err(corrupt());
            }

            let entropy = fs.random_bytes(16).await.map_err(io_failure)?;
            if entropy.len() != 16 {
                return Err(unsupported());
            }
            let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
            let temporary = parent.join(format!(".terrane-tmp:{suffix}"));
            // This set records only uniqueness, never successful absence or
            // physical authority. Every new staging path is freshly observed.
            if !staging_names.insert(temporary.clone())
                || self.actual_read(fs, &temporary, policy).await?.is_some()
            {
                return Err(corrupt());
            }
            completed.push((temporary.clone(), target.clone(), bytes));
            installs.push(immutable_cohort::Install {
                temporary,
                target,
                bytes: bytes.to_vec(),
                policy,
            });
        }
        if installs.is_empty() {
            return Ok(created);
        }

        #[cfg(test)]
        {
            timings.installs = installs.len();
        }
        let (plan, receipt) = match scope {
            Some(scope) => immutable_cohort::request_scoped(installs, Some(scope)),
            None => immutable_cohort::request(installs),
        };
        #[cfg(test)]
        timings.phase(1);
        self.execute(fs, plan).await?;
        receipt.take().map_err(super::native_failure)?;
        #[cfg(test)]
        timings.phase(2);
        for (temporary, target, bytes) in completed {
            // Only returned native ACK permits rebinding the caller's frame.
            // Independently read every final target; never assume successful
            // installation from an adapter's callback or worker plan alone.
            self.reads
                .retain(|read| read.path != temporary && read.path != target);
            #[cfg(test)]
            {
                timings.recaptures += 1;
            }
            if self.actual_read(fs, &target, policy).await?.as_deref() != Some(bytes) {
                return Err(corrupt());
            }
            if let Some(writes) = &mut self.writes {
                writes.records.insert(
                    target.clone(),
                    CompletedWrite {
                        root: root.to_owned(),
                        policy,
                        expected: Some(bytes.to_vec()),
                    },
                );
            }
            created.insert(target);
        }
        Ok(created)
    }

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
        if let Some(writes) = &mut self.writes {
            writes.records.insert(
                target,
                CompletedWrite {
                    root: root.to_owned(),
                    policy,
                    expected: Some(bytes.to_vec()),
                },
            );
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
                        if let Some(writes) = &mut self.writes {
                            writes.records.insert(
                                path,
                                CompletedWrite {
                                    root: root.to_owned(),
                                    policy: FencePolicy::Payload { owner: self.owner },
                                    expected: None,
                                },
                            );
                        }
                    }
                }
                None => {}
            }
        }
        Ok(())
    }
}
