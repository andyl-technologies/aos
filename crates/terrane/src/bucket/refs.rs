//! Implements whole-record ref CAS and create-once ordered reflogs.

use super::{BucketBinding, FileBucket, files};
use crate::store::{
    Clock, ContentValidator, CorruptSubject, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    RefWatch, StoreErrorKind, StoreFailure,
};
use terrane_core::bucket::{BucketCapabilities, BucketKey};
use terrane_core::refs::{RefClass, RefLogRecord, RefName, RefRecord};

fn ref_key(name: &str, version: u64) -> Result<BucketKey, StoreFailure> {
    if !name.starts_with("refs/") {
        return Err(files::malformed());
    }
    let key = if version == 1 {
        BucketKey::parse(name)
    } else {
        BucketKey::ref_record(name)
    };
    key.map_err(|_| files::malformed())
}

fn corrupt(name: &str) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::RefName(
        name.into(),
    )))
}

fn branch(name: &str) -> Result<bool, StoreFailure> {
    let name = RefName::parse(name).map_err(|_| files::malformed())?;
    Ok(matches!(
        name.class(),
        RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
    ))
}

fn log_key(name: &str, record: &RefRecord, version: u64) -> Result<BucketKey, StoreFailure> {
    match &record.candidate_id {
        Some(candidate) => BucketKey::reflog_candidate(name, record.seq, candidate),
        None if version == 1 => BucketKey::legacy_reflog(name, record.seq),
        None => BucketKey::reflog(name, record.seq),
    }
    .map_err(|_| files::malformed())
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Returns the authoritative complete ref-name inventory.
    ///
    /// Names may survive a losing first write or deletion. Completeness is
    /// never inferred from directory listing or from individually read refs.
    ///
    /// # Errors
    /// Returns `Unsupported` for an unmigrated legacy inventory, corruption for
    /// invalid capability bytes, and the configured binding's storage failures.
    pub async fn ref_names(&self) -> Result<Vec<String>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let bytes = self
            .logical_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let capabilities =
            BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
        self.validate_layout(&capabilities)?;
        self.ensure_layout().await?;
        capabilities
            .ref_names
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))
    }

    async fn read_ref(&self, key: &BucketKey) -> Result<Option<RefRecord>, StoreFailure> {
        self.ensure_layout().await?;
        let public_name = key.as_str().strip_suffix(":record").unwrap_or(key.as_str());
        let record = self
            .logical_optional(key)
            .await?
            .map(|bytes| RefRecord::decode(&bytes).map_err(|_| corrupt(key.as_str())))
            .transpose()?;
        if record.is_some() {
            // A visible first head is preceded by its durable registration.
            // Read the head before capabilities so concurrent registration
            // cannot produce a spurious missing-name report.
            let cap_key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
            let bytes = self
                .logical_optional(&cap_key)
                .await?
                .ok_or_else(files::layout_corrupt)?;
            let capabilities =
                BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
            self.validate_layout(&capabilities)?;
            if capabilities.ref_names.as_ref().is_some_and(|names| {
                names
                    .binary_search_by(|name| name.as_bytes().cmp(public_name.as_bytes()))
                    .is_err()
            }) {
                return Err(corrupt(key.as_str()));
            }
        }
        self.ensure_layout().await?;
        Ok(record)
    }

    async fn read_log_observed(
        &self,
        name: &str,
        selected: &RefRecord,
        retain_original: bool,
    ) -> Result<(RefLogRecord, super::publication::receipts::RecordRead), StoreFailure> {
        let key = log_key(name, selected, self.inner.access.version())?;
        let read = if retain_original {
            self.read_optional_retained(&key).await?
        } else {
            self.read_optional_observed(&key).await?
        };
        let bytes = read.bytes().ok_or_else(|| corrupt(name))?;
        let log = RefLogRecord::decode(bytes).map_err(|_| corrupt(name))?;
        if &log.record != selected {
            return Err(corrupt(name));
        }
        Ok((log, read))
    }

    // Each selected record identifies its exact predecessor. Legacy numbered
    // records are traversed only after a selected legacy endpoint is reached.
    /// Returns the complete exact committed history for a selected endpoint.
    ///
    /// # Errors
    /// Rejects invalid names, missing or malformed logs, incompatible whole
    /// predecessors and successors, and unavailable exact reads.
    pub(in crate::bucket) async fn committed_logs(
        &self,
        name: &str,
        selected: RefRecord,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.committed_logs_observed(name, selected, &mut Vec::new())
            .await
    }

    /// Retains every exact history read while validating the complete chain.
    ///
    /// Duplicate present reads remain in operation order; the resulting data
    /// grants no selected or checked publication authority.
    ///
    /// # Errors
    /// Rejects invalid names, missing or malformed logs, incompatible whole
    /// predecessors and successors, and unavailable exact reads.
    pub(in crate::bucket) async fn committed_logs_observed(
        &self,
        name: &str,
        selected: RefRecord,
        reads: &mut Vec<super::publication::receipts::RecordRead>,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.committed_logs_observed_mode(name, selected, reads, false)
            .await
    }

    /// Preserves original physical recipes for every consumed committed log.
    ///
    /// # Errors
    /// Preserves all chain failures and refuses changed or unsafe original reads.
    pub(in crate::bucket) async fn committed_logs_observed_retained(
        &self,
        name: &str,
        selected: RefRecord,
        reads: &mut Vec<super::publication::receipts::RecordRead>,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.committed_logs_observed_mode(name, selected, reads, true)
            .await
    }

    async fn committed_logs_observed_mode(
        &self,
        name: &str,
        mut selected: RefRecord,
        reads: &mut Vec<super::publication::receipts::RecordRead>,
        retain_original: bool,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        let mut records = Vec::new();
        loop {
            let (log, read) = self
                .read_log_observed(name, &selected, retain_original)
                .await?;
            reads.push(read);
            let previous = if selected.candidate_id.is_some() {
                log.selected_previous().map_err(|_| corrupt(name))?.cloned()
            } else if selected.seq > 1 {
                let key = BucketKey::reflog(name, selected.seq - 1).map_err(|_| corrupt(name))?;
                let read = if retain_original {
                    self.read_optional_retained(&key).await?
                } else {
                    self.read_optional_observed(&key).await?
                };
                let bytes = read.bytes().ok_or_else(|| corrupt(name))?;
                let previous = RefLogRecord::decode(bytes)
                    .map_err(|_| corrupt(name))?
                    .record;
                RefRecord::validate_successor(Some(&previous), &selected)
                    .map_err(|_| corrupt(name))?;
                if previous.candidate_id.is_some() || log.previous_commit != Some(previous.commit) {
                    return Err(corrupt(name));
                }
                reads.push(read);
                Some(previous)
            } else {
                RefRecord::validate_successor(None, &selected).map_err(|_| corrupt(name))?;
                if log.previous_commit.is_some() {
                    return Err(corrupt(name));
                }
                None
            };
            records.push(log);
            match previous {
                Some(previous) => selected = previous,
                None => break,
            }
        }
        records.reverse();
        Ok(records)
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Runs the ordinary ref_get path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn ref_get_locked(
        &self,
        name: &str,
    ) -> Result<Option<RefRecord>, StoreFailure> {
        let key = ref_key(name, self.inner.access.version())?;
        self.read_ref(&key).await
    }

    /// Runs the ordinary ref_log_read path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn ref_log_read_locked(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        let key = ref_key(name, self.inner.access.version())?;
        if !branch(name)? {
            return Err(files::malformed());
        }
        let current = if let Some(current) = self.read_ref(&key).await? {
            current
        } else if self.inner.access.read_only() {
            return Ok(Vec::new());
        } else {
            let selected = self.selected_publication_locked().await?;
            match selected
                .state
                .branches
                .iter()
                .find(|row| row.name == name)
                .map(|row| &row.selection)
            {
                Some(terrane_core::gc::publication::CommittedSelection::Selected(record)) => {
                    record.as_ref().clone()
                }
                Some(terrane_core::gc::publication::CommittedSelection::Unknown) => {
                    return Err(StoreFailure::new(StoreErrorKind::Unsupported));
                }
                _ => return Ok(Vec::new()),
            }
        };
        let from_seq = from_seq.max(1);
        if from_seq > current.seq {
            return Ok(Vec::new());
        }
        let records = self.committed_logs(name, current).await?;
        self.ensure_layout().await?;
        Ok(records
            .into_iter()
            .filter(|log| log.record.seq >= from_seq)
            .collect())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    RefStore for FileBucket<F, C, V>
{
    type Watch = FileRefWatch<F, C, V>;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        self.ref_get_locked(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        ref_key(name, self.inner.access.version())?;
        let holder = super::held::SingleHeld::acquire(self).await?;
        holder.destination().ref_cas(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        log_key(name, &record.record, self.inner.access.version())?;
        if record.record.seq != seq {
            return Err(files::malformed());
        }
        record.encode().map_err(|_| files::malformed())?;

        let holder = super::held::SingleHeld::acquire(self).await?;
        holder.destination().ref_log_append(name, seq, record).await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        ref_key(name, self.inner.access.version())?;
        if !branch(name)? {
            return Err(files::malformed());
        }

        let _guard = self.read_exclusion().await?;
        self.ref_log_read_locked(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        ref_key(name, self.inner.access.version())?;
        if !branch(name)? {
            return Err(files::malformed());
        }
        Ok(FileRefWatch {
            bucket: self.clone(),
            name: name.into(),
            next: Some(from_seq.max(1)),
        })
    }
}

/// Reads ordered reflog records from a live file bucket.
///
/// Every call follows the selected predecessor chain through exact registered keys.
/// Records become visible only after the authoritative ref confirms their
/// sequence. Idle reads wait through the configured clock binding.
pub struct FileRefWatch<F, C, V> {
    bucket: FileBucket<F, C, V>,
    name: String,
    next: Option<u64>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    RefWatch for FileRefWatch<F, C, V>
{
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        let Some(seq) = self.next else {
            return Ok(None);
        };
        loop {
            let records = self.bucket.ref_log_read(&self.name, seq).await?;
            if let Some(record) = records.into_iter().next() {
                self.next = seq.checked_add(1);
                return Ok(Some(record));
            }

            self.bucket
                .inner
                .clock
                .sleep(std::time::Duration::from_millis(10))
                .await
                .map_err(files::io_failure)?;
        }
    }
}
