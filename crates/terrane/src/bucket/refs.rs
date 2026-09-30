//! Implements whole-record ref CAS and create-once ordered reflogs.

use super::{BucketBinding, FileBucket, files};
use crate::store::{
    Clock, ContentValidator, CorruptSubject, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    RefWatch, StoreErrorKind, StoreFailure,
};
use terrane_core::bucket::{BucketCapabilities, BucketKey, Mutability};
use terrane_core::refs::{RefClass, RefLogRecord, RefName, RefRecord};

fn ref_key(name: &str) -> Result<BucketKey, StoreFailure> {
    if !name.starts_with("refs/") {
        return Err(files::malformed());
    }
    BucketKey::parse(name).map_err(|_| files::malformed())
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

fn log_key(name: &str, record: &RefRecord) -> Result<BucketKey, StoreFailure> {
    match &record.candidate_id {
        Some(candidate) => BucketKey::reflog_candidate(name, record.seq, candidate),
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
        let _guard = self.exclusive().await?;
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let bytes = self
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let capabilities =
            BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
        if capabilities.profile != self.profile() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        capabilities
            .ref_names
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))
    }

    // Registration precedes the head installation while retaining the same
    // exclusion guard, so any possibly applied ref has durable inventory reachability.
    async fn register_ref_name(
        &self,
        name: &str,
        already_exists: bool,
    ) -> Result<(), StoreFailure> {
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let bytes = self
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let mut capabilities =
            BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
        if capabilities.profile != self.profile() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let Some(names) = capabilities.ref_names.as_mut() else {
            return if already_exists {
                Ok(())
            } else {
                Err(StoreFailure::new(StoreErrorKind::Unsupported))
            };
        };
        match names.binary_search_by(|existing| existing.as_bytes().cmp(name.as_bytes())) {
            Ok(_) => Ok(()),
            Err(_) if already_exists => Err(files::layout_corrupt()),
            Err(position) => {
                names.insert(position, name.into());
                let replacement = capabilities.encode().map_err(|_| files::layout_corrupt())?;
                if !self
                    .replace_conditionally(&key, Some(&bytes), &replacement)
                    .await?
                {
                    return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                        retry_after: None,
                    }));
                }
                Ok(())
            }
        }
    }

    async fn read_ref(&self, key: &BucketKey) -> Result<Option<RefRecord>, StoreFailure> {
        let record = self
            .read_optional(key)
            .await?
            .map(|bytes| RefRecord::decode(&bytes).map_err(|_| corrupt(key.as_str())))
            .transpose()?;
        if record.is_some() {
            // A visible first head is preceded by its durable registration.
            // Read the head before capabilities so concurrent registration
            // cannot produce a spurious missing-name report.
            let cap_key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
            let bytes = self
                .read_optional(&cap_key)
                .await?
                .ok_or_else(files::layout_corrupt)?;
            let capabilities =
                BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
            if capabilities.profile != self.profile() {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
            if capabilities.ref_names.as_ref().is_some_and(|names| {
                names
                    .binary_search_by(|name| name.as_bytes().cmp(key.as_str().as_bytes()))
                    .is_err()
            }) {
                return Err(corrupt(key.as_str()));
            }
        }
        Ok(record)
    }

    async fn read_log(
        &self,
        name: &str,
        selected: &RefRecord,
    ) -> Result<RefLogRecord, StoreFailure> {
        let key = log_key(name, selected)?;
        let bytes = self
            .read_optional(&key)
            .await?
            .ok_or_else(|| corrupt(name))?;
        let log = RefLogRecord::decode(&bytes).map_err(|_| corrupt(name))?;
        if &log.record != selected {
            return Err(corrupt(name));
        }
        Ok(log)
    }

    // Each selected record identifies its exact predecessor. Legacy numbered
    // records are traversed only after a selected legacy endpoint is reached.
    async fn committed_logs(
        &self,
        name: &str,
        mut selected: RefRecord,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        let mut records = Vec::new();
        loop {
            let log = self.read_log(name, &selected).await?;
            let previous = if selected.candidate_id.is_some() {
                log.selected_previous().map_err(|_| corrupt(name))?.cloned()
            } else if selected.seq > 1 {
                let key = BucketKey::reflog(name, selected.seq - 1).map_err(|_| corrupt(name))?;
                let bytes = self
                    .read_optional(&key)
                    .await?
                    .ok_or_else(|| corrupt(name))?;
                let previous = RefLogRecord::decode(&bytes)
                    .map_err(|_| corrupt(name))?
                    .record;
                RefRecord::validate_successor(Some(&previous), &selected)
                    .map_err(|_| corrupt(name))?;
                if previous.candidate_id.is_some() || log.previous_commit != Some(previous.commit) {
                    return Err(corrupt(name));
                }
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
        let key = ref_key(name)?;
        self.read_ref(&key).await
    }

    /// Runs the ordinary ref_cas path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn ref_cas_locked(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        let key = ref_key(name)?;
        let current = self.read_ref(&key).await?;
        if current.as_ref() != expect
            || (key.mutability() == Mutability::CreateOnce && current.is_some())
        {
            return Ok(RefCasOutcome::Conflict(current.map(Box::new)));
        }
        RefRecord::validate_successor(current.as_ref(), new).map_err(|_| files::malformed())?;
        if branch(name)? {
            if new.candidate_id.is_none() {
                return Err(files::malformed());
            }
            let proposal_key = log_key(name, new)?;
            let proposal_bytes = self
                .read_optional(&proposal_key)
                .await?
                .ok_or_else(files::malformed)?;
            let proposal = RefLogRecord::decode(&proposal_bytes).map_err(|_| corrupt(name))?;
            proposal
                .validate_candidate(expect, new)
                .map_err(|_| files::malformed())?;
        }
        let bytes = new.encode().map_err(|_| files::malformed())?;
        self.register_ref_name(name, current.is_some()).await?;
        if !self.install(&key, &bytes, current.is_some()).await? {
            return Ok(RefCasOutcome::Conflict(
                self.read_ref(&key).await?.map(Box::new),
            ));
        }
        Ok(RefCasOutcome::Applied)
    }

    /// Runs the ordinary ref_log_append path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn ref_log_append_locked(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        let key = log_key(name, &record.record)?;
        if record.record.seq != seq {
            return Err(files::malformed());
        }
        let bytes = record.encode().map_err(|_| files::malformed())?;
        if self.read_optional(&key).await?.is_some() {
            return Ok(RefLogAppendOutcome::Exists);
        }
        if record.record.candidate_id.is_some() {
            let previous = record.selected_previous().map_err(|_| files::malformed())?;
            record
                .validate_candidate(previous, &record.record)
                .map_err(|_| files::malformed())?;
        } else if seq > 1 {
            let previous_key = BucketKey::reflog(name, seq - 1).map_err(|_| files::malformed())?;
            let previous_bytes = self
                .read_optional(&previous_key)
                .await?
                .ok_or_else(|| corrupt(name))?;
            let previous = RefLogRecord::decode(&previous_bytes).map_err(|_| corrupt(name))?;
            RefRecord::validate_successor(Some(&previous.record), &record.record)
                .map_err(|_| files::malformed())?;
            if record.previous_commit != Some(previous.record.commit) {
                return Err(files::malformed());
            }
        } else {
            RefRecord::validate_successor(None, &record.record).map_err(|_| files::malformed())?;
            if record.previous_commit.is_some() {
                return Err(files::malformed());
            }
        }
        if self.install(&key, &bytes, false).await? {
            Ok(RefLogAppendOutcome::Appended)
        } else {
            Ok(RefLogAppendOutcome::Exists)
        }
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
        let key = ref_key(name)?;
        if !branch(name)? {
            return Err(files::malformed());
        }
        let Some(current) = self.read_ref(&key).await? else {
            return Ok(Vec::new());
        };
        let from_seq = from_seq.max(1);
        if from_seq > current.seq {
            return Ok(Vec::new());
        }
        let records = self.committed_logs(name, current).await?;
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
        self.ref_get_locked(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        let _guard = self.exclusive().await?;
        self.ref_cas_locked(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        let _guard = self.exclusive().await?;
        self.ref_log_append_locked(name, seq, record).await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        let _guard = self.exclusive().await?;
        self.ref_log_read_locked(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        ref_key(name)?;
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
            let head = self.bucket.ref_get(&self.name).await?;
            if head.is_some_and(|record| record.seq >= seq) {
                let records = self.bucket.ref_log_read(&self.name, seq).await?;
                let record = records
                    .into_iter()
                    .next()
                    .ok_or_else(|| corrupt(&self.name))?;
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
