//! Implements whole-record ref CAS and create-once ordered reflogs.

use super::{BucketBinding, FileBucket, files};
use crate::store::{
    Clock, ContentValidator, CorruptSubject, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    RefWatch, StoreErrorKind, StoreFailure,
};
use terrane_core::bucket::{BucketKey, Mutability};
use terrane_core::refs::{RefLogRecord, RefRecord};

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

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    async fn read_ref(&self, key: &BucketKey) -> Result<Option<RefRecord>, StoreFailure> {
        self.read_optional(key)
            .await?
            .map(|bytes| RefRecord::decode(&bytes).map_err(|_| corrupt(key.as_str())))
            .transpose()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    RefStore for FileBucket<F, C, V>
{
    type Watch = FileRefWatch<F, C, V>;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        let key = ref_key(name)?;
        self.read_ref(&key).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        let key = ref_key(name)?;
        let _guard = self.exclusive().await?;
        let current = self.read_ref(&key).await?;
        if current.as_ref() != expect
            || (key.mutability() == Mutability::CreateOnce && current.is_some())
        {
            return Ok(RefCasOutcome::Conflict(current.map(Box::new)));
        }
        RefRecord::validate_successor(current.as_ref(), new).map_err(|_| files::malformed())?;
        let bytes = new.encode().map_err(|_| files::malformed())?;
        if !self.install(&key, &bytes, current.is_some()).await? {
            return Ok(RefCasOutcome::Conflict(
                self.read_ref(&key).await?.map(Box::new),
            ));
        }
        Ok(RefCasOutcome::Applied)
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        let key = BucketKey::reflog(name, seq).map_err(|_| files::malformed())?;
        if record.record.seq != seq {
            return Err(files::malformed());
        }
        let bytes = record.encode().map_err(|_| files::malformed())?;
        let _guard = self.exclusive().await?;
        if self.read_optional(&key).await?.is_some() {
            return Ok(RefLogAppendOutcome::Exists);
        }
        if seq > 1 {
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

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        let key = ref_key(name)?;
        BucketKey::reflog(name, 1).map_err(|_| files::malformed())?;
        let _guard = self.exclusive().await?;
        let current = self.read_ref(&key).await?;
        let horizon = current.as_ref().map_or(0, |record| record.seq);
        let mut seq = from_seq.max(1);
        let mut records = Vec::new();
        let mut previous: Option<RefLogRecord> = None;
        if seq > 1 {
            let key = BucketKey::reflog(name, seq - 1).map_err(|_| files::malformed())?;
            if let Some(bytes) = self.read_optional(&key).await? {
                previous = Some(RefLogRecord::decode(&bytes).map_err(|_| corrupt(name))?);
            }
        }
        loop {
            let key = BucketKey::reflog(name, seq).map_err(|_| files::malformed())?;
            let Some(bytes) = self.read_optional(&key).await? else {
                if seq <= horizon {
                    return Err(corrupt(name));
                }
                break;
            };
            let record = RefLogRecord::decode(&bytes).map_err(|_| corrupt(name))?;
            if record.record.seq != seq {
                return Err(corrupt(name));
            }
            if seq == horizon && current.as_ref() != Some(&record.record) {
                return Err(corrupt(name));
            }
            if let Some(previous) = &previous {
                RefRecord::validate_successor(Some(&previous.record), &record.record)
                    .map_err(|_| corrupt(name))?;
                if record.previous_commit != Some(previous.record.commit) {
                    return Err(corrupt(name));
                }
            } else if seq != 1 || record.previous_commit.is_some() {
                return Err(corrupt(name));
            }
            previous = Some(record.clone());
            records.push(record);
            match seq.checked_add(1) {
                Some(next) => seq = next,
                None => break,
            }
        }
        Ok(records)
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        BucketKey::reflog(name, 1).map_err(|_| files::malformed())?;
        Ok(FileRefWatch {
            bucket: self.clone(),
            name: name.into(),
            next: Some(from_seq.max(1)),
        })
    }
}

/// Reads ordered reflog records from a live file bucket.
///
/// Every call consults authoritative numbered keys rather than directory listing.
pub struct FileRefWatch<F, C, V> {
    bucket: FileBucket<F, C, V>,
    name: String,
    next: Option<u64>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    RefWatch for FileRefWatch<F, C, V>
{
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        let Some(seq) = self.next else {
            return Ok(None);
        };
        let records = self.bucket.ref_log_read(&self.name, seq).await?;
        let record = records.into_iter().next();
        if record.is_some() {
            self.next = seq.checked_add(1);
        }
        Ok(record)
    }
}
