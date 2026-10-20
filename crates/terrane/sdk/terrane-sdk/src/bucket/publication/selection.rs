//! Resolves a contiguous protected commit chain through exact consecutive reads.

mod memo;

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

pub(super) use memo::DecodeMemo;

use super::control::{Control, HeldReads};
use super::projection::{self, Values};
use super::receipts::RecordRead;
use super::{PayloadRetention, Selected, corrupt, digest};
use crate::bucket::held::HeldIdentity;
use crate::bucket::{BucketBinding, FileBucket};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::sync::Mutex;
use terrane_format::gc::publication::evidence::GuardSnapshot;
use terrane_format::gc::publication::{
    Activation, BackendRegistration, PortableSnapshot, PredecessorSlot, PublicationCommit,
    PublicationTransaction,
};

enum ReadScope<'scope, F> {
    Ordinary {
        control: &'scope Control,
        fs: &'scope F,
    },
    Held(HeldReads<'scope, F>),
}

struct ChainReads<'scope, F> {
    scope: ReadScope<'scope, F>,
    records: Mutex<Vec<RecordRead>>,
    memo: Option<&'scope DecodeMemo>,
    retention: PayloadRetention,
}

impl<'scope, F: LocalFs + BucketBinding> ChainReads<'scope, F> {
    fn ordinary(control: &'scope Control, fs: &'scope F) -> Self {
        Self {
            scope: ReadScope::Ordinary { control, fs },
            records: Mutex::new(Vec::new()),
            memo: None,
            retention: PayloadRetention::Observed,
        }
    }

    fn held(reads: HeldReads<'scope, F>) -> Self {
        Self {
            scope: ReadScope::Held(reads),
            records: Mutex::new(Vec::new()),
            memo: None,
            retention: PayloadRetention::Observed,
        }
    }

    fn held_retained(reads: HeldReads<'scope, F>, retention: PayloadRetention) -> Self {
        Self {
            scope: ReadScope::Held(reads.retaining_original()),
            records: Mutex::new(Vec::new()),
            memo: None,
            retention,
        }
    }

    fn remember(&self, read: RecordRead) -> Result<Option<Vec<u8>>, StoreFailure> {
        let bytes = read.bytes().map(<[u8]>::to_vec);
        self.records.lock().map_err(|_| corrupt())?.push(read);
        Ok(bytes)
    }

    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StoreFailure> {
        let read = match &self.scope {
            ReadScope::Ordinary { control, fs } => control.read_observed(*fs, key).await?,
            ReadScope::Held(reads) => reads.read_observed(key).await?,
        };
        self.remember(read)
    }

    async fn finish(self) -> Result<Vec<RecordRead>, StoreFailure> {
        match self.scope {
            ReadScope::Ordinary { control, fs } => control.recheck(fs).await?,
            ReadScope::Held(reads) => reads.finish().await?,
        }
        self.records.into_inner().map_err(|_| corrupt())
    }
}

/// Resolves Active registration and independently verifies every selected record.
///
/// # Errors
/// Rejects missing genesis, malformed chains, changed bindings, incompatible
/// payloads, incomplete portable projections, and unavailable exact reads.
pub(super) async fn resolve<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
) -> Result<Selected, StoreFailure> {
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    let mut diagnostic =
        crate::diagnostic_clock::span(crate::diagnostic_clock::Group::PublicationSelection);
    let reads = ChainReads::ordinary(control, &bucket.inner.fs);
    let bytes = reads
        .read("backend-registration.cbor")
        .await?
        .ok_or_else(corrupt)?;
    let registration = BackendRegistration::decode(&bytes).map_err(|_| corrupt())?;
    if registration.binding != control.binding || registration.activation != Activation::Active {
        return Err(corrupt());
    }
    let result = resolve_with_reads(bucket, control, registration.genesis, reads).await;
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    diagnostic.finish_result(&result);
    result
}

/// Resolves exact selected bytes while borrowing an actual retained exclusion.
///
/// Every protected record keeps its parent, mode, link and inode checks. Common
/// physical bindings and ancestry are checked before reads and after the complete
/// chain, portable closure and committed history have been verified.
///
/// # Errors
/// Rejects changed bindings or ancestry, malformed chains and incomplete payloads.
pub(super) async fn resolve_held<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    held: &HeldIdentity<'_>,
) -> Result<Selected, StoreFailure> {
    resolve_held_mode(bucket, control, held, PayloadRetention::Observed, None).await
}

/// Retains original physical recipes during the actual held selected resolution.
///
/// # Errors
/// Refuses malformed selected evidence and unsafe, changed or missing ancestry.
pub(super) async fn resolve_held_retained<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    held: &HeldIdentity<'_>,
) -> Result<Selected, StoreFailure> {
    resolve_held_mode(bucket, control, held, PayloadRetention::Strict, None).await
}

/// Retains public payload recipes while preserving strict protected reads.
///
/// The observation-local memo reuses only pure checks of exact fresh bytes;
/// original physical recipes are still captured before those bytes are consumed.
///
/// # Errors
/// Rejects malformed selection, unavailable retention and changed bindings.
#[cfg(all(feature = "tokio", unix))]
pub(super) async fn resolve_held_ordinary_retained<F, C, V>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    held: &HeldIdentity<'_>,
    memo: &DecodeMemo,
) -> Result<Selected, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    resolve_held_mode(
        bucket,
        control,
        held,
        PayloadRetention::Ordinary,
        Some(memo),
    )
    .await
}

/// Reuses only pure successful checks after the same complete fresh held reads.
///
/// # Errors
/// Preserves malformed-chain, changed-binding and unavailable-read refusals.
pub(super) async fn resolve_held_reusing<F, C, V>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    held: &HeldIdentity<'_>,
    memo: &DecodeMemo,
) -> Result<Selected, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    let mut diagnostic =
        crate::diagnostic_clock::span(crate::diagnostic_clock::Group::PublicationSelection);
    let mut reads = ChainReads::held(control.held_reads(&bucket.inner.fs, held).await?);
    reads.memo = Some(memo);
    let bytes = reads
        .read("backend-registration.cbor")
        .await?
        .ok_or_else(corrupt)?;
    let registration = BackendRegistration::decode(&bytes).map_err(|_| corrupt())?;
    if registration.binding != control.binding || registration.activation != Activation::Active {
        return Err(corrupt());
    }
    let result = resolve_with_reads(bucket, control, registration.genesis, reads).await;
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    diagnostic.finish_result(&result);
    result
}

async fn resolve_held_mode<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    held: &HeldIdentity<'_>,
    retention: PayloadRetention,
    memo: Option<&DecodeMemo>,
) -> Result<Selected, StoreFailure> {
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    let mut diagnostic =
        crate::diagnostic_clock::span(crate::diagnostic_clock::Group::PublicationSelection);
    let held_reads = control.held_reads(&bucket.inner.fs, held).await?;
    let mut reads = if matches!(retention, PayloadRetention::Observed) {
        ChainReads::held(held_reads)
    } else {
        ChainReads::held_retained(held_reads, retention)
    };
    reads.memo = memo;
    let bytes = reads
        .read("backend-registration.cbor")
        .await?
        .ok_or_else(corrupt)?;
    let registration = BackendRegistration::decode(&bytes).map_err(|_| corrupt())?;
    if registration.binding != control.binding || registration.activation != Activation::Active {
        return Err(corrupt());
    }
    let result = resolve_with_reads(bucket, control, registration.genesis, reads).await;
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    diagnostic.finish_result(&result);
    result
}

/// Verifies an exact contiguous chain without treating activation phase as permission.
///
/// # Errors
/// Rejects absent or malformed genesis and every inconsistent selected transition.
pub(super) async fn resolve_chain<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    genesis: Option<[u8; 32]>,
) -> Result<Selected, StoreFailure> {
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    let mut diagnostic =
        crate::diagnostic_clock::span(crate::diagnostic_clock::Group::PublicationSelection);
    let reads = ChainReads::ordinary(control, &bucket.inner.fs);
    let result = resolve_with_reads(bucket, control, genesis, reads).await;
    #[cfg(all(test, feature = "std", feature = "tokio"))]
    diagnostic.finish_result(&result);
    result
}

async fn resolve_with_reads<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    control: &Control,
    genesis: Option<[u8; 32]>,
    reads: ChainReads<'_, F>,
) -> Result<Selected, StoreFailure> {
    let mut revision = 0u64;
    let mut selected: Option<Selected> = None;
    let mut projection = Values::new();
    loop {
        let key = format!("publication/commits/{revision}");
        let Some(bytes) = reads.read(&key).await? else {
            let mut selected = selected.ok_or_else(corrupt)?;
            if !matches!(reads.retention, PayloadRetention::Observed)
                && let Some(expected) = selected.state.guard
            {
                // The selected digest identifies bytes, not their original
                // protected incarnation. Capture that recipe before reuse.
                let suffix: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
                let bytes = reads
                    .read(&format!("publication/guards/{suffix}"))
                    .await?
                    .ok_or_else(corrupt)?;
                if digest(&bytes) != expected {
                    return Err(corrupt());
                }
                GuardSnapshot::decode(&bytes).map_err(|_| corrupt())?;
            }

            let mut log_reads = Vec::new();
            for row in &selected.state.branches {
                if let terrane_format::gc::publication::CommittedSelection::Selected(record) =
                    &row.selection
                {
                    match reads.retention {
                        PayloadRetention::Observed => {
                            bucket
                                .committed_logs_observed(
                                    &row.name,
                                    record.as_ref().clone(),
                                    &mut log_reads,
                                )
                                .await?;
                        }
                        PayloadRetention::Strict => {
                            bucket
                                .committed_logs_observed_retained(
                                    &row.name,
                                    record.as_ref().clone(),
                                    &mut log_reads,
                                )
                                .await?;
                        }
                        #[cfg(all(feature = "tokio", unix))]
                        PayloadRetention::Ordinary => {
                            bucket
                                .committed_logs_observed_mode(
                                    &row.name,
                                    record.as_ref().clone(),
                                    &mut log_reads,
                                    PayloadRetention::Ordinary,
                                )
                                .await?;
                        }
                    }
                }
            }
            for read in log_reads {
                reads.remember(read)?;
            }
            selected.reads = reads.finish().await?;
            return Ok(selected);
        };
        let (commit, slot_digest) = match reads.memo {
            Some(memo) => memo.commit(&bytes)?,
            None => {
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                let mut decode =
                    crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DecodeCommit);
                let decoded = PublicationCommit::decode(&bytes).map_err(|_| corrupt());
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                decode.finish_result(&decoded);
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                drop(decode);
                (decoded?, digest(&bytes))
            }
        };
        if revision == 0 && genesis.is_some_and(|expected| expected != slot_digest) {
            return Err(corrupt());
        }
        let transaction_bytes = reads
            .read(&commit.transaction_key)
            .await?
            .ok_or_else(corrupt)?;
        let transaction = match reads.memo {
            Some(memo) => memo.transaction(&commit, &bytes, &key, &transaction_bytes)?,
            None => {
                commit
                    .check_transaction(&key, &transaction_bytes)
                    .map_err(|_| corrupt())?;
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                let mut decode = crate::diagnostic_clock::span(
                    crate::diagnostic_clock::Group::DecodeTransaction,
                );
                let result =
                    PublicationTransaction::decode(&transaction_bytes).map_err(|_| corrupt());
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                decode.finish_result(&result);
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                drop(decode);
                result?
            }
        };
        let previous = selected.as_ref().map(|selected| PredecessorSlot {
            revision: selected.state.revision,
            digest: selected.digest,
        });
        if transaction.old.as_ref() != selected.as_ref().map(|selected| &selected.state)
            || transaction.predecessor != previous
            || transaction.new.binding != control.binding
        {
            return Err(corrupt());
        }

        let mut logical = selected
            .as_ref()
            .map_or_else(Values::new, |selected| selected.logical.clone());
        for change in &transaction.changes {
            if logical.get(&change.key).and_then(Option::as_ref) != change.expected.as_ref() {
                return Err(corrupt());
            }
            logical.insert(change.key.clone(), change.new.clone());
        }
        projection::validate(bucket, &transaction.new, &logical)?;
        if let Some(previous) = &selected {
            projection::validate_successor(&previous.logical, &logical)?;
        }

        let snapshot_key = terrane_format::bucket::BucketKey::parse(&transaction.snapshot.key)
            .map_err(|_| corrupt())?;
        let snapshot_read = reads.retention.read(bucket, &snapshot_key).await?;
        let snapshot_bytes = reads.remember(snapshot_read)?.ok_or_else(corrupt)?;
        let snapshot = match reads.memo {
            Some(memo) => memo.snapshot(&transaction, &transaction_bytes, &snapshot_bytes)?,
            None => {
                transaction
                    .snapshot
                    .check_snapshot(&snapshot_bytes)
                    .map_err(|_| corrupt())?;
                transaction
                    .check_snapshot(&snapshot_bytes)
                    .map_err(|_| corrupt())?;
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                let mut decode =
                    crate::diagnostic_clock::span(crate::diagnostic_clock::Group::DecodeSnapshot);
                let result = PortableSnapshot::decode(&snapshot_bytes).map_err(|_| corrupt());
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                decode.finish_result(&result);
                #[cfg(all(test, feature = "std", feature = "tokio"))]
                drop(decode);
                result?
            }
        };
        if let Some(pointer) = &snapshot.predecessor
            && selected.as_ref().map(|selected| &selected.snapshot) != Some(pointer)
        {
            return Err(corrupt());
        }
        projection = projection::apply(&snapshot, Some(&projection))?;
        if projection != projection::portable(&logical) {
            return Err(corrupt());
        }

        selected = Some(Selected {
            state: transaction.new,
            digest: slot_digest,
            logical,
            snapshot: transaction.snapshot,
            reads: Vec::new(),
            control_identity: control.physical_identity(),
        });
        revision = revision.checked_add(1).ok_or_else(corrupt)?;
    }
}
