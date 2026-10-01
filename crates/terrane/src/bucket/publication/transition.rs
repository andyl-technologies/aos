//! Publishes whole raw logical transitions through the exact next immutable slot.

use super::control::Control;
use super::projection::{self, Values};
use super::receipts::RecordRead;
use super::{Selected, corrupt, digest, unsupported};
use crate::bucket::{BucketBinding, FileBucket, files};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_core::bucket::{BucketKey, GenerationManifest, Mutability};
use terrane_core::gc::publication::{
    CommittedSelection, HistoryEntry, LogicalChange, PortableCurrent, PortableSnapshot,
    PredecessorSlot, ProjectionEntry, PublicationCommit, PublicationProof, PublicationState,
    PublicationTransaction, RawDigest, SelectedHistory,
};
use terrane_core::refs::{RefClass, RefLogRecord, RefName, RefRecord};

/// Carries canonical backend-only transition data without actor or GC authority.
///
/// Construction validates whole logical preimages against an actual selected
/// backend. The native consumer independently requires its matching live held
/// observation and retains every additional exact proposal read.
pub(crate) struct RawMutation {
    previous: PublicationState,
    predecessor: RawDigest,
    previous_logical: Values,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    reads: Vec<RecordRead>,
}

impl RawMutation {
    /// Borrows the whole previously selected state used during validation.
    pub(crate) fn previous(&self) -> &PublicationState {
        &self.previous
    }

    /// Returns the immutable predecessor slot digest used during validation.
    pub(crate) fn predecessor(&self) -> RawDigest {
        self.predecessor
    }

    /// Borrows every whole logical preimage used during validation.
    pub(crate) fn previous_logical(&self) -> &Values {
        &self.previous_logical
    }

    /// Borrows the validated successor while granting no checked authority.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows the canonical sorted raw logical changes.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows additional exact candidate reads captured during validation.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Applies independently compared raw changes under actual namespace exclusion.
    ///
    /// # Errors
    /// Rejects stale selected preimages, invalid records, incomplete projections,
    /// counter exhaustion, lost exact-slot installation and unavailable durability.
    pub(in crate::bucket) async fn publish_raw_locked(
        &self,
        observed: &Selected,
        changes: Vec<LogicalChange>,
    ) -> Result<Selected, StoreFailure> {
        let control = Control::open(self, false).await?;
        let current = super::selection::resolve(self, &control).await?;
        if current.state != observed.state
            || current.digest != observed.digest
            || current.logical != observed.logical
        {
            return Err(unavailable());
        }
        self.flush_publication_locked(&current).await?;
        let mutation = self.prepare_raw_changes(&current, changes).await?;
        let state = mutation.next;
        let changes = mutation.changes;

        // Catalog artifacts become durable at their exact registered keys
        // before either the manifest-bearing snapshot or the commit slot.
        for change in &changes {
            let key = BucketKey::parse(&change.key).map_err(|_| corrupt())?;
            if key.mutability() == Mutability::Immutable {
                let bytes = change.new.as_deref().ok_or_else(files::malformed)?;
                if !self.install(&key, bytes, false).await?
                    && self.read_optional(&key).await?.as_deref() != Some(bytes)
                {
                    return Err(corrupt());
                }
            }
        }

        let nonce: [u8; 32] = self
            .inner
            .fs
            .random_bytes(32)
            .await
            .map_err(files::io_failure)?
            .try_into()
            .map_err(|_| unsupported())?;
        let operation: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let snapshot = PortableSnapshot {
            revision: state.revision,
            origin: state.binding.clone(),
            projection: changes
                .iter()
                .filter(|row| projection::projectable(&row.key))
                .map(|row| ProjectionEntry {
                    key: row.key.clone(),
                    value: if row.key == "gc/lease" {
                        None
                    } else {
                        row.new.clone()
                    },
                })
                .collect(),
            predecessor: Some(current.snapshot.clone()),
        };
        let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
        let pointer = PortableCurrent {
            key: format!("publication/snapshots/{}:{operation}", state.revision),
            digest: digest(&snapshot_bytes),
        };
        let transaction = PublicationTransaction {
            nonce,
            old: Some(current.state.clone()),
            new: state,
            changes,
            proof: PublicationProof::Raw,
            predecessor: Some(PredecessorSlot {
                revision: current.state.revision,
                digest: current.digest,
            }),
            snapshot: pointer,
        };
        transaction
            .check_snapshot(&snapshot_bytes)
            .map_err(|_| corrupt())?;
        self.stage_snapshot_locked(&transaction.snapshot, &snapshot_bytes)
            .await?;
        self.commit_publication_locked(&control, transaction).await
    }

    /// Validates canonical raw data without installing any physical effect.
    async fn prepare_raw_changes(
        &self,
        current: &Selected,
        mut changes: Vec<LogicalChange>,
    ) -> Result<RawMutation, StoreFailure> {
        changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
        if changes.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(files::malformed());
        }

        let mut reads = Vec::new();
        let mut logical = current.logical.clone();
        let mut state = current.state.clone();
        state.revision = state.revision.checked_add(1).ok_or_else(corrupt)?;
        for change in &changes {
            // Ordinary backend changes cannot acquire collector ownership or
            // advance its protected lease/progress from canonical data alone.
            // Branch history is derived below from validated ref transitions.
            if change.key != "CAPABILITIES"
                && !(change.key.starts_with("refs/") && change.key.ends_with(":record"))
                && !change.key.starts_with("objects/index/")
            {
                return Err(unsupported());
            }
            if logical.get(&change.key).and_then(Option::as_ref) != change.expected.as_ref() {
                return Err(unavailable());
            }
            let key = BucketKey::parse(&change.key).map_err(|_| files::malformed())?;
            if key.mutability() != Mutability::CompareAndSwap
                && change.expected.is_some()
                && change.expected != change.new
            {
                return Err(files::malformed());
            }
            if let Some(name) = change.key.strip_suffix(":record") {
                let parsed = RefName::parse(name).map_err(|_| files::malformed())?;
                if parsed.class() != RefClass::Notes {
                    self.update_raw_ref(current, &mut state, name, change, &mut reads)
                        .await?;
                }
                state.sources.retain(|row| row.name != name);
            }
            logical.insert(change.key.clone(), change.new.clone());
        }

        if state.branches != current.state.branches
            || changes.iter().any(|row| row.key.starts_with("refs/"))
        {
            let history = SelectedHistory {
                branches: state.branches.clone(),
                origin: state.binding.clone(),
            }
            .encode()
            .map_err(|_| corrupt())?;
            let change = LogicalChange {
                key: "publication/SELECTED-HISTORY".into(),
                expected: current
                    .logical
                    .get("publication/SELECTED-HISTORY")
                    .cloned()
                    .flatten(),
                new: Some(history.clone()),
            };
            if changes.iter().any(|row| row.key == change.key) {
                return Err(files::malformed());
            }
            logical.insert(change.key.clone(), Some(history));
            changes.push(change);
        }
        if catalog_loses_availability(&current.logical, &logical)? {
            state.loss_generation = state.loss_generation.checked_add(1).ok_or_else(corrupt)?;
            state.sources.clear();
        }
        projection::validate(self, &state, &logical)?;
        projection::validate_successor(&current.logical, &logical)?;
        changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));

        Ok(RawMutation {
            previous: current.state.clone(),
            predecessor: current.digest,
            previous_logical: current.logical.clone(),
            next: state,
            changes,
            reads,
        })
    }

    async fn update_raw_ref(
        &self,
        current: &Selected,
        state: &mut terrane_core::gc::publication::PublicationState,
        name: &str,
        change: &LogicalChange,
        reads: &mut Vec<RecordRead>,
    ) -> Result<(), StoreFailure> {
        let expected = change
            .expected
            .as_deref()
            .map(RefRecord::decode)
            .transpose()
            .map_err(|_| files::malformed())?;
        let new = change
            .new
            .as_deref()
            .map(RefRecord::decode)
            .transpose()
            .map_err(|_| files::malformed())?;
        let class = RefName::parse(name)
            .map_err(|_| files::malformed())?
            .class();
        if class == RefClass::Tags {
            if expected.is_some() || new.as_ref().is_none_or(|record| record.seq != 1) {
                return Err(files::malformed());
            }
            return Ok(());
        }
        let previous = current
            .state
            .branches
            .iter()
            .find(|row| row.name == name)
            .map(|row| &row.selection);
        let retained = match previous {
            Some(CommittedSelection::Selected(record)) => Some(record.as_ref()),
            Some(CommittedSelection::Unknown) => return Err(unsupported()),
            _ => None,
        };
        if let Some(new) = &new {
            RefRecord::validate_successor(retained, new).map_err(|_| files::malformed())?;
            let candidate = new.candidate_id.ok_or_else(files::malformed)?;
            let key = BucketKey::reflog_candidate(name, new.seq, &candidate)
                .map_err(|_| files::malformed())?;
            let read = self.read_optional_observed(&key).await?;
            let bytes = read.bytes().ok_or_else(files::malformed)?;
            let log = RefLogRecord::decode(bytes).map_err(|_| corrupt())?;
            log.validate_candidate(expected.as_ref(), new)
                .map_err(|_| files::malformed())?;
            if log.selected_previous().map_err(|_| files::malformed())? != retained {
                return Err(files::malformed());
            }
            reads.push(read);
        }
        let selection = new.map_or_else(
            || previous.cloned().unwrap_or(CommittedSelection::Never),
            |record| CommittedSelection::Selected(record.into()),
        );
        match state
            .branches
            .binary_search_by(|row| row.name.as_bytes().cmp(name.as_bytes()))
        {
            Ok(position) => state.branches[position].selection = selection,
            Err(position) => state.branches.insert(
                position,
                HistoryEntry {
                    name: name.into(),
                    selection,
                },
            ),
        }
        Ok(())
    }

    /// Durably stages exact portable snapshot bytes before selecting their transaction.
    ///
    /// # Errors
    /// Rejects mismatched existing bytes and propagates unavailable durable I/O.
    pub(super) async fn stage_snapshot_locked(
        &self,
        pointer: &PortableCurrent,
        bytes: &[u8],
    ) -> Result<(), StoreFailure> {
        pointer.check_snapshot(bytes).map_err(|_| corrupt())?;
        let key = BucketKey::parse(&pointer.key).map_err(|_| corrupt())?;
        if !self.install(&key, bytes, false).await?
            && self.read_optional(&key).await?.as_deref() != Some(bytes)
        {
            return Err(corrupt());
        }
        self.read_portable_snapshot(pointer).await?;
        Ok(())
    }

    /// Installs exactly the next create-once slot, then durable portable projection.
    ///
    /// # Errors
    /// Returns indeterminate unavailability after submitted durable effects;
    /// a lost slot is resolved through exact selected-chain rereading.
    pub(super) async fn commit_publication_locked(
        &self,
        control: &Control,
        transaction: PublicationTransaction,
    ) -> Result<Selected, StoreFailure> {
        if transaction.proof != PublicationProof::Raw
            || transaction
                .old
                .as_ref()
                .is_some_and(|old| old.burn_owners != transaction.new.burn_owners)
        {
            return Err(corrupt());
        }
        self.commit_transaction_locked(control, transaction).await
    }

    async fn commit_transaction_locked(
        &self,
        control: &Control,
        transaction: PublicationTransaction,
    ) -> Result<Selected, StoreFailure> {
        let operation: String = transaction
            .nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let transaction_key = format!("publication/transactions/{operation}");
        let bytes = transaction.encode().map_err(|_| corrupt())?;
        transaction
            .check_key(&transaction_key)
            .map_err(|_| corrupt())?;
        if !control
            .install(&self.inner.fs, &transaction_key, &bytes, false)
            .await?
            && control
                .read(&self.inner.fs, &transaction_key)
                .await?
                .as_deref()
                != Some(bytes.as_slice())
        {
            return Err(corrupt());
        }
        if control
            .read(&self.inner.fs, &transaction_key)
            .await?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(corrupt());
        }
        let commit = PublicationCommit {
            revision: transaction.new.revision,
            predecessor: transaction.predecessor.as_ref().map(|row| row.digest),
            transaction_key,
            transaction_digest: digest(&bytes),
        };
        let key = format!("publication/commits/{}", commit.revision);
        let slot_bytes = commit.encode().map_err(|_| corrupt())?;
        let installed = control
            .install(&self.inner.fs, &key, &slot_bytes, false)
            .await?;
        if !installed {
            super::selection::resolve_chain(self, control, None).await?;
            return Err(unavailable());
        }
        let selected = super::selection::resolve_chain(self, control, None).await?;
        if selected.digest != digest(&slot_bytes) {
            return Err(unavailable());
        }
        self.flush_publication_locked(&selected).await?;
        Ok(selected)
    }
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

/// Keeps every represented retirement association fixed for backend-only data.
///
/// A separate maintenance producer must authorize active exclusions, permanent
/// burns and their ownership. Legacy unknown and known empty remain distinct.
fn validate_raw_retirement_associations(
    before: &GenerationManifest,
    after: &GenerationManifest,
) -> Result<(), StoreFailure> {
    if before.exclusions != after.exclusions || before.burns != after.burns {
        return Err(unsupported());
    }
    Ok(())
}

fn catalog_loses_availability(before: &Values, after: &Values) -> Result<bool, StoreFailure> {
    let old = projection::capabilities(before)?;
    let new = projection::capabilities(after)?;
    if old.generation == new.generation {
        return Ok(false);
    }
    let old_generation = old.generation.ok_or_else(corrupt)?;
    let new_generation = new.generation.ok_or_else(corrupt)?;
    let old_manifest = GenerationManifest::decode(projection::value(
        before,
        &format!("objects/index/{old_generation}/MANIFEST"),
    )?)
    .map_err(|_| corrupt())?;
    let new_manifest = GenerationManifest::decode(projection::value(
        after,
        &format!("objects/index/{new_generation}/MANIFEST"),
    )?)
    .map_err(|_| corrupt())?;
    validate_raw_retirement_associations(&old_manifest, &new_manifest)?;
    for entry in old_manifest.inventory.as_ref().ok_or_else(corrupt)? {
        if !new_manifest
            .inventory
            .as_ref()
            .is_some_and(|rows| rows.contains(entry))
        {
            return Ok(true);
        }
    }
    let mut next = std::collections::BTreeMap::new();
    for shard in &new_manifest.shards {
        let records = terrane_core::pack_format::decode_shard(
            projection::value(
                after,
                &format!("objects/index/{new_generation}/{}.idx", shard.shard),
            )?,
            u8::try_from(shard.shard).map_err(|_| corrupt())?,
        )
        .map_err(|_| corrupt())?;
        for record in records {
            next.insert(record.record.hash, record);
        }
    }
    for shard in &old_manifest.shards {
        let records = terrane_core::pack_format::decode_shard(
            projection::value(
                before,
                &format!("objects/index/{old_generation}/{}.idx", shard.shard),
            )?,
            u8::try_from(shard.shard).map_err(|_| corrupt())?,
        )
        .map_err(|_| corrupt())?;
        for record in records {
            if record.state == crate::pack::RecordState::Live as u8
                && next.get(&record.record.hash) != Some(&record)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> crate::bucket::held::HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Validates a raw proposal under its actual matching retained namespace.
    ///
    /// # Errors
    /// Rejects stale or mismatched held observations, malformed whole logical
    /// preimages and successors, incomplete catalogs and unavailable exact reads.
    pub(super) async fn prepare_raw(
        &self,
        observed: &super::SelectedObservation<'_>,
        changes: Vec<LogicalChange>,
    ) -> Result<RawMutation, StoreFailure> {
        self.retained_namespace()?;
        self.check_observation(observed).await?;
        let mutation = self
            .bucket()
            .prepare_raw_changes(&observed.selected, changes)
            .await?;
        observed.revalidate().await?;
        Ok(mutation)
    }
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> crate::bucket::held::HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Compares a whole raw ref and publishes its canonical retained successor.
    ///
    /// # Errors
    /// Rejects read-only roles, unavailable retention, malformed records,
    /// unknown retained history, unsafe physical preimages and failed durability.
    pub(in crate::bucket) async fn cas_raw_ref(
        &self,
        name: &str,
        expected: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<crate::store::RefCasOutcome, StoreFailure> {
        self.retained_namespace()?;
        let key = BucketKey::ref_record(name).map_err(|_| files::malformed())?;
        let observed = self.observe_publication().await?;
        let current = observed
            .logical()
            .get(key.as_str())
            .and_then(Option::as_deref)
            .map(RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        if current.as_ref() != expected
            || key.mutability() == Mutability::CreateOnce && current.is_some()
        {
            return Ok(crate::store::RefCasOutcome::Conflict(current.map(Box::new)));
        }
        let previous = match observed
            .state()
            .branches
            .iter()
            .find(|row| row.name == name)
            .map(|row| &row.selection)
        {
            Some(CommittedSelection::Selected(record)) => Some(record.as_ref()),
            Some(CommittedSelection::Unknown) => return Err(unsupported()),
            _ => current.as_ref(),
        };
        RefRecord::validate_successor(previous, new).map_err(|_| files::malformed())?;
        let mut capabilities = projection::capabilities(observed.logical())?;
        let names = capabilities.ref_names.as_mut().ok_or_else(unsupported)?;
        if let Err(position) = names.binary_search_by(|row| row.as_bytes().cmp(name.as_bytes())) {
            names.insert(position, name.into());
        }
        let capability_bytes = capabilities.encode().map_err(|_| files::malformed())?;
        let previous_capabilities = observed.logical().get("CAPABILITIES").cloned().flatten();
        let mut changes = vec![LogicalChange {
            key: key.as_str().into(),
            expected: current
                .as_ref()
                .map(RefRecord::encode)
                .transpose()
                .map_err(|_| files::malformed())?,
            new: Some(new.encode().map_err(|_| files::malformed())?),
        }];
        if previous_capabilities.as_ref() != Some(&capability_bytes) {
            changes.push(LogicalChange {
                key: "CAPABILITIES".into(),
                expected: previous_capabilities,
                new: Some(capability_bytes),
            });
        }
        // The closed validator performs and captures the exact candidate GET.
        // It also preserves absent-head history and strips target raw lineage.
        self.publish_backend_raw(&observed, changes).await?;
        Ok(crate::store::RefCasOutcome::Applied)
    }
}

#[cfg(test)]
mod retirement_association_tests {
    //! Checks raw association preservation without granting maintenance authority.

    use super::validate_raw_retirement_associations;
    use terrane_core::bucket::GenerationManifest;

    fn manifest(burns: Option<Vec<[u8; 16]>>) -> GenerationManifest {
        GenerationManifest {
            generation: 1,
            shards: Vec::new(),
            written_at: 0,
            cycle: 0,
            inventory: Some(Vec::new()),
            exclusions: Some(Vec::new()),
            burns,
        }
    }

    #[test]
    fn raw_retirement_check_preserves_known_empty_and_legacy_unknown_burns() {
        let unknown = manifest(None);
        let empty = manifest(Some(Vec::new()));
        assert!(unknown.encode().is_ok());
        assert!(empty.encode().is_ok());

        assert!(validate_raw_retirement_associations(&unknown, &unknown).is_ok());
        assert!(validate_raw_retirement_associations(&empty, &empty).is_ok());
        assert!(validate_raw_retirement_associations(&unknown, &empty).is_err());
        assert!(validate_raw_retirement_associations(&empty, &unknown).is_err());
    }

    #[test]
    fn raw_retirement_check_rejects_added_removed_or_replaced_burns() {
        let previous = manifest(Some(vec![[1; 16]]));
        assert!(previous.encode().is_ok());
        assert!(validate_raw_retirement_associations(&previous, &previous).is_ok());

        for burns in [
            Some(Vec::new()),
            Some(vec![[2; 16]]),
            Some(vec![[1; 16], [2; 16]]),
        ] {
            let next = manifest(burns);
            assert!(next.encode().is_ok());
            assert!(validate_raw_retirement_associations(&previous, &next).is_err());
        }
    }
}
