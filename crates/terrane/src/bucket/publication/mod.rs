//! Resolves immutable selected slots and their complete portable projections.
//!
//! Protected registration and physical exclusion establish backend authority.
//! Public format records remain untrusted until the exact selected chain, actual
//! binding, logical preimages, and portable projection have been checked.

mod activation;
mod checked;
mod control;
mod lease_reads;
mod location;
mod profile;
pub(super) mod projection;
pub(crate) mod receipts;
mod selection;
mod transition;

pub(super) use location::configured_location;

#[cfg(all(test, feature = "tokio", unix))]
mod held_read_tests;
#[cfg(all(test, feature = "tokio", unix))]
mod tests;

use super::{BucketBinding, FileBucket, files};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use terrane_core::gc::publication::{PublicationState, RawDigest};

pub(crate) use super::containers::ContainerArtifacts;
pub(crate) use profile::registered_profile;
pub(crate) use transition::RawMutation;

#[cfg(feature = "send")]
type RecheckFuture<'held> =
    Pin<Box<dyn Future<Output = Result<Selected, StoreFailure>> + Send + 'held>>;
#[cfg(not(feature = "send"))]
type RecheckFuture<'held> = Pin<Box<dyn Future<Output = Result<Selected, StoreFailure>> + 'held>>;

#[cfg(feature = "send")]
type SelectedRecheck<'held> = Box<dyn Fn() -> RecheckFuture<'held> + Send + Sync + 'held>;
#[cfg(not(feature = "send"))]
type SelectedRecheck<'held> = Box<dyn Fn() -> RecheckFuture<'held> + 'held>;

/// Holds backend-verified selected bytes while the caller retains exclusion.
pub(super) struct Selected {
    /// The verified whole state selected by the contiguous chain.
    pub state: PublicationState,
    /// The raw digest of its exact immutable commit slot.
    pub digest: RawDigest,
    /// The complete selected logical bytes, including explicit absence.
    pub logical: BTreeMap<String, Option<Vec<u8>>>,
    /// The exact verified snapshot closure for the selected projection.
    pub snapshot: terrane_core::gc::publication::PortableCurrent,
    /// Exact read data retained only for this completed resolution.
    pub reads: Vec<receipts::RecordRead>,
    /// Actual protected external control incarnation checked throughout reads.
    pub control_identity: (u64, u64),
}

/// Borrows a selected chain from an actual live held namespace adapter.
///
/// Its private construction retains the holder borrow; public format values
/// cannot manufacture this backend observation or publication authority.
pub(crate) struct SelectedObservation<'held> {
    selected: Selected,
    operator_uid: u32,
    identity: super::held::HeldIdentity<'held>,
    recheck: SelectedRecheck<'held>,
}

impl SelectedObservation<'_> {
    /// Returns the exact selected revision and immutable slot digest.
    pub(crate) fn stamp(&self) -> (u64, RawDigest) {
        (self.selected.state.revision, self.selected.digest)
    }

    /// Borrows the verified whole selected state without granting private authority.
    pub(crate) fn state(&self) -> &PublicationState {
        &self.selected.state
    }

    /// Borrows the complete selected logical values, including explicit absence.
    pub(crate) fn logical(&self) -> &BTreeMap<String, Option<Vec<u8>>> {
        &self.selected.logical
    }

    /// Returns the independently configured operator checked by this backend.
    pub(crate) fn configured_operator_uid(&self) -> u32 {
        self.operator_uid
    }

    /// Borrows the complete operation-local protected and portable exact reads.
    pub(crate) fn physical_reads(&self) -> &[receipts::RecordRead] {
        &self.selected.reads
    }

    /// Returns the actual external control incarnation retained by this read.
    pub(crate) fn control_identity(&self) -> (u64, u64) {
        self.selected.control_identity
    }

    /// Borrows the complete durable snapshot closure selected by this chain.
    pub(crate) fn snapshot(&self) -> &terrane_core::gc::publication::PortableCurrent {
        &self.selected.snapshot
    }

    /// Borrows the actual namespace exclusion proof for this observation.
    pub(crate) fn identity(&self) -> &super::held::HeldIdentity<'_> {
        &self.identity
    }

    /// Rechecks the actual borrowed backend and its whole selected observation.
    ///
    /// # Errors
    /// Rejects changed physical bindings, selected state, logical preimages or
    /// slot evidence and propagates exact-read failures under the retained holder.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.revalidate_against(&self.selected).await
    }

    async fn revalidate_against(&self, expected: &Selected) -> Result<(), StoreFailure> {
        let current = (self.recheck)().await?;
        if current.state != expected.state
            || current.digest != expected.digest
            || current.logical != expected.logical
            || current.control_identity != expected.control_identity
        {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        Ok(())
    }

    /// Constructs untrusted ref-transition data from these actual selected bytes.
    ///
    /// The returned format values grant no checked authority. Only the separate
    /// private native verifier can place them in a sealed checked mutation.
    ///
    /// # Errors
    /// Rejects malformed names, unknown retained history, invalid sequence or
    /// epoch, counter exhaustion, create-once replacement and incomplete bytes.
    pub(crate) fn ref_transition(
        &self,
        name: &str,
        new: &terrane_core::refs::RefRecord,
    ) -> Result<
        (
            PublicationState,
            Vec<terrane_core::gc::publication::LogicalChange>,
        ),
        StoreFailure,
    > {
        use terrane_core::gc::publication::{
            CommittedSelection, HistoryEntry, LogicalChange, SelectedHistory,
        };
        use terrane_core::refs::{RefClass, RefName};

        let class = RefName::parse(name)
            .map_err(|_| files::malformed())?
            .class();
        let key = terrane_core::bucket::BucketKey::ref_record(name)
            .map_err(|_| files::malformed())?
            .as_str()
            .to_owned();
        let expected = self.selected.logical.get(&key).cloned().flatten();
        let branch = matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        );
        let retained = self
            .state()
            .branches
            .iter()
            .find(|row| row.name == name)
            .map(|row| &row.selection);
        let current = expected
            .as_deref()
            .map(terrane_core::refs::RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        let previous = match retained {
            Some(CommittedSelection::Selected(previous)) => Some(previous.as_ref()),
            Some(CommittedSelection::Unknown) => return Err(unsupported()),
            _ => current.as_ref(),
        };
        terrane_core::refs::RefRecord::validate_successor(previous, new)
            .map_err(|_| files::malformed())?;
        if branch && new.candidate_id.is_none()
            || !branch && new.candidate_id.is_some()
            || class == RefClass::Tags && expected.is_some()
        {
            return Err(files::malformed());
        }

        let mut next = self.state().clone();
        next.revision = next.revision.checked_add(1).ok_or_else(corrupt)?;
        if branch {
            next.sources.retain(|row| row.name != name);
            let row = HistoryEntry {
                name: name.into(),
                selection: CommittedSelection::Selected(new.clone().into()),
            };
            match next
                .branches
                .binary_search_by(|row| row.name.as_bytes().cmp(name.as_bytes()))
            {
                Ok(position) => next.branches[position] = row,
                Err(position) => next.branches.insert(position, row),
            }
        }
        let mut changes = vec![LogicalChange {
            key,
            expected,
            new: Some(new.encode().map_err(|_| files::malformed())?),
        }];
        let mut capabilities = projection::capabilities(&self.selected.logical)?;
        let names = capabilities.ref_names.as_mut().ok_or_else(corrupt)?;
        if let Err(position) = names.binary_search_by(|row| row.as_bytes().cmp(name.as_bytes())) {
            names.insert(position, name.into());
            changes.push(LogicalChange {
                key: "CAPABILITIES".into(),
                expected: Some(projection::value(&self.selected.logical, "CAPABILITIES")?.to_vec()),
                new: Some(capabilities.encode().map_err(|_| corrupt())?),
            });
        }
        if branch {
            changes.push(LogicalChange {
                key: "publication/SELECTED-HISTORY".into(),
                expected: Some(
                    projection::value(&self.selected.logical, "publication/SELECTED-HISTORY")?
                        .to_vec(),
                ),
                new: Some(
                    SelectedHistory {
                        origin: next.binding.clone(),
                        branches: next.branches.clone(),
                    }
                    .encode()
                    .map_err(|_| corrupt())?,
                ),
            });
        }
        changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
        Ok((next, changes))
    }
}

/// Reports a durably projected selected transition.
pub(crate) struct SelectedReceipt {
    /// The exact committed revision and immutable slot digest.
    pub(crate) stamp: (u64, RawDigest),
    /// The whole verified state after the transition.
    pub(crate) state: PublicationState,
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> super::held::HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Observes exact selected bytes while retaining this actual holder borrow.
    ///
    /// # Errors
    /// Rejects unregistered, stale, malformed or physically mismatched evidence
    /// and propagates exact-read and portable-recovery failures.
    pub(crate) async fn observe_publication(
        &self,
    ) -> Result<SelectedObservation<'_>, StoreFailure> {
        let observed = self.observe_for_read().await?;
        if WRITABLE {
            self.retained_namespace()?;
            crate::store::native_publication_effects::repair(self.fs(), &observed).await?;
        }
        Ok(observed)
    }

    /// Resolves one complete read observation without repairing materialized caches.
    ///
    /// Its actual holder borrow and fresh full-chain recheck stay local to this
    /// call. Destination adapters also use this path for read-only operations.
    ///
    /// # Errors
    /// Rejects malformed or unavailable selected evidence, changed physical
    /// bindings and missing trusted operator configuration.
    pub(super) async fn observe_for_read(&self) -> Result<SelectedObservation<'_>, StoreFailure> {
        let selected = self.selected_held().await?;
        let recheck: SelectedRecheck<'_> = Box::new(move || Box::pin(self.selected_held()));
        Ok(SelectedObservation {
            selected,
            operator_uid: self
                .bucket()
                .publication_operator_uid()
                .ok_or_else(unsupported)?,
            identity: self.identity_proof(),
            recheck,
        })
    }

    async fn selected_held(&self) -> Result<Selected, StoreFailure> {
        let held = self.identity_proof();
        let control = control::Control::open(self.bucket(), false).await?;
        selection::resolve_held(self.bucket(), &control, &held).await
    }

    /// Reads a canonical ref from a fresh complete held selection.
    ///
    /// Each call resolves the whole exact chain and inventory under this actual
    /// holder. It does not reuse prior observations or read mutable ref caches.
    ///
    /// # Errors
    /// Rejects invalid ref keys, malformed whole records, changed physical
    /// evidence and incomplete or unavailable selected chains.
    pub(super) async fn read_selected_ref(
        &self,
        name: &str,
    ) -> Result<Option<terrane_core::refs::RefRecord>, StoreFailure> {
        let key =
            terrane_core::bucket::BucketKey::ref_record(name).map_err(|_| files::malformed())?;
        let selected = self.selected_held().await?;
        selected
            .logical
            .get(key.as_str())
            .and_then(Option::as_deref)
            .map(terrane_core::refs::RefRecord::decode)
            .transpose()
            .map_err(|_| {
                StoreFailure::new(StoreErrorKind::Corrupt(
                    crate::store::CorruptSubject::RefName(key.as_str().into()),
                ))
            })
    }

    /// Returns the independently configured operator for this actual observation.
    ///
    /// This trusted configuration input grants no publication authority.
    ///
    /// # Errors
    /// Rejects stale observations, mismatched holders and missing configuration.
    pub(crate) async fn operator_uid(
        &self,
        observed: &SelectedObservation<'_>,
    ) -> Result<u32, StoreFailure> {
        self.check_observation(observed).await?;
        self.bucket()
            .publication_operator_uid()
            .ok_or_else(unsupported)
    }

    /// Reads the exact current protected Guard snapshot selected by this observation.
    ///
    /// Format validation and selected storage establish bytes, while actual
    /// trusted configuration checks remain the Guard's responsibility.
    ///
    /// # Errors
    /// Rejects mismatched holders, missing or malformed protected evidence and
    /// raw digest disagreement; preserves unavailable exact reads.
    pub(crate) async fn selected_guard_snapshot(
        &self,
        observed: &SelectedObservation<'_>,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(self
            .selected_guard_snapshot_record(observed)
            .await?
            .and_then(receipts::RecordRead::into_bytes))
    }

    /// Retains the exact selected protected Guard snapshot read under this holder.
    ///
    /// The whole selected digest fixes the canonical record key. These bytes and
    /// metadata are storage observations; the genuine producer independently
    /// checks its trusted configuration and retains this read in the native frame.
    ///
    /// # Errors
    /// Rejects mismatched holders, absent or malformed selected Guard bytes,
    /// digest disagreement and changed observations before or after the read.
    pub(crate) async fn selected_guard_snapshot_record(
        &self,
        observed: &SelectedObservation<'_>,
    ) -> Result<Option<receipts::RecordRead>, StoreFailure> {
        let control = self.check_observation(observed).await?;
        let Some(expected) = observed.state().guard else {
            return Ok(None);
        };
        let suffix: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
        let read = control
            .read_observed(self.fs(), &format!("publication/guards/{suffix}"))
            .await?;
        let bytes = read.bytes().ok_or_else(corrupt)?;
        if digest(bytes) != expected {
            return Err(corrupt());
        }
        terrane_core::gc::publication::evidence::GuardSnapshot::decode(bytes)
            .map_err(|_| corrupt())?;
        self.check_observation(observed).await?;
        Ok(Some(read))
    }

    /// Reads the exact protected source lineage selected by this observation.
    ///
    /// # Errors
    /// Rejects mismatched holders, missing or malformed evidence and raw digest
    /// disagreement; absence means the source has no selected checked lineage.
    pub(crate) async fn selected_lineage(
        &self,
        observed: &SelectedObservation<'_>,
        name: &str,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(self
            .selected_lineage_record(observed, name)
            .await?
            .and_then(receipts::RecordRead::into_bytes))
    }

    /// Retains exact protected lineage bytes and their physical read receipt.
    ///
    /// The selected source row fixes the registered key and raw digest. This
    /// observation grants no source-preservation or collection authority.
    ///
    /// # Errors
    /// Rejects mismatched holders, missing or malformed selected lineage,
    /// conflicting source names and unavailable protected physical reads.
    pub(crate) async fn selected_lineage_record(
        &self,
        observed: &SelectedObservation<'_>,
        name: &str,
    ) -> Result<Option<receipts::RecordRead>, StoreFailure> {
        let control = self.check_observation(observed).await?;
        let Some(row) = observed.state().sources.iter().find(|row| row.name == name) else {
            return Ok(None);
        };
        let suffix: String = row
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let read = control
            .read_observed(self.fs(), &format!("publication/lineage/{suffix}"))
            .await?;
        let bytes = read.bytes().ok_or_else(corrupt)?;
        if digest(bytes) != row.digest {
            return Err(corrupt());
        }
        let lineage = terrane_core::gc::publication::evidence::CheckedLineage::decode(bytes)
            .map_err(|_| corrupt())?;
        if lineage.source_name != row.name {
            return Err(corrupt());
        }
        self.check_observation(observed).await?;
        Ok(Some(read))
    }

    async fn check_observation(
        &self,
        observed: &SelectedObservation<'_>,
    ) -> Result<control::Control, StoreFailure> {
        if observed.identity().root() != self.root()
            || observed.identity().physical_identity() != self.physical_identity()
        {
            return Err(corrupt());
        }
        let control = control::Control::open(self.bucket(), false).await?;
        if control.binding != observed.state().binding {
            return Err(corrupt());
        }
        let current = selection::resolve_held(self.bucket(), &control, observed.identity()).await?;
        if current.state != observed.selected.state
            || current.digest != observed.selected.digest
            || current.logical != observed.selected.logical
            || current.control_identity != observed.selected.control_identity
        {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        Ok(control)
    }

    async fn selected_evidence(
        &self,
        observed: &SelectedObservation<'_>,
        kind: &str,
        expected: RawDigest,
    ) -> Result<Vec<u8>, StoreFailure> {
        let control = self.check_observation(observed).await?;
        let suffix: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
        let bytes = control
            .read(self.fs(), &format!("publication/{kind}/{suffix}"))
            .await?
            .ok_or_else(corrupt)?;
        if digest(&bytes) != expected {
            return Err(corrupt());
        }
        Ok(bytes)
    }
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> super::held::HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Publishes whole raw logical changes and invalidates affected checked lineage.
    ///
    /// Raw records never install a Guard, certify a graph or create lineage.
    ///
    /// # Errors
    /// Rejects stale observations, mismatched actual holders, malformed preimages
    /// or successors, incomplete payload evidence, and indeterminate durability.
    pub(in crate::bucket) async fn publish_backend_raw(
        &self,
        observed: &SelectedObservation<'_>,
        changes: Vec<terrane_core::gc::publication::LogicalChange>,
    ) -> Result<SelectedReceipt, StoreFailure> {
        self.publish_backend_raw_with_placement(observed, changes, None)
            .await
    }

    /// Retains actual ordinary data preimages through backend-only publication.
    ///
    /// # Errors
    /// Refuses stale held selection, malformed changes, changed exact additional
    /// reads or incomplete executor acknowledgment; creates no actor authority.
    pub(in crate::bucket) async fn publish_backend_raw_with_placement(
        &self,
        observed: &SelectedObservation<'_>,
        changes: Vec<terrane_core::gc::publication::LogicalChange>,
        placement: Option<&super::missing_placement::Placement>,
    ) -> Result<SelectedReceipt, StoreFailure> {
        self.publish_backend_raw_contextual(observed, changes, placement, None)
            .await
    }

    /// Retains native publication checks on the unchanged ordinary Raw transition.
    ///
    /// # Errors
    /// Preserves exact placement/preimage checks and refuses changed current
    /// controls, elapsed time or missing executor-filled durable acknowledgment.
    pub(in crate::bucket) async fn publish_backend_raw_contextual(
        &self,
        observed: &SelectedObservation<'_>,
        changes: Vec<terrane_core::gc::publication::LogicalChange>,
        placement: Option<&super::missing_placement::Placement>,
        context: Option<
            &crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext<'_, '_>,
        >,
    ) -> Result<SelectedReceipt, StoreFailure> {
        self.retained_namespace()?;
        if observed.identity.root() != self.root()
            || observed.identity.physical_identity() != self.physical_identity()
        {
            return Err(corrupt());
        }
        let mut mutation = self.prepare_raw(observed, changes).await?;
        if let Some(placement) = placement {
            mutation.retain_placement(placement);
        }
        let acknowledgment = match context {
            Some(context) => {
                crate::store::native_publication_effects::publish_raw_contextual(
                    self.fs(),
                    observed,
                    &mutation,
                    context,
                )
                .await?
            }
            None => {
                crate::store::native_publication_effects::publish_raw(
                    self.fs(),
                    observed,
                    &mutation,
                )
                .await?
            }
        };
        let selected = self.selected_held().await?;
        let mut logical = observed.logical().clone();
        for change in mutation.changes() {
            logical.insert(change.key.clone(), change.new.clone());
        }
        if selected.logical != logical
            || selected.state != *mutation.next()
            || (selected.state.revision, selected.digest)
                != (acknowledgment.revision, acknowledgment.digest)
        {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        Ok(SelectedReceipt {
            stamp: (selected.state.revision, selected.digest),
            state: selected.state,
        })
    }
}

/// Identifies inconsistent protected publication evidence.
pub(super) fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("publication".into()),
    ))
}

/// Identifies an unavailable registered authority or native primitive.
pub(super) fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}

/// Calculates an untyped digest for exact protected and portable record bytes.
pub(super) fn digest(bytes: &[u8]) -> RawDigest {
    *blake3::hash(bytes).as_bytes()
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Resolves selected logical bytes without consulting materialized caches.
    ///
    /// # Errors
    /// Rejects missing registration, malformed selected evidence, changed
    /// physical bindings, incomplete projections, and unavailable exact reads.
    pub(super) async fn selected_publication_locked(&self) -> Result<Selected, StoreFailure> {
        let control = control::Control::open(self, false).await?;
        selection::resolve(self, &control).await
    }

    /// Reads selected logical bytes, with explicit legacy read-only compatibility.
    ///
    /// # Errors
    /// Rejects missing selected evidence rather than filling from mutable caches.
    pub(super) async fn logical_optional(
        &self,
        key: &terrane_core::bucket::BucketKey,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        if self.inner.access.read_only() {
            return self.read_optional(key).await;
        }
        self.check_payload_namespace(key).await?;
        let selected = self.selected_publication_locked().await?;
        Ok(selected.logical.get(key.as_str()).cloned().flatten())
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    super::held::HeldBucket<'_, F, C, V, true>
{
    /// Publishes validated backend-only raw changes under actual exclusion.
    ///
    /// # Errors
    /// Rejects stale observations, unavailable native retention, malformed
    /// whole preimages and successors, and indeterminate durable effects.
    pub(crate) async fn publish_raw(
        &self,
        observed: &SelectedObservation<'_>,
        changes: Vec<terrane_core::gc::publication::LogicalChange>,
    ) -> Result<SelectedReceipt, StoreFailure> {
        self.publish_backend_raw(observed, changes).await
    }
}

// Collector observations preserve actual selected values and physical reads.
#[path = "../../gc/observation.rs"]
pub(crate) mod collection_observation;
