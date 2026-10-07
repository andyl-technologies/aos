//! Consumes sealed native verification while remaining blind to repository policy.
//!
//! Public canonical records never enter this path directly. The neutral bridge
//! retains genuinely checked destination and source holders through the exact
//! immutable slot and durable portable-pointer acknowledgment.

use super::projection;
use super::{Selected, SelectedObservation, SelectedReceipt, corrupt, digest};
use crate::bucket::BucketBinding;
use crate::selected_bridge::CheckedMutation;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::evidence::{CheckedLineage, GuardSnapshot};
use terrane_core::gc::publication::{LogicalChange, PublicationProof, PublicationState};
use terrane_core::refs::{RefClass, RefLogRecord, RefName, RefRecord};

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    crate::bucket::held::HeldBucket<'_, F, C, V, true>
{
    /// Consumes one genuinely checked transition under all its retained holders.
    ///
    /// The storage layer checks fixed bindings and bytes. Repository policy,
    /// signatures and exhaustive consumed inputs are privately checked by the
    /// separate neutral capability producer before this method can be invoked.
    ///
    /// # Errors
    /// Rejects stale destination or source observations, incomplete logical
    /// preimages, invalid fixed evidence or successors and unavailable durable
    /// I/O. Failures after slot submission remain indeterminate.
    pub(crate) async fn publish_checked(
        &self,
        checked: CheckedMutation<'_, '_>,
    ) -> Result<SelectedReceipt, StoreFailure> {
        self.retained_namespace()?;
        checked.effect_context().ok_or_else(super::unsupported)?;
        let observed = checked.observed();
        self.check_observation(observed).await?;
        for source in checked.sources() {
            source.revalidate().await?;
        }
        let current = &observed.selected;

        let next = checked.next();
        if next.binding != current.state.binding
            || next.revision != current.state.revision.checked_add(1).ok_or_else(corrupt)?
            || next.loss_generation != current.state.loss_generation
            || next.burn_owners != current.state.burn_owners
        {
            return Err(corrupt());
        }
        let snapshot = GuardSnapshot::decode(checked.guard_snapshot()).map_err(|_| corrupt())?;
        match (&snapshot.registration, &next.binding) {
            (
                terrane_core::gc::publication::evidence::PhysicalRegistration::Local(original),
                terrane_core::gc::publication::BackendBinding::Local {
                    root,
                    root_device,
                    root_inode,
                    coordination_device,
                    coordination_inode,
                },
            ) if original.root == *root
                && original.root_device == *root_device
                && original.root_inode == *root_inode
                && original.coordination_device == *coordination_device
                && original.coordination_inode == *coordination_inode => {}
            _ => return Err(corrupt()),
        }
        let guard = digest(checked.guard_snapshot());
        if next.guard != Some(guard) {
            return Err(corrupt());
        }
        let mut logical = current.logical.clone();
        for change in checked.changes() {
            if logical.get(&change.key).and_then(Option::as_ref) != change.expected.as_ref() {
                return Err(corrupt());
            }
            logical.insert(change.key.clone(), change.new.clone());
        }
        projection::validate(self.bucket(), next, &logical)?;
        projection::validate_successor(&current.logical, &logical)?;
        match checked.proof() {
            PublicationProof::Raw => {
                if checked.lineage().is_some() {
                    return Err(corrupt());
                }
                verify_advisory_change(observed, next, checked.changes())?;
            }
            PublicationProof::Guard(expected) => {
                if expected != guard
                    || checked.lineage().is_some()
                    || !checked.changes().is_empty()
                    || next.branches != current.state.branches
                {
                    return Err(corrupt());
                }
                self.verify_guard_carry(&checked).await?;
            }
            PublicationProof::Candidate(expected) => {
                if current.state.guard != next.guard {
                    return Err(corrupt());
                }
                let bytes = checked.lineage().ok_or_else(corrupt)?;
                let lineage = CheckedLineage::decode(bytes).map_err(|_| corrupt())?;
                if digest(bytes) != expected
                    || lineage.guard_digest != guard
                    || lineage.loss_generation != next.loss_generation
                    || !next
                        .sources
                        .iter()
                        .any(|row| row.name == lineage.source_name && row.digest == expected)
                {
                    return Err(corrupt());
                }
                self.verify_candidate_change(&checked, &lineage).await?;
            }
            _ => return Err(corrupt()),
        }
        let publication =
            crate::store::native_publication_effects::publish_checked(self.fs(), &checked).await?;
        let selected = self.selected_held().await?;
        if (selected.state.revision, selected.digest) != (publication.revision, publication.digest)
            || selected.state != *next
            || selected.logical != logical
        {
            return Err(corrupt());
        }
        for source in checked.sources() {
            let expected = if source.state().binding == current.state.binding {
                &selected
            } else {
                &source.selected
            };
            source.revalidate_against(expected).await?;
        }
        Ok(receipt(selected))
    }

    // Fixed source associations supplement the sealed producer's complete actual
    // trust/Original/interpretation checks; they never qualify decoded evidence.
    async fn verify_guard_carry(
        &self,
        checked: &CheckedMutation<'_, '_>,
    ) -> Result<(), StoreFailure> {
        let observed = checked.observed();
        let carried = checked.guard_carried_lineages();
        if carried.len() != checked.next().sources.len() {
            return Err(corrupt());
        }
        if carried.is_empty() {
            return Ok(());
        }

        let context = checked.effect_context().ok_or_else(super::unsupported)?;
        let previous_guard = self
            .selected_guard_snapshot_record(observed)
            .await?
            .ok_or_else(corrupt)?;
        let previous_bytes = previous_guard.bytes().ok_or_else(corrupt)?;
        let previous_digest = digest(previous_bytes);
        if observed.state().guard != Some(previous_digest)
            || !context.selected_reads().iter().any(|read| {
                read.record().path() == previous_guard.path()
                    && read.record().bytes() == previous_guard.bytes()
                    && read.owner() == observed.configured_operator_uid()
            })
        {
            return Err(corrupt());
        }

        let guard = digest(checked.guard_snapshot());
        for (next_source, output) in checked.next().sources.iter().zip(carried) {
            if next_source.name != output.previous().name
                || next_source.digest != digest(output.lineage())
                || !observed.state().sources.contains(output.previous())
            {
                return Err(corrupt());
            }
            let previous = self
                .selected_lineage_record(observed, &next_source.name)
                .await?
                .ok_or_else(corrupt)?;
            let bytes = previous.bytes().ok_or_else(corrupt)?;
            if digest(bytes) != output.previous().digest
                || !context.selected_reads().iter().any(|read| {
                    read.record().path() == previous.path()
                        && read.record().bytes() == previous.bytes()
                        && read.owner() == observed.configured_operator_uid()
                })
            {
                return Err(corrupt());
            }

            let mut expected = CheckedLineage::decode(bytes).map_err(|_| corrupt())?;
            let fresh = CheckedLineage::decode(output.lineage()).map_err(|_| corrupt())?;
            let key = format!("{}:record", next_source.name);
            let record = observed
                .logical()
                .get(&key)
                .and_then(Option::as_deref)
                .ok_or_else(corrupt)?;
            let record = RefRecord::decode(record).map_err(|_| corrupt())?;
            if expected.source_name != next_source.name
                || expected.source != record
                || expected.guard_digest != previous_digest
                || expected.loss_generation != observed.state().loss_generation
            {
                return Err(corrupt());
            }
            expected
                .check_guard_snapshot(previous_bytes)
                .map_err(|_| corrupt())?;
            expected.guard_digest = guard;
            if fresh != expected {
                return Err(corrupt());
            }
            fresh
                .check_guard_snapshot(checked.guard_snapshot())
                .map_err(|_| corrupt())?;
        }
        Ok(())
    }

    async fn verify_candidate_change(
        &self,
        checked: &CheckedMutation<'_, '_>,
        lineage: &CheckedLineage,
    ) -> Result<(), StoreFailure> {
        let key = format!("{}:record", lineage.source_name);
        if checked.changes().iter().any(|change| {
            change.key != key
                && change.key != "CAPABILITIES"
                && change.key != "publication/SELECTED-HISTORY"
        }) {
            return Err(corrupt());
        }
        let change = checked
            .changes()
            .iter()
            .find(|change| change.key == key)
            .ok_or_else(corrupt)?;
        let new =
            RefRecord::decode(change.new.as_deref().ok_or_else(corrupt)?).map_err(|_| corrupt())?;
        if new != lineage.source {
            return Err(corrupt());
        }
        let expected = change
            .expected
            .as_deref()
            .map(RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        let candidate = new.candidate_id.ok_or_else(corrupt)?;
        let proposal_key = BucketKey::reflog_candidate(&lineage.source_name, new.seq, &candidate)
            .map_err(|_| corrupt())?;
        let bytes = self
            .bucket()
            .read_optional(&proposal_key)
            .await?
            .ok_or_else(corrupt)?;
        let log = RefLogRecord::decode(&bytes).map_err(|_| corrupt())?;
        log.validate_candidate(expected.as_ref(), &new)
            .map_err(|_| corrupt())?;
        let retained = checked
            .observed()
            .state()
            .branches
            .iter()
            .find(|row| row.name == lineage.source_name)
            .map(|row| &row.selection);
        let previous = match retained {
            Some(terrane_core::gc::publication::CommittedSelection::Selected(previous)) => {
                Some(previous.as_ref())
            }
            Some(terrane_core::gc::publication::CommittedSelection::Unknown) => {
                return Err(corrupt());
            }
            _ => None,
        };
        if log.selected_previous().map_err(|_| corrupt())? != previous {
            return Err(corrupt());
        }
        Ok(())
    }
}

/// Checks fixed advisory data without granting publication authority.
///
/// Admission requires the sealed producer and its final operation check.
///
/// # Errors
/// Rejects changes outside one ordinary tag or Notes write, altered selected
/// evidence, invalid whole-record successors and inconsistent inventory changes.
pub(super) fn verify_advisory_change(
    observed: &SelectedObservation<'_>,
    next: &PublicationState,
    changes: &[LogicalChange],
) -> Result<(), StoreFailure> {
    if next.guard != observed.state().guard
        || next.branches != observed.state().branches
        || next.sources != observed.state().sources
    {
        return Err(corrupt());
    }

    let mut records = changes
        .iter()
        .filter_map(|row| row.key.strip_suffix(":record").map(|name| (name, row)));
    let (name, change) = records.next().ok_or_else(corrupt)?;
    if records.next().is_some()
        || !matches!(
            RefName::parse(name).map_err(|_| corrupt())?.class(),
            RefClass::Tags | RefClass::Notes
        )
    {
        return Err(corrupt());
    }

    let record =
        RefRecord::decode(change.new.as_deref().ok_or_else(corrupt)?).map_err(|_| corrupt())?;
    let (expected_state, expected_changes) = observed.ref_transition(name, &record)?;
    if *next != expected_state || changes != expected_changes {
        return Err(corrupt());
    }
    Ok(())
}

fn receipt(selected: Selected) -> SelectedReceipt {
    SelectedReceipt {
        stamp: (selected.state.revision, selected.digest),
        state: selected.state,
    }
}
