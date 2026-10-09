//! Separately named native DATA geometry for actual Root V2 and Provider shapes.
//!
//! Root edges borrow complete checked graphs and retain exact canonical adjacency;
//! Provider edges remain syntactic until the Source owner validates its sealed
//! proposal. Both profiles measure the unchanged version3 namespace46 format.

use std::collections::BTreeSet;

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeDataClassV2, RootNativeTransitionKindV2,
};

use super::super::{
    NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3, invalid, root_v2::RootCapacityEdgeV2,
};
use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, MeasurementAppend,
    NativeHeldCapacityChangeV3, NativeHeldCapacityGeometryV3, NativeHeldCapacityPathV3,
    NativeHeldCapacityPurposeV3, NativeHeldCapacityStepV3, closed_path_shape, measure_appends,
    normal_successor, require_changes, require_owner_shape,
};

/// Names an actual Root V2 edge or the existing Provider append schedule as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHeldCapacityStepV2 {
    /// Uses the kind rederived from the complete actual Root V2 owner graphs.
    Root(RootNativeTransitionKindV2),
    /// Uses the existing Provider slot; slot18 additionally permits five owners.
    Provider(NativeHeldCapacityStepV3),
}

/// Holds exact owner changes and, for Root, borrowed validated graph continuity.
#[derive(Clone, Debug)]
pub struct NativeHeldCapacityAppendV2<'graph> {
    step: NativeHeldCapacityStepV2,
    transaction_id: [u8; 16],
    changes: Vec<NativeHeldCapacityChangeV3>,
    root: Option<RootCapacityEdgeV2<'graph>>,
}

impl NativeHeldCapacityAppendV2<'_> {
    /// Constructs only syntactic Provider DATA from exact owner proposal bytes.
    ///
    /// The future Source bridge must validate its sealed proposal, all touched
    /// before bytes and its complete graph. This constructor cannot prove them.
    /// Root DATA can only be constructed through the graph-rederiving adapter.
    ///
    /// # Errors
    ///
    /// Rejects Root slots, invalid/duplicate mutations or a wrong Provider shape.
    /// Slot18 permits exactly native40 alone or the five pending-retirement owners.
    /// Cleanup additionally permits the actual95-byte Release key, with at most
    /// six owner changes; independent status floors remain separate obligations.
    pub fn provider(
        step: NativeHeldCapacityStepV3,
        transaction_id: [u8; 16],
        changes: Vec<NativeHeldCapacityChangeV3>,
    ) -> Result<Self, JournalError> {
        if step.owner_and_slot().0 != NativeHeldCapacityPurposeV3::Provider {
            return Err(invalid("Root slot in Provider capacity DATA"));
        }
        if matches!(
            step,
            NativeHeldCapacityStepV3::ProviderRootTerminalStored
                | NativeHeldCapacityStepV3::ProviderLifecycleCleanup
        ) {
            require_changes(transaction_id, &changes)?;
            let mut widths = changes
                .iter()
                .map(|change| change.key.len())
                .collect::<Vec<_>>();
            widths.sort_unstable();
            let valid = if step == NativeHeldCapacityStepV3::ProviderRootTerminalStored {
                (widths == [40] || widths == [40, 63, 96, 99, 103])
                    && changes
                        .iter()
                        .all(|change| change.before.is_some() && change.after.is_some())
            } else {
                // The actual Release key is95; legacy V3 retains its unchanged
                // conservative99-byte family bound and old syntax separately.
                widths.len() <= 6
                    && widths
                        .iter()
                        .all(|width| [40, 49, 63, 95, 96, 99, 103].contains(width))
            };
            if !valid {
                return Err(invalid("Provider terminal DATA owner shape"));
            }
        } else {
            // Preserve the old exact syntax for every other Provider slot.
            require_changes(transaction_id, &changes)?;
            require_owner_shape(step, &changes)?;
        }
        Ok(Self {
            step: NativeHeldCapacityStepV2::Provider(step),
            transaction_id,
            changes,
            root: None,
        })
    }

    /// Returns the DATA append kind without granting its owner scope.
    #[must_use]
    pub const fn step(&self) -> NativeHeldCapacityStepV2 {
        self.step
    }

    pub(super) fn measurement(&self) -> MeasurementAppend<'_> {
        MeasurementAppend {
            transaction_id: self.transaction_id,
            changes: &self.changes,
            final_append: self.is_final(),
        }
    }

    fn purpose(&self) -> NativeHeldCapacityPurposeV3 {
        match self.step {
            NativeHeldCapacityStepV2::Root(_) => NativeHeldCapacityPurposeV3::Root,
            NativeHeldCapacityStepV2::Provider(step) => step.owner_and_slot().0,
        }
    }

    fn is_final(&self) -> bool {
        match self.step {
            NativeHeldCapacityStepV2::Root(kind) => matches!(
                kind,
                RootNativeTransitionKindV2::TerminalAckStored
                    | RootNativeTransitionKindV2::NativeNoInterestCleanup
            ),
            NativeHeldCapacityStepV2::Provider(step) => step.is_final(),
        }
    }

    pub(in crate::journal::capacity_reservation::native_held) fn owner_records(
        &self,
    ) -> Vec<JournalRecord> {
        let namespace = self.purpose().owner_namespace();
        self.changes
            .iter()
            .map(|change| match &change.after {
                Some(value) => JournalRecord::put(namespace, change.key.clone(), value.clone()),
                None => JournalRecord::delete(namespace, change.key.clone()),
            })
            .collect()
    }

    pub(in crate::journal::capacity_reservation::native_held) fn root_edge(
        &self,
    ) -> Option<&RootCapacityEdgeV2<'_>> {
        self.root.as_ref()
    }
}

impl<'graph> NativeHeldCapacityAppendV2<'graph> {
    pub(in crate::journal::capacity_reservation::native_held) fn root(
        edge: RootCapacityEdgeV2<'graph>,
        transaction_id: [u8; 16],
        changes: Vec<NativeHeldCapacityChangeV3>,
    ) -> Result<Self, JournalError> {
        require_changes(transaction_id, &changes)?;
        Ok(Self {
            step: NativeHeldCapacityStepV2::Root(edge.kind),
            transaction_id,
            changes,
            root: Some(edge),
        })
    }
}

/// Retains a complete V2 DATA continuation without changing the capacity wire.
#[derive(Clone, Debug)]
pub struct NativeHeldCapacitySuffixV2<'graph> {
    purpose: NativeHeldCapacityPurposeV3,
    path: NativeHeldCapacityPathV3,
    appends: Vec<NativeHeldCapacityAppendV2<'graph>>,
}

impl<'graph> NativeHeldCapacitySuffixV2<'graph> {
    /// Validates complete Root graph continuity or the fixed Provider slot grammar.
    ///
    /// Root uses actual reducer edges instead of guessed cold slot numbering.
    /// Provider chronology is mechanical DATA; Source must prove actual owners.
    ///
    /// # Errors
    ///
    /// Rejects mixed owners, missing retirement, duplicate TXs, excess count,
    /// discontinuous Root graphs/bindings/counts or an invalid Provider schedule.
    pub fn new(
        purpose: NativeHeldCapacityPurposeV3,
        path: NativeHeldCapacityPathV3,
        appends: Vec<NativeHeldCapacityAppendV2<'graph>>,
    ) -> Result<Self, JournalError> {
        if appends.is_empty() || appends.len() > purpose.maximum_future_transactions() as usize {
            return Err(invalid("native V2 complete suffix count"));
        }
        let mut transactions = BTreeSet::new();
        for (index, append) in appends.iter().enumerate() {
            if append.purpose() != purpose
                || !transactions.insert(append.transaction_id)
                || (append.is_final() && index + 1 != appends.len())
            {
                return Err(invalid("native V2 suffix owner or retirement"));
            }
        }
        if !appends
            .last()
            .is_some_and(NativeHeldCapacityAppendV2::is_final)
        {
            return Err(invalid("native V2 suffix lacks retirement"));
        }
        match purpose {
            NativeHeldCapacityPurposeV3::Root => require_root_chain(&appends)?,
            NativeHeldCapacityPurposeV3::Provider => require_provider_chain(path, &appends)?,
        }
        Ok(Self {
            purpose,
            path,
            appends,
        })
    }

    /// Returns the fixed owner represented by the DATA continuation.
    #[must_use]
    pub const fn purpose(&self) -> NativeHeldCapacityPurposeV3 {
        self.purpose
    }

    /// Returns the DATA continuation class, never a signing/effect permission.
    #[must_use]
    pub const fn path(&self) -> NativeHeldCapacityPathV3 {
        self.path
    }

    /// Measures complete journal framing and exact relative retained growth.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent before-images, arithmetic overflow or unchanged
    /// per-transaction/aggregate limits. All other floors must be checked too.
    pub fn measure(
        &self,
        limits: JournalLimits,
    ) -> Result<NativeHeldCapacityGeometryV3, JournalError> {
        self.measure_with_floor_value_bytes(limits, super::NATIVE_HELD_CAPACITY_VALUE_BYTES_V3)
    }

    // The original Source adapter derives this width from its canonical codec.
    // It remains framing DATA, not branch coverage or full coupled growth.
    pub(in crate::journal) fn measure_with_floor_value_bytes(
        &self,
        limits: JournalLimits,
        floor_value_bytes: usize,
    ) -> Result<NativeHeldCapacityGeometryV3, JournalError> {
        measure_appends(
            self.purpose,
            self.appends.iter().map(|append| MeasurementAppend {
                transaction_id: append.transaction_id,
                changes: &append.changes,
                final_append: append.is_final(),
            }),
            limits,
            floor_value_bytes,
        )
    }

    pub(in crate::journal::capacity_reservation::native_held) fn root_start(
        &self,
    ) -> Option<&RootCapacityEdgeV2<'graph>> {
        self.appends.first().and_then(|append| append.root.as_ref())
    }

    fn has_cold_root_edge(&self) -> bool {
        self.appends.iter().any(|append| {
            matches!(
                append.step,
                NativeHeldCapacityStepV2::Root(
                    RootNativeTransitionKindV2::ClosedAssertionRecorded
                        | RootNativeTransitionKindV2::NativeRecoveryReplacement
                        | RootNativeTransitionKindV2::NativeRecoveryInventoryReserved
                        | RootNativeTransitionKindV2::NativeRecoveryInventoryResolved
                        | RootNativeTransitionKindV2::NativeNoInterestCleanup
                )
            )
        })
    }
}

fn require_root_chain(appends: &[NativeHeldCapacityAppendV2<'_>]) -> Result<(), JournalError> {
    let mut previous: Option<&RootCapacityEdgeV2<'_>> = None;
    for append in appends {
        let edge = append
            .root
            .as_ref()
            .ok_or(invalid("native V2 Root edge absent"))?;
        if edge.after_remaining >= edge.before_remaining || edge.before_remaining > 7 {
            return Err(invalid("native V2 Root reducer count"));
        }
        if let Some(previous) = previous {
            if previous.after.canonical_records() != edge.before.canonical_records()
                || previous.original.canonical_records() != edge.original.canonical_records()
                || previous.binding != edge.binding
                || previous.after_remaining != edge.before_remaining
            {
                return Err(invalid("native V2 Root canonical graph discontinuity"));
            }
        }
        // Root path labels select alternatives for DATA measurement. The actual
        // reducer edge/graph chain, not a second phase grammar, proves legality;
        // after a cold-only prefix both labelled alternatives may be identical.
        previous = Some(edge);
    }
    if previous.is_none_or(|edge| edge.after_remaining != 0) {
        return Err(invalid("native V2 Root suffix remains outstanding"));
    }
    Ok(())
}

fn require_provider_chain(
    path: NativeHeldCapacityPathV3,
    appends: &[NativeHeldCapacityAppendV2<'_>],
) -> Result<(), JournalError> {
    let mut slots = Vec::with_capacity(appends.len());
    for append in appends {
        let NativeHeldCapacityStepV2::Provider(step) = append.step else {
            return Err(invalid("native V2 Provider slot absent"));
        };
        let slot = step.owner_and_slot().1;
        if let Some(previous) = slots.last().copied() {
            if slot <= previous
                || (path == NativeHeldCapacityPathV3::Normal
                    && !normal_successor(NativeHeldCapacityPurposeV3::Provider, previous, slot))
            {
                return Err(invalid("native V2 Provider chronology"));
            }
        }
        if path == NativeHeldCapacityPathV3::Normal && (12..=17).contains(&slot) {
            return Err(invalid("native V2 recovery slot in normal suffix"));
        }
        slots.push(slot);
    }
    if !closed_path_shape(NativeHeldCapacityPurposeV3::Provider, path, &slots) {
        return Err(invalid("native V2 Provider closed chronology"));
    }
    Ok(())
}

impl NativeHeldCapacityRecordV3 {
    /// Derives unchanged V3 wire DATA from both complete named V2 continuations.
    ///
    /// This measures the supplied complete alternatives; it does not prove they
    /// attain every legal branch maximum. A future protected original producer
    /// must derive all relevant alternatives and whole-snapshot headroom before
    /// escape. DATA path labels and these measurements grant no admission.
    ///
    /// # Errors
    ///
    /// Rejects foreign classes/bindings, different Root starting graphs, count
    /// underfunding, malformed suffixes or unchanged journal ceiling violations.
    pub fn from_suffixes_v2(
        mut request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
        normal: &NativeHeldCapacitySuffixV2<'_>,
        closed_or_recovery: &NativeHeldCapacitySuffixV2<'_>,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        if normal.purpose != request.purpose
            || closed_or_recovery.purpose != request.purpose
            || normal.path != NativeHeldCapacityPathV3::Normal
            || closed_or_recovery.path == NativeHeldCapacityPathV3::Normal
        {
            return Err(invalid("native V2 capacity continuation classes"));
        }
        let terminal = normal.measure(limits)?;
        let poison = closed_or_recovery.measure(limits)?;
        request.future_transactions = terminal.transactions.max(poison.transactions);
        request.terminal_records = terminal.records;
        request.terminal_bytes = terminal.append_bytes;
        request.poison_records = poison.records;
        request.poison_bytes = poison.append_bytes;
        if request.purpose == NativeHeldCapacityPurposeV3::Root {
            let first = normal
                .root_start()
                .ok_or(invalid("native V2 normal Root start absent"))?;
            let cold = closed_or_recovery
                .root_start()
                .ok_or(invalid("native V2 cold Root start absent"))?;
            if first.before.canonical_records() != cold.before.canonical_records()
                || first.original.canonical_records() != cold.original.canonical_records()
                || first.binding != cold.binding
                || request.future_transactions != first.before_remaining
            {
                return Err(invalid("native V2 complete Root alternatives or count"));
            }
            let attempt = first.binding.mount_attempt();
            let original_phase0 = first
                .before
                .sidecars()
                .get(&attempt)
                .is_some_and(|sidecar| sidecar.suffix().phase() == 0)
                && first.before.data_class(attempt) == Some(RootNativeDataClassV2::LiveOriginal);
            if original_phase0 && !closed_or_recovery.has_cold_root_edge() {
                return Err(invalid(
                    "native V2 original admission lacks an actual cold alternative",
                ));
            }
            first.binding.require_request(request, admission)?;
        }
        Self::new(request, admission)
    }
}

/// Frames a Provider V2 DATA edge with its complete measured V3 successor floor.
///
/// Source must separately prove its sealed proposal and complete before snapshot.
/// Root terminal slot18 retains future1 cleanup credit in either owner shape.
///
/// # Errors
///
/// Rejects foreign owners, absent/enlarged continuations, nondecreasing counts,
/// premature cleanup or unchanged full framed budget/transaction-limit failures.
pub fn provider_native_capacity_transition_v2(
    append: &NativeHeldCapacityAppendV2<'_>,
    old: &NativeHeldCapacityRecordV3,
    remaining: Option<(
        &NativeHeldCapacitySuffixV2<'_>,
        &NativeHeldCapacitySuffixV2<'_>,
    )>,
    limits: JournalLimits,
) -> Result<(JournalTransaction, Option<NativeHeldCapacityRecordV3>), JournalError> {
    let cleanup = append.step
        == NativeHeldCapacityStepV2::Provider(NativeHeldCapacityStepV3::ProviderLifecycleCleanup);
    if append.purpose() != NativeHeldCapacityPurposeV3::Provider
        || old.request().purpose != NativeHeldCapacityPurposeV3::Provider
        || (cleanup && (remaining.is_some() || old.request().future_transactions != 1))
        || (!cleanup && remaining.is_none())
    {
        return Err(invalid("native V2 Provider continuation or cleanup"));
    }
    let next = remaining
        .map(|(normal, cold)| {
            NativeHeldCapacityRecordV3::from_suffixes_v2(
                old.request(),
                old.admission_transaction_id(),
                normal,
                cold,
                limits,
            )
        })
        .transpose()?;
    if next
        .as_ref()
        .is_some_and(|next| next.request().future_transactions >= old.request().future_transactions)
    {
        return Err(invalid("native V2 Provider count did not decrease"));
    }
    let transaction = super::super::transfer::frame_transfer(
        append.transaction_id,
        append.owner_records(),
        old,
        next.as_ref(),
        limits,
        (
            "native Provider consumed records",
            "native Provider complete transferred suffix",
        ),
    )?;
    Ok((transaction, next))
}

#[cfg(test)]
mod tests;
