//! Defines one actual shared original Source and its complete historical graph.
//!
//! Ticket histories refer to this definition through the same finite alias bank.
//! Historical issuance, target and failed phases stay DATA. No constructor here
//! creates a Source, ticket, weak Plan upgrade, native context or live target.

use super::collecting::CollectingTargetPhase;
use super::*;
use crate::node_admission::WeakInstalledConformancePlan;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRow,
    OriginalRestoredOwnerCapacityRows,
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::Ref;

#[path = "history/portable_capacities.rs"]
mod portable_capacities;

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
struct IssuanceFacts {
    host_issued: bool,
    native_issued: [bool; 4],
    target_started: bool,
    restoration_transactions: Option<[bool; 4]>,
}

impl IssuanceFacts {
    fn from_source(source: &CompleteOriginalSource) -> Self {
        Self {
            host_issued: source.host_issued.get(),
            native_issued: source.native_issued.get(),
            target_started: source.target_started.get(),
            restoration_transactions: source.restoration_transactions.get(),
        }
    }
}

/// Borrows one complete original Source as inert historical DATA.
///
/// The loan retains actual RefCell guards and no new strong ownership. It has
/// no constructor, Clone, Deserialize or conversion into restoration authority.
pub struct CompleteOriginalSourceHistory<'a> {
    source: &'a CompleteOriginalRestorationSource,
    target: Ref<'a, Option<Rc<()>>>,
    collecting: Option<Ref<'a, CollectingTargetPhase>>,
    issuance: IssuanceFacts,
}

impl CompleteOriginalRestorationSource {
    /// Borrows the complete original Source without decoding or copying owners.
    ///
    /// The enclosing writer encodes this definition once and links its actual
    /// ticket edges with the same precharged alias bank. Separate allocation
    /// admission must precede encoder, output and reader reconstruction work.
    ///
    /// # Errors
    /// Refuses foreign creator custody or busy actual target/collecting loans.
    pub fn borrowed_settled_history_data(
        &self,
    ) -> Result<CompleteOriginalSourceHistory<'_>, RuntimeError> {
        self.inner.authenticate_birth()?;
        let target = self
            .inner
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let collecting = match &self.inner.purpose {
            CompleteOriginalSourcePurpose::Ordinary => None,
            CompleteOriginalSourcePurpose::Collecting {
                validation_plan: _,
                target,
            } => Some(target.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?),
        };
        let issuance = IssuanceFacts::from_source(&self.inner);
        self.inner.authenticate_birth()?;
        Ok(CompleteOriginalSourceHistory {
            source: self,
            target,
            collecting,
            issuance,
        })
    }
}

impl<'a> CompleteOriginalSourceHistory<'a> {
    pub(crate) fn with_aliases<'view>(
        &'view self,
        aliases: &'view RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> impl Serialize + 'view {
        SourceHistoryView {
            original: self,
            aliases,
        }
    }

    pub(crate) fn metadata_demand_data(&self) -> Result<(usize, usize), RuntimeError> {
        self.authenticate()?;
        let source = &self.source.inner;
        let archive = source
            .archive
            .borrowed_settled_archive_history_data()?
            .metadata_demand_data()?;
        let content = source
            .content
            .borrowed_settled_history_data()
            .metadata_demand_data()?;
        let administrative =
            OriginalRestoredOwnerCapacityRows(&source.administrative).metadata_demand_data()?;
        let host = OriginalRestoredOwnerCapacityRows(&source.host).metadata_demand_data()?;
        let runtime = OriginalRestoredOwnerCapacityRows(&source.runtime).metadata_demand_data()?;
        let mut rows = 2usize;
        let mut shared = 2usize; // actual Source and actual Host record
        for (count, edges) in [archive, content, administrative, host, runtime] {
            rows = rows.checked_add(count).ok_or(RuntimeError::ResourceLimit)?;
            shared = shared
                .checked_add(edges)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if self.target.is_some() {
            rows = rows.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            shared = shared.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(phase) = &self.collecting {
            let edges = 1 + usize::from(matches!(&**phase, CollectingTargetPhase::Bound(_)));
            rows = rows.checked_add(edges).ok_or(RuntimeError::ResourceLimit)?;
            shared = shared
                .checked_add(edges)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        self.authenticate()?;
        Ok((rows, shared))
    }

    pub(crate) fn base64_temporary_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.authenticate()?;
        self.source
            .inner
            .content
            .borrowed_settled_history_data()
            .base64_temporary_bytes_data()
    }

    fn authenticate(&self) -> Result<(), RuntimeError> {
        self.source.inner.authenticate_birth()?;
        if self.issuance != IssuanceFacts::from_source(&self.source.inner) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

struct SourceHistoryView<'view, 'source> {
    original: &'view CompleteOriginalSourceHistory<'source>,
    aliases: &'view RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl Serialize for SourceHistoryView<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.original
            .metadata_demand_data()
            .map_err(S::Error::custom)?;
        let CompleteOriginalSource {
            archive,
            content,
            administrative,
            host,
            runtime,
            purpose,
            native_restoration_data,
            settled_restoration_data: _,
            restored_collection: _,
            coordinator_checkpoint: _,
            validation_limits,
            process,
            thread: _,
            host_issued: _,
            native_issued: _,
            target_started: _,
            target: _,
            restoration_transactions: _,
        } = self.original.source.inner.as_ref();
        let source_edge = self
            .aliases
            .try_borrow_mut()
            .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?
            .shared_owner_data(&self.original.source.inner)
            .map_err(S::Error::custom)?;
        let host_edge = {
            let mut aliases = self
                .aliases
                .try_borrow_mut()
                .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?;
            match host {
                CompleteHostArchiveRecord::InitialInvocation15(record) => {
                    aliases.shared_owner_data(record)
                }
                CompleteHostArchiveRecord::Settled17(record) => aliases.shared_owner_data(record),
            }
            .map_err(S::Error::custom)?
        };
        let target_edge = self
            .original
            .target
            .as_ref()
            .map(|target| {
                self.aliases
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .shared_owner_data(target)
            })
            .transpose()
            .map_err(S::Error::custom)?;
        let archive = archive
            .borrowed_settled_archive_history_data()
            .map_err(S::Error::custom)?;

        let mut value = serializer.serialize_struct("CompleteOriginalSourceHistory", 17)?;
        value.serialize_field(
            "schema",
            "source-private.complete-original-source-history/1",
        )?;
        value.serialize_field("role", "complete_original_source")?;
        value.serialize_field("source_edge", &source_edge)?;
        value.serialize_field("archive", &archive.with_aliases(self.aliases))?;
        value.serialize_field("content", &content.borrowed_settled_history_data())?;
        value.serialize_field("administrative", administrative)?;
        value.serialize_field(
            "administrative_capacities",
            &OriginalRestoredOwnerCapacityRows(administrative),
        )?;
        value.serialize_field("host_edge", &host_edge)?;
        value.serialize_field("host", host)?;
        value.serialize_field("host_capacities", &OriginalRestoredOwnerCapacityRows(host))?;
        value.serialize_field("runtime_object", runtime)?;
        value.serialize_field(
            "runtime_object_capacities",
            &OriginalRestoredOwnerCapacityRows(runtime),
        )?;
        value.serialize_field(
            "purpose",
            &PurposeHistory {
                purpose,
                phase: self.original.collecting.as_deref(),
                aliases: self.aliases,
            },
        )?;
        value.serialize_field(
            "native_restoration_data",
            &NativeRows(native_restoration_data),
        )?;
        value.serialize_field("validation_limits", &ValidationLimits(validation_limits))?;
        value.serialize_field(
            "creator",
            &(process, "original-creator-thread-not-portable"),
        )?;
        value.serialize_field("issuance", &(&self.original.issuance, &target_edge))?;
        let completed = value.end()?;
        self.original.authenticate().map_err(S::Error::custom)?;
        Ok(completed)
    }
}

struct PurposeHistory<'a> {
    purpose: &'a CompleteOriginalSourcePurpose,
    phase: Option<&'a CollectingTargetPhase>,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl Serialize for PurposeHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        match self.purpose {
            CompleteOriginalSourcePurpose::Ordinary => {
                if self.phase.is_some() {
                    return Err(S::Error::custom(RuntimeError::ForeignAuthority));
                }
                serializer.serialize_str("ordinary")
            }
            CompleteOriginalSourcePurpose::Collecting {
                validation_plan,
                target: _,
            } => {
                let validation = validation_plan
                    .borrowed_settled_role_data(
                        &mut *self
                            .aliases
                            .try_borrow_mut()
                            .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?,
                    )
                    .map_err(S::Error::custom)?;
                let (phase, target) = match self
                    .phase
                    .ok_or_else(|| S::Error::custom(RuntimeError::ForeignAuthority))?
                {
                    CollectingTargetPhase::Unbound => ("unbound", None),
                    CollectingTargetPhase::Binding => ("binding", None),
                    CollectingTargetPhase::Failed => ("failed", None),
                    CollectingTargetPhase::Bound(target) => (
                        "bound",
                        Some(
                            target
                                .borrowed_settled_role_data(
                                    &mut *self
                                        .aliases
                                        .try_borrow_mut()
                                        .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?,
                                )
                                .map_err(S::Error::custom)?,
                        ),
                    ),
                };
                let mut value = serializer.serialize_struct("CollectingSourceHistory", 3)?;
                value.serialize_field("validation_plan_edge", &validation)?;
                value.serialize_field("phase", phase)?;
                value.serialize_field("target_plan_edge", &target)?;
                value.end()
            }
        }
    }
}

struct NativeRows<'a>(&'a [Option<super::super::CompleteOriginalNativeRestorationData>; 4]);

impl Serialize for NativeRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for row in self.0 {
            values
                .serialize_element(&row.as_ref().map(|row| row.borrowed_settled_history_data()))?;
        }
        values.end()
    }
}

struct ValidationLimits<'a>(&'a HostSchedulingContinuationLimits);

impl Serialize for ValidationLimits<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let HostSchedulingContinuationLimits {
            maximum_record_bytes,
            lineage,
        } = self.0;
        let crate::node_contract::OriginalInputLineageLimits {
            maximum_objects,
            maximum_bytes,
            maximum_edges,
        } = lineage;
        let mut value = serializer.serialize_struct("OriginalSourceValidationLimits", 4)?;
        value.serialize_field("maximum_record_bytes", maximum_record_bytes)?;
        value.serialize_field("maximum_objects", maximum_objects)?;
        value.serialize_field("maximum_bytes", maximum_bytes)?;
        value.serialize_field("maximum_edges", maximum_edges)?;
        value.end()
    }
}

impl CompleteOriginalRestorationSource {
    /// Names complete Source historical wrapper, field-loan and cursor views.
    ///
    /// This fixed counter conjoins each defining child and the common metadata
    /// vocabulary. Alias-bank backing, base64 temporary, output, serializer work
    /// and later sealed historical reconstruction stay separately admitted.
    pub fn settled_history_counter_scratch_data() -> usize {
        use super::super::CompleteOriginalNativeRestorationData;
        use crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data;
        use std::cell::{BorrowError, BorrowMutError, RefMut};
        use std::mem::{size_of, size_of_val};

        let terms = [
            original_restored_owner_capacity_counter_scratch_data(),
            portable_capacities::counter_scratch_data(),
            NativeArchiveRecord::settled_history_counter_scratch_data(),
            VerifiedStateContent::settled_history_counter_scratch_data(),
            CompleteOriginalNativeRestorationData::settled_history_counter_scratch_data(),
            WeakInstalledConformancePlan::settled_history_counter_scratch_data(),
            size_of::<CompleteOriginalSourceHistory<'static>>(),
            size_of::<Result<CompleteOriginalSourceHistory<'static>, RuntimeError>>(),
            size_of::<SourceHistoryView<'static, 'static>>(),
            size_of::<PurposeHistory<'static>>(),
            size_of::<NativeRows<'static>>(),
            size_of::<ValidationLimits<'static>>(),
            size_of::<IssuanceFacts>(),
            size_of::<(
                &NativeArchiveRecord,
                &VerifiedStateContent,
                &RuntimeOriginalCaptureJournal,
                &Rc<HostSchedulingContinuationRecord>,
                &ContentRef,
                &CompleteOriginalSourcePurpose,
                &[Option<CompleteOriginalNativeRestorationData>; 4],
                &HostSchedulingContinuationLimits,
                &u32,
                &ThreadId,
                &Cell<bool>,
                &Cell<[bool; 4]>,
                &Cell<bool>,
                &RefCell<Option<Rc<()>>>,
                &Cell<Option<[bool; 4]>>,
            )>(),
            size_of::<Ref<'static, Option<Rc<()>>>>(),
            size_of::<Result<Ref<'static, Option<Rc<()>>>, BorrowError>>(),
            size_of::<Result<Ref<'static, Option<Rc<()>>>, RuntimeError>>(),
            size_of::<Ref<'static, CollectingTargetPhase>>(),
            size_of::<Option<Ref<'static, CollectingTargetPhase>>>(),
            size_of::<Result<Ref<'static, CollectingTargetPhase>, BorrowError>>(),
            size_of::<Result<Ref<'static, CollectingTargetPhase>, RuntimeError>>(),
            size_of::<Option<&CollectingTargetPhase>>(),
            size_of::<Result<&CollectingTargetPhase, RuntimeError>>(),
            size_of::<&WeakInstalledConformancePlan>(),
            size_of::<&CompleteOriginalSourcePurpose>(),
            size_of::<&CompleteOriginalRestorationSource>(),
            size_of::<&CompleteOriginalSource>(),
            size_of::<&Rc<CompleteOriginalSource>>(),
            size_of::<Option<&Rc<()>>>(),
            size_of::<(
                &WeakInstalledConformancePlan,
                &RefCell<CollectingTargetPhase>,
            )>(),
            size_of::<(&str, Option<OriginalRestoredOwnerCapacityRow>)>(),
            size_of::<RefMut<'static, OriginalRestoredOwnerCapacityAliases>>(),
            size_of::<Result<RefMut<'static, OriginalRestoredOwnerCapacityAliases>, BorrowMutError>>(
            ),
            size_of::<Result<RefMut<'static, OriginalRestoredOwnerCapacityAliases>, RuntimeError>>(
            ),
            size_of::<OriginalRestoredOwnerCapacityRow>(),
            size_of::<Option<OriginalRestoredOwnerCapacityRow>>(),
            size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>(),
            size_of::<Option<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>>(),
            size_of::<Result<Option<OriginalRestoredOwnerCapacityRow>, RuntimeError>>(),
            size_of::<[usize; 2]>(),
            size_of::<[(usize, usize); 5]>(),
            size_of::<std::array::IntoIter<(usize, usize), 5>>(),
            size_of::<Result<(usize, usize), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<std::slice::Iter<'static, Option<CompleteOriginalNativeRestorationData>>>(),
            size_of::<Option<&CompleteOriginalNativeRestorationData>>(),
            size_of::<(&usize, &crate::node_contract::OriginalInputLineageLimits)>(),
            size_of::<(&usize, &usize, &usize)>(),
            size_of::<(&IssuanceFacts, &Option<OriginalRestoredOwnerCapacityRow>)>(),
            size_of::<(&u32, &str)>(),
            size_of::<OriginalRestoredOwnerCapacityRows<'static, RuntimeOriginalCaptureJournal>>(),
            size_of::<OriginalRestoredOwnerCapacityRows<'static, HostSchedulingContinuationRecord>>(
            ),
            size_of::<OriginalRestoredOwnerCapacityRows<'static, ContentRef>>(),
        ];
        let array_bytes = size_of_val(&terms);
        let mut iterator = terms.into_iter();
        let iterator_bytes = size_of_val(&iterator);
        array_bytes
            .checked_add(iterator_bytes)
            .and_then(|initial| iterator.try_fold(initial, usize::checked_add))
            .unwrap_or(usize::MAX)
    }
}
