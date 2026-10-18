//! Retains one verified complete archive beneath a genuine fresh target.
//!
//! The opaque source owns the signed archive backing and complete verified
//! closure. Its host ticket is consumed once; historical capture identities
//! remain data, while the fresh runtime separately authenticates native journals.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::thread::{self, ThreadId};

use super::*;
use crate::node_contract::{
    HostSchedulingContinuationLimits, HostSchedulingContinuationRecord,
    HostSchedulingRuntimeRecord, OriginalLineageRuntimeRecord, RuntimeError,
    RuntimeOriginalCaptureJournal,
};
use crucible_node_contract::ContentRef;

#[path = "complete_original_source/collecting.rs"]
mod collecting;
use collecting::CompleteOriginalSourcePurpose;

mod prebirth_storage;

#[path = "complete_original_source/prebirth_control.rs"]
mod prebirth_control;
pub use prebirth_control::{
    CompleteInitial15PrebirthControlInput, CompleteInitial15PrebirthControlAttempt,
    CompleteInitial15PrebirthControlConstructionData,
};

#[path = "complete_original_source/settled17.rs"]
mod settled17;

#[path = "complete_original_source/host_ancestry17.rs"]
mod host_ancestry17;

#[path = "complete_original_source/host_record.rs"]
mod host_record;
use host_record::CompleteHostArchiveRecord;

#[path = "complete_original_source/coordinator_checkpoint.rs"]
mod coordinator_checkpoint;
use coordinator_checkpoint::CompleteCoordinatorArchiveRecord;

#[path = "complete_original_source/history.rs"]
mod history;
pub use history::CompleteOriginalSourceHistory;

/// Retains a source-verified complete archive without issuing fresh readiness.
///
/// This handle has no public constructor or serialization. Source-specific
/// verification precedes its issuance; a fresh runtime must independently bind
/// the same source and validate every native target before administrative install.
pub struct CompleteOriginalRestorationSource {
    pub(crate) inner: Rc<CompleteOriginalSource>,
}

pub(crate) struct CompleteOriginalSource {
    archive: NativeArchiveRecord,
    content: VerifiedStateContent,
    administrative: RuntimeOriginalCaptureJournal,
    host: CompleteHostArchiveRecord,
    runtime: ContentRef,
    coordinator_checkpoint: Option<CompleteCoordinatorArchiveRecord>,
    purpose: CompleteOriginalSourcePurpose,
    native_restoration_data: [Option<super::CompleteOriginalNativeRestorationData>; 4],
    settled_restoration_data: [Option<super::CompleteRestoredSettledNativeRestorationData>; 4],
    restored_collection: RefCell<Option<super::RetainedCold17Collection>>,
    validation_limits: HostSchedulingContinuationLimits,
    process: u32,
    thread: ThreadId,
    host_issued: Cell<bool>,
    native_issued: Cell<[bool; 4]>,
    target_started: Cell<bool>,
    target: RefCell<Option<Rc<()>>>,
    // A selected transaction cannot renew an old final-context attempt.
    restoration_transactions: Cell<Option<[bool; 4]>>,
}

/// Carries the single source-issued host snapshot into its fresh factory.
///
/// The ticket retains verified source bytes and private source identity. It
/// grants neither native adoption nor permission to replay historical requests.
#[must_use = "retain the original archive ticket through target failure"]
pub struct CompleteOriginalHostTicket {
    pub(crate) source: Rc<CompleteOriginalSource>,
}

impl CompleteOriginalHostTicket {
    /// Borrows the genuine initial Host2 record without converting Host17.
    ///
    /// # Errors
    /// Refuses foreign custody or a ticket carrying the distinct restored family.
    pub fn record(&self) -> Result<&HostSchedulingContinuationRecord, RuntimeError> {
        self.source.authenticate_birth()?;
        self.source.host.initial_data()
    }

    /// Borrows the genuine restored Host17 record without reconstructing Host2.
    ///
    /// # Errors
    /// Refuses foreign custody or an initial-family ticket.
    pub fn restored_record_data(
        &self,
    ) -> Result<&crate::node_contract::HostSchedulingRestoredContinuationRecord17, RuntimeError>
    {
        self.source.authenticate_birth()?;
        self.source.host.restored_data()
    }

    pub(crate) fn authenticate_birth(&self) -> Result<(), RuntimeError> {
        self.source.authenticate_birth()
    }

    pub(crate) fn authenticate_context(
        &self,
        context: &crate::node_contract::OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.source
            .authenticate_legacy_restoration_context_phase_data()?;
        let target = self
            .source
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if !target
            .as_ref()
            .is_some_and(|authority| Rc::ptr_eq(authority, context.original_runtime_authority()))
            || context.source_record() != &self.source.runtime
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl CompleteOriginalRestorationSource {
    /// Issues one historical native-owner ticket before its fresh target exists.
    ///
    /// The retained source was created only after complete signed-archive and
    /// source-factory verification. This ticket borrows that exact backing;
    /// fresh process custody and the later original runtime context remain
    /// independent requirements before installation or execution.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody, a different four-owner roster,
    /// the host owner, an absent owner, repeated issuance, or a target binding
    /// that has already started. Refusal never renews spent tickets.
    pub fn take_native_ticket(
        &self,
        owner: &Id,
    ) -> Result<CompleteOriginalNativeTicket, RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner.authenticate_ticket_phase()?;
        let owners = self.inner.archive.owners();
        if owners.len() != 4 || owner == &self.inner.host.selection_data().owner.owner.id {
            return Err(RuntimeError::ForeignAuthority);
        }
        let index = owners
            .iter()
            .position(|row| &row.owner == owner)
            .ok_or(RuntimeError::ForeignAuthority)?;
        // Tickets belong to prebirth source preparation. Binding the original
        // runtime seals that roster; it cannot be extended after construction.
        let target = self
            .inner
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if self.inner.target_started.get() || target.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut issued = self.inner.native_issued.get();
        if issued[index] {
            return Err(RuntimeError::OutstandingObligations);
        }
        issued[index] = true;
        self.inner.native_issued.set(issued);
        Ok(CompleteOriginalNativeTicket {
            source: Rc::clone(&self.inner),
            owner_index: index,
        })
    }

    /// Issues the single original archive host ticket without cloning body buffers.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody, a previous ticket issuance, or
    /// target binding that has already started.
    pub fn take_host_ticket(&self) -> Result<CompleteOriginalHostTicket, RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner.authenticate_ticket_phase()?;
        if self.inner.target_started.get() || self.inner.host_issued.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(CompleteOriginalHostTicket {
            source: Rc::clone(&self.inner),
        })
    }

    /// Borrows source-verified complete content without allocating another closure.
    pub fn content(&self) -> &VerifiedStateContent {
        &self.inner.content
    }

    /// Borrows the same already verified typed Runtime7 retained in the Host record.
    ///
    /// This raw data loan allocates nothing and creates no restoration context.
    pub(crate) fn original_runtime_record_data(
        &self,
    ) -> Result<&OriginalLineageRuntimeRecord, RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner.host.runtime_data()
    }

    /// Returns this same admitted archive's retained finite decoding limits.
    ///
    /// Limits are DATA and do not renew selected-load or restoration permission.
    pub(crate) fn original_archive_limits_data(&self) -> Result<NativeArchiveLimits, RuntimeError> {
        self.inner.authenticate_birth()?;
        Ok(self.inner.archive.limits)
    }

    /// Borrows the exact archived Runtime7 identity.
    pub fn runtime_object(&self) -> &ContentRef {
        &self.inner.runtime
    }

    /// Borrows the actual signed archive backing and original owner roster.
    pub fn archive(&self) -> &NativeArchiveRecord {
        &self.inner.archive
    }
}

impl CompleteOriginalSource {
    pub(crate) fn authenticate_birth(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn collecting_plan(
        &self,
    ) -> Result<Option<crate::node_admission::InstalledConformancePlan>, RuntimeError> {
        self.authenticate_birth()?;
        self.purpose.bound_plan()
    }

    pub(crate) fn bind_target(&self, authority: &Rc<()>) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        // Physical target preparation has already happened before this call.
        // Refusal cannot reopen prebirth issuance or retrofit its missing rows.
        if self.target_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        if !self.host_issued.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owners = self.archive.owners();
        let issued = self.native_issued.get();
        let host = &self.host.selection_data().owner.owner.id;
        if owners.len() != issued.len()
            || owners.iter().filter(|row| &row.owner == host).count() != 1
            || owners
                .iter()
                .enumerate()
                .any(|(index, row)| issued[index] != (&row.owner != host))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut target = self
            .target
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if target.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *target = Some(Rc::clone(authority));
        Ok(())
    }

    pub(crate) fn authenticate_target(&self, authority: &Rc<()>) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        let target = self
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if !target
            .as_ref()
            .is_some_and(|original| Rc::ptr_eq(original, authority))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn archive(&self) -> &NativeArchiveRecord {
        &self.archive
    }

    pub(super) fn content(&self) -> &VerifiedStateContent {
        &self.content
    }

    pub(super) fn runtime_object(&self) -> &ContentRef {
        &self.runtime
    }

    pub(crate) fn administrative(&self) -> &RuntimeOriginalCaptureJournal {
        &self.administrative
    }
}

impl NativeArchiveRecord {
    /// Retains a complete source-verified archive for one fresh restoration attempt.
    ///
    /// The source-specific factory must validate all native snapshots, local
    /// settled journals and administrative dependencies before a ticket exists.
    /// Earlier index editions and unsupported factories retain their refusals.
    ///
    /// # Errors
    /// Refuses incomplete signed closure, unsupported source codecs, an absent
    /// or mismatched host snapshot, or exhausted bounded decode credit.
    pub fn into_complete_original_restoration_source(
        self,
        graph: &AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<CompleteOriginalRestorationSource, StateError> {
        self.authenticate_complete_load_admission()
            .map_err(super::super::schema)?;
        if self.collecting_complete_capture_provenance()?.is_some() {
            return Err(refused(
                "collecting archive requires its original collecting restoration route",
            ));
        }
        self.into_complete_original_restoration_source_scoped(graph, factory, limits, None)
    }

    pub(crate) fn into_complete_original_restoration_source_scoped(
        self,
        graph: &AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: HostSchedulingContinuationLimits,
        collecting_plan: Option<crate::node_admission::InstalledConformancePlan>,
    ) -> Result<CompleteOriginalRestorationSource, StateError> {
        self.authenticate_complete_load_admission()
            .map_err(super::super::schema)?;
        let (content, native_restoration_data) = self
            .complete_original_lineage_content_with_restoration_data(
                graph,
                factory,
                limits.lineage,
            )?;
        let administrative = super::complete_original_index::authenticate_admitted(
            &self,
            content
                .capture_owned_storage()
                .map_err(super::super::schema)?,
            self.limits.state.maximum_total_content_bytes,
        )?;
        let original = administrative
            .attempts
            .last()
            .ok_or_else(|| refused("complete capture history is absent"))?;
        let runtime = original.source_runtime.clone();
        let mut hosts = self.owners().iter().filter(|owner| {
            owner.key.implementation.as_str() == "source-owned.host-scheduling-owner/2"
        });
        let host = hosts
            .next()
            .ok_or_else(|| refused("complete host snapshot is absent"))?;
        if hosts.next().is_some() || !host.artifacts.is_empty() {
            return Err(refused("complete host snapshot roster differs"));
        }
        let bytes = content
            .get(&host.state)
            .ok_or_else(|| refused("complete host bytes are absent"))?;
        if bytes.len() > limits.maximum_record_bytes || limits.maximum_record_bytes == 0 {
            return Err(StateError::new(
                super::super::StateErrorCode::ResourceLimit,
                "complete original host",
                "record bytes",
            ));
        }
        super::core_decode_credit::require_original_lineage(bytes).map_err(super::super::schema)?;
        let admitted = self.limits.state.maximum_total_content_bytes;
        let decode =
            super::core_decode_credit::preflight(bytes, admitted).map_err(super::super::schema)?;
        let validation = super::core_decode_credit::validation_storage(&decode, limits)
            .map_err(super::super::schema)?;
        // Verified raw/typed content, archive metadata and admin rows survive
        // the complete Host2 decode. Canonical Runtime7 reconstruction below is
        // another DOM/encoding pass over a strict subtree of this same record.
        let common_reconstruction = decode
            .value_containers
            .checked_add(decode.parser_strings)
            .and_then(|bytes| bytes.checked_add(decode.canonical_temporaries))
            .ok_or_else(|| refused("complete host reconstruction credit overflow"))?;
        let admin_storage =
            crate::node_contract::NodeRuntime::capture_admin_storage(&administrative)
                .map_err(super::super::schema)?;
        // This clone is independent of both the admin row and archive fields,
        // and survives the decode until it moves into the retained source.
        let runtime_reference_storage =
            crate::node_contract::NodeRuntime::capture_reference_storage(&runtime)
                .map_err(super::super::schema)?;
        let retained = content
            .capture_owned_storage()
            .map_err(super::super::schema)?
            .checked_add(self.capture_owned_storage().map_err(super::super::schema)?)
            .and_then(|bytes| bytes.checked_add(admin_storage))
            .and_then(|bytes| bytes.checked_add(runtime_reference_storage))
            .ok_or_else(|| refused("complete host retained credit overflow"))?;
        let peak = decode
            .total()
            .map_err(super::super::schema)?
            .checked_add(validation)
            .and_then(|bytes| bytes.checked_add(common_reconstruction))
            .and_then(|bytes| bytes.checked_add(retained))
            .and_then(|bytes| bytes.checked_add(limits.maximum_record_bytes.checked_add(29)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                        HostSchedulingContinuationRecord,
                    >(),
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                        CompleteOriginalSource,
                    >(),
                )
            })
            .ok_or_else(|| refused("complete host restoration peak overflow"))?;
        if peak > admitted {
            return Err(StateError::new(
                super::super::StateErrorCode::ResourceLimit,
                "complete original host",
                "named restoration peak",
            ));
        }
        let record = HostSchedulingContinuationRecord::decode(bytes, limits)
            .map_err(super::super::schema)?;
        let HostSchedulingRuntimeRecord::OriginalLineage(common) = &record.runtime else {
            return Err(refused("complete host uses a legacy runtime"));
        };
        if common.source_activation != original.source_activation
            || common.capture_cut != original.cut
            || common.capture_ordinal != original.ordinal
            || host.owner != record.source.owner.owner.id
            || host.participants != [record.source.descriptor.id.clone()]
            || content.get(&runtime).is_none()
        {
            return Err(refused("complete host and administrative source differ"));
        }
        let common_bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(common).map_err(super::super::schema)?,
        )
        .map_err(super::super::schema)?;
        runtime
            .verify(&common_bytes)
            .map_err(super::super::schema)?;
        for object in &record.objects {
            if content.get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(refused("complete host original body differs"));
            }
        }
        Ok(CompleteOriginalRestorationSource {
            inner: Rc::new(CompleteOriginalSource {
                archive: self,
                content,
                administrative,
                host: CompleteHostArchiveRecord::InitialInvocation15(Rc::new(record)),
                runtime,
                purpose: CompleteOriginalSourcePurpose::new(collecting_plan),
                native_restoration_data,
                // This constructor has authenticated the original-only /5
                // family and decoded Host2. Current17 custody is constructed
                // separately by settled_load from its actual validated bank.
                settled_restoration_data: std::array::from_fn(|_| None),
                restored_collection: RefCell::new(None),
                coordinator_checkpoint: None,
                validation_limits: limits,
                process: std::process::id(),
                thread: thread::current().id(),
                host_issued: Cell::new(false),
                native_issued: Cell::new([false; 4]),
                target_started: Cell::new(false),
                target: RefCell::new(None),
                restoration_transactions: Cell::new(None),
            }),
        })
    }
}

impl CompleteOriginalSource {
    pub(super) fn native_restoration_construction_data(
        &self,
        index: usize,
    ) -> Result<&super::CompleteOriginalNativeRestorationData, RuntimeError> {
        self.authenticate_birth()?;
        self.native_restoration_data
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::UnsupportedFacet)
    }

    pub(crate) fn capture_owned_storage(&self) -> Result<usize, RuntimeError> {
        self.authenticate_birth()?;
        use crate::node_contract::NodeRuntime;
        let add = |a: usize, b: usize| a.checked_add(b).ok_or(RuntimeError::ResourceLimit);
        let mut bytes = NodeRuntime::capture_shared_allocation_storage::<Self>();
        let target = self
            .target
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if target.is_some() {
            bytes = add(
                bytes,
                NodeRuntime::capture_shared_allocation_storage::<()>(),
            )?;
        }
        bytes = add(
            bytes,
            self.purpose
                .retained_plan_storage(self.archive.limits.state.maximum_total_content_bytes)?,
        )?;
        bytes = add(bytes, self.archive.capture_owned_storage()?)?;
        bytes = add(bytes, self.content.capture_owned_storage()?)?;
        bytes = add(
            bytes,
            NodeRuntime::capture_admin_storage(&self.administrative)?,
        )?;
        bytes = add(bytes, self.host.retained_storage_data()?)?;
        if let Some(checkpoint) = &self.coordinator_checkpoint {
            bytes = add(bytes, checkpoint.retained_backing_requested_bytes_data()?)?;
        }
        for data in self.settled_restoration_data.iter().flatten() {
            bytes = add(
                bytes,
                data.native_import_geometry_data()
                    .retained_requested_storage_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(collection) = self
            .restored_collection
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .as_ref()
        {
            bytes = add(
                bytes,
                collection.retained_requested_storage_data(
                    self.archive.limits.state.maximum_total_content_bytes,
                )?,
            )?;
        }
        NodeRuntime::capture_reference_storage(&self.runtime)
            .and_then(|reference| add(bytes, reference))
    }
}

#[cfg(test)]
#[path = "complete_original_source_tests.rs"]
mod tests;

impl CompleteOriginalSource {
    pub(crate) fn begin_original_restoration_transaction(
        &self,
        authority: &Rc<()>,
        owner_index: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        let owner = self
            .archive
            .owners()
            .get(owner_index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if owner.owner == self.host.selection_data().owner.owner.id {
            return Err(RuntimeError::ForeignAuthority);
        }

        // Only this selected boundary initializes the ledger. An old final-context
        // attempt, including a failed one, cannot be relabelled as this action.
        match self.restoration_transactions.get() {
            None => {
                self.bind_target(authority)?;
                self.restoration_transactions.set(Some([false; 4]));
            }
            Some(_) => self.authenticate_target(authority)?,
        }
        let mut transactions = self
            .restoration_transactions
            .get()
            .ok_or(RuntimeError::OutstandingObligations)?;
        let slot = transactions
            .get_mut(owner_index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if *slot {
            return Err(RuntimeError::OutstandingObligations);
        }
        // A refused or unwound callback leaves this same owner permanently spent.
        *slot = true;
        self.restoration_transactions.set(Some(transactions));
        Ok(())
    }

    pub(crate) fn authenticate_original_restoration_transaction(
        &self,
        authority: &Rc<()>,
        owner_index: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_target(authority)?;
        if !self
            .restoration_transactions
            .get()
            .and_then(|slots| slots.get(owner_index).copied())
            .unwrap_or(false)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_legacy_restoration_context_phase_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        if self.restoration_transactions.get().is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl CompleteOriginalRestorationSource {
    pub(crate) fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.inner.retained_descriptor_views_precredit_data()
    }
}

impl CompleteOriginalSource {
    pub(crate) fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.authenticate_birth()?;
        Ok(self.archive.retained_descriptor_views_precredit_data())
    }
}

impl CompleteOriginalRestorationSource {
    pub(crate) fn original_host_record_data(
        &self,
    ) -> Result<&HostSchedulingContinuationRecord, RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner.host.initial_data()
    }
}

#[path = "complete_original_source/context_validation.rs"]
mod context_validation;

#[path = "complete_original_source/settled.rs"]
mod settled;

#[path = "complete_original_source/settled_load.rs"]
mod settled_load;
pub use settled_load::CompleteRestoredSettledSourceLoadAttempt;
