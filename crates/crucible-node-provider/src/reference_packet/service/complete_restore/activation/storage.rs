//! Separates prospective Host and native activation phase ownership as DATA.
//!
//! The issuer independently sums these terms with every simultaneous Source,
//! Core and other-native owner. Neither a row nor an equal phase label can
//! allocate, send, install readiness or release the actual native physical hold.

use super::*;

/// Lends actual source Runtime7 bytes and its closed future coordinator geometry.
///
/// The genuine Core producer supplies these DATA fields from the same archive,
/// target, scope and paused scheduler row before Prepare. They grant no native
/// allocation: ingress independently counts the real received body before
/// parsing and compares it with the separately Source-signed activation row.
pub struct PacketRestorationActivationCoordinatorConstructionInputs<'a> {
    /// Borrows the full verified unchanged source Runtime7 body.
    pub source_runtime: &'a [u8],
    /// Bounds the complete selected eleven-slot coordinator bytes.
    pub maximum_encoded_bytes: usize,
    /// Bounds every independent future coordinator/content/publication owner.
    pub retained_requested_bytes: usize,
    /// Bounds the actual closed serializer, parser and paused scheduler phase.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Names actual fixed coordinator producer/conversion/result views.
    pub declared_counter_scratch_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PhaseStorage {
    pub(super) host_retained: usize,
    pub(super) host_transient: usize,
    pub(super) host_scratch: usize,
    pub(super) native: PacketRestorationActivationAllocationRow,
    pub(super) source_evidence_retained: usize,
    pub(super) source_evidence_transient: usize,
    pub(super) source_evidence_scratch: usize,
}

/// Names all prospective SDK and native activation owners for one original node.
///
/// Only the defining producer constructs this fixed DATA. The genuine Core
/// Window separately binds and admits it before Prepare, then issues a distinct
/// once phase claim; the native service independently verifies the signed row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OriginalInstalledRestorationActivationConstructionData {
    pub(super) phases: [PhaseStorage; 2],
    pub(super) uploads: [super::upload::storage::UploadStorage; 2],
    pub(super) controller: *const (),
    pub(super) requested: usize,
    pub(super) counter_scratch: usize,
}

impl OriginalInstalledRestorationActivationConstructionData {
    /// Compares every fixed defining field without issuing an action or grant.
    ///
    /// # Errors
    /// Refuses a different actual controller identity, phase axis, evidence
    /// term, complete requested sum or counter layout. No sum-only alias passes.
    pub fn authenticate_same_construction_data(&self, other: &Self) -> Result<(), ProviderError> {
        if self != other { return Err(invalid()); }
        Ok(())
    }

    pub(crate) fn authenticate_controller_data(&self, controller: *const ()) -> Result<(), ProviderError> {
        if self.controller.is_null() || self.controller != controller || self.requested == 0 {
            return Err(invalid());
        }
        Ok(())
    }
    /// Returns the independently admitted native allocation for one upload ordinal.
    pub fn upload_native_allocation_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> PacketRestorationActivationAllocationRow {
        self.uploads[role.ordinal_data()].native
    }

    /// Returns this ordinal's unchanged negotiated and prequoted chunk width.
    pub fn upload_chunk_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].chunk
    }

    /// Returns this ordinal's genuine selected frame ceiling.
    pub fn upload_maximum_frame_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].frame
    }

    /// Returns the complete future content upper lent by its real defining producer.
    pub fn upload_maximum_content_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].maximum_bytes
    }

    /// Returns additional independently retained SDK upload histories/content.
    pub fn upload_host_retained_requested_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].retained
    }

    /// Returns additional independent SDK upload construction and receive work.
    pub fn upload_host_maximum_simultaneous_transient_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].transient
    }

    /// Returns actual upload counter and conversion fixed views.
    pub fn upload_counter_scratch_bytes_data(&self, role: super::upload::PacketRestorationActivationUploadRole) -> usize {
        self.uploads[role.ordinal_data()].scratch
    }

    pub(crate) fn preflight_upload_data(&self, controller: &crate::client::CnpController, role: super::upload::PacketRestorationActivationUploadRole) -> Result<(), ProviderError> {
        let rows = &self.uploads[role.ordinal_data()..];
        let mut requests = 0usize;
        let mut journal = 0usize;
        let mut content = 0usize;
        for row in rows {
            requests = requests.checked_add(row.requests).ok_or_else(invalid)?;
            journal = journal.checked_add(row.journal).ok_or_else(invalid)?;
            content = content.checked_add(row.maximum_bytes).ok_or_else(invalid)?;
        }
        controller.preflight_source_reply(requests, 0, journal, rows.len(), content)
    }

    /// Returns the complete separately admitted native row for the named phase.
    pub fn native_allocation_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> PacketRestorationActivationAllocationRow {
        self.phases[index(phase)].native
    }

    /// Returns the phase's persistent SDK/request/response/cache growth.
    pub fn host_retained_requested_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
        self.phases[index(phase)].host_retained
    }

    /// Returns the full simultaneous Host construction, codec and receive work.
    pub fn host_maximum_simultaneous_transient_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
        self.phases[index(phase)].host_transient
    }

    /// Returns exact phase counter, borrowed and conversion headers.
    pub fn host_declared_counter_scratch_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
        self.phases[index(phase)].host_scratch
    }

    /// Returns additional Source-owned decoded receipt/model-proof backing.
    ///
    /// This is independent of every SDK owner. Source must add this term to its
    /// own retained row rather than borrow the controller's retained allowance.
    pub fn source_evidence_retained_requested_bytes_data(&self, phase: PacketRestorationActivationPhase) -> usize {
        self.phases[index(phase)].source_evidence_retained
    }

    /// Returns independent Source parsing, full-hash and revalidation workspace.
    pub fn source_evidence_maximum_simultaneous_transient_bytes_data(&self, phase: PacketRestorationActivationPhase) -> usize {
        self.phases[index(phase)].source_evidence_transient
    }

    /// Returns Source evidence decoder and raw-owning-walk fixed views.
    pub fn source_evidence_counter_scratch_bytes_data(&self, phase: PacketRestorationActivationPhase) -> usize {
        self.phases[index(phase)].source_evidence_scratch
    }

    /// Returns the checked whole two-phase prospective demand.
    ///
    /// Independent native and Host phase demands remain summed. This getter
    /// does not infer a shared transient peak from matching phase labels.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns independently precharged fixed producer and view layouts.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.counter_scratch
    }
}

pub(super) const fn index(phase: PacketRestorationActivationPhase) -> usize {
    match phase {
        PacketRestorationActivationPhase::Arm => 0,
        PacketRestorationActivationPhase::WorldActivate => 1,
    }
}
