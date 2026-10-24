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
        if self != other {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn authenticate_controller_data(
        &self,
        controller: *const (),
    ) -> Result<(), ProviderError> {
        if self.controller.is_null() || self.controller != controller || self.requested == 0 {
            return Err(invalid());
        }
        Ok(())
    }
    /// Returns the independently admitted native allocation for one upload ordinal.
    pub fn upload_native_allocation_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> PacketRestorationActivationAllocationRow {
        self.uploads[role.ordinal_data()].native
    }

    /// Returns this ordinal's unchanged negotiated and prequoted chunk width.
    pub fn upload_chunk_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].chunk
    }

    /// Returns this ordinal's genuine selected frame ceiling.
    pub fn upload_maximum_frame_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].frame
    }

    /// Returns the complete future content upper lent by its real defining producer.
    pub fn upload_maximum_content_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].maximum_bytes
    }

    /// Returns additional independently retained SDK upload histories/content.
    pub fn upload_host_retained_requested_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].retained
    }

    /// Returns additional independent SDK upload construction and receive work.
    pub fn upload_host_maximum_simultaneous_transient_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].transient
    }

    /// Returns actual upload counter and conversion fixed views.
    pub fn upload_counter_scratch_bytes_data(
        &self,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> usize {
        self.uploads[role.ordinal_data()].scratch
    }

    pub(crate) fn preflight_upload_data(
        &self,
        controller: &crate::client::CnpController,
        role: super::upload::PacketRestorationActivationUploadRole,
    ) -> Result<(), ProviderError> {
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
    pub fn source_evidence_retained_requested_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
        self.phases[index(phase)].source_evidence_retained
    }

    /// Returns independent Source parsing, full-hash and revalidation workspace.
    pub fn source_evidence_maximum_simultaneous_transient_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
        self.phases[index(phase)].source_evidence_transient
    }

    /// Returns Source evidence decoder and raw-owning-walk fixed views.
    pub fn source_evidence_counter_scratch_bytes_data(
        &self,
        phase: PacketRestorationActivationPhase,
    ) -> usize {
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

/// Borrows every portable phase/upload field from the actual activation row.
///
/// This historical DATA has no decoder or live-row constructor. The actual
/// process-private Controller pointer remains outside the serialized graph.
pub struct OriginalInstalledRestorationActivationHistoricalData<'a> {
    original: &'a OriginalInstalledRestorationActivationConstructionData,
}

impl OriginalInstalledRestorationActivationConstructionData {
    /// Lends the full retained quote without copying owned identities.
    pub fn historical_data(&self) -> OriginalInstalledRestorationActivationHistoricalData<'_> {
        OriginalInstalledRestorationActivationHistoricalData { original: self }
    }

    /// Names borrowed arrays, nested fixed rows and their actual iterators.
    pub fn historical_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<OriginalInstalledRestorationActivationHistoricalData<'static>>()
            + size_of::<&OriginalInstalledRestorationActivationConstructionData>()
            + size_of::<HistoricalPhases<'static>>()
            + size_of::<HistoricalPhase<'static>>()
            + size_of::<HistoricalUploads<'static>>()
            + size_of::<HistoricalUpload<'static>>()
            + size_of::<&[PhaseStorage; 2]>()
            + size_of::<&[super::upload::storage::UploadStorage; 2]>()
            + size_of::<std::slice::Iter<'static, PhaseStorage>>()
            + size_of::<std::slice::Iter<'static, super::upload::storage::UploadStorage>>()
            + size_of::<&PacketRestorationActivationAllocationRow>()
            + 16 * size_of::<&usize>()
    }
}

impl serde::Serialize for OriginalInstalledRestorationActivationHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let OriginalInstalledRestorationActivationConstructionData {
            phases,
            uploads,
            controller: _,
            requested,
            counter_scratch,
        } = self.original;
        let mut state = serializer.serialize_struct("HistoricalActivationConstruction", 5)?;
        state.serialize_field(
            "schema",
            "source-private.restoration-activation-construction/1",
        )?;
        state.serialize_field("phases", &HistoricalPhases(phases))?;
        state.serialize_field("uploads", &HistoricalUploads(uploads))?;
        state.serialize_field("requested", requested)?;
        state.serialize_field("counter_scratch", counter_scratch)?;
        state.end()
    }
}

struct HistoricalPhases<'a>(&'a [PhaseStorage; 2]);

struct HistoricalPhase<'a>(&'a PhaseStorage);

struct HistoricalUploads<'a>(&'a [super::upload::storage::UploadStorage; 2]);

struct HistoricalUpload<'a>(&'a super::upload::storage::UploadStorage);

impl serde::Serialize for HistoricalPhases<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut state = serializer.serialize_seq(Some(self.0.len()))?;
        for phase in self.0 {
            state.serialize_element(&HistoricalPhase(phase))?;
        }
        state.end()
    }
}

impl serde::Serialize for HistoricalPhase<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PhaseStorage {
            host_retained,
            host_transient,
            host_scratch,
            native,
            source_evidence_retained,
            source_evidence_transient,
            source_evidence_scratch,
        } = self.0;
        let mut state = serializer.serialize_struct("HistoricalActivationPhase", 7)?;
        state.serialize_field("host_retained", host_retained)?;
        state.serialize_field("host_transient", host_transient)?;
        state.serialize_field("host_scratch", host_scratch)?;
        state.serialize_field("native", native)?;
        state.serialize_field("source_evidence_retained", source_evidence_retained)?;
        state.serialize_field("source_evidence_transient", source_evidence_transient)?;
        state.serialize_field("source_evidence_scratch", source_evidence_scratch)?;
        state.end()
    }
}

impl serde::Serialize for HistoricalUploads<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut state = serializer.serialize_seq(Some(self.0.len()))?;
        for upload in self.0 {
            state.serialize_element(&HistoricalUpload(upload))?;
        }
        state.end()
    }
}

impl serde::Serialize for HistoricalUpload<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let super::upload::storage::UploadStorage {
            maximum_bytes,
            chunk,
            frame,
            requests,
            journal,
            retained,
            transient,
            scratch,
            native,
        } = self.0;
        let mut state = serializer.serialize_struct("HistoricalActivationUpload", 9)?;
        state.serialize_field("maximum_bytes", maximum_bytes)?;
        state.serialize_field("chunk", chunk)?;
        state.serialize_field("frame", frame)?;
        state.serialize_field("requests", requests)?;
        state.serialize_field("journal", journal)?;
        state.serialize_field("retained", retained)?;
        state.serialize_field("transient", transient)?;
        state.serialize_field("scratch", scratch)?;
        state.serialize_field("native", native)?;
        state.end()
    }
}

#[cfg(test)]
mod historical_tests {
    use super::*;

    #[test]
    fn historical_activation_keeps_both_phase_and_upload_rows_without_pointer_data() {
        let native = PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        };
        let phase = PhaseStorage {
            host_retained: 4,
            host_transient: 5,
            host_scratch: 6,
            native,
            source_evidence_retained: 7,
            source_evidence_transient: 8,
            source_evidence_scratch: 9,
        };
        let upload = super::super::upload::storage::UploadStorage {
            maximum_bytes: 10,
            chunk: 11,
            frame: 12,
            requests: 13,
            journal: 14,
            retained: 15,
            transient: 16,
            scratch: 17,
            native,
        };
        let row = OriginalInstalledRestorationActivationConstructionData {
            phases: [phase, phase],
            uploads: [upload, upload],
            controller: std::ptr::null(),
            requested: 18,
            counter_scratch: 19,
        };
        let actual = serde_json::to_value(row.historical_data()).unwrap();
        assert_eq!(actual.as_object().unwrap().len(), 5);
        assert_eq!(actual["phases"].as_array().unwrap().len(), 2);
        assert_eq!(actual["uploads"].as_array().unwrap().len(), 2);
        assert_eq!(actual["phases"][1]["source_evidence_scratch"], 9);
        assert_eq!(actual["uploads"][1]["journal"], 14);
        assert_eq!(actual["uploads"][1]["scratch"], 17);
        assert_eq!(actual["requested"], 18);
        assert_eq!(actual["counter_scratch"], 19);
        assert!(actual.get("controller").is_none());
        let mut changed = row;
        changed.uploads[1].journal = 20;
        assert_ne!(
            actual,
            serde_json::to_value(changed.historical_data()).unwrap()
        );
        assert!(row.authenticate_controller_data(std::ptr::null()).is_err());
    }
}
