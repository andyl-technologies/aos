//! Owns pre-child semantic, ancestry, settlement and complete protocol-copy banks.
//!
//! These actual allocations are retained in the same concrete source. They do
//! not select a capture mechanism or issue geometry permission. The source's
//! full codec and factory still authenticate all coexisting storage and metadata.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;

#[path = "capture_banks/retained.rs"]
mod retained;
use crate::node_adapters::cnp::{CnpOriginalSemanticSnapshot, CnpSemanticSnapshotReservation};
use crucible_node_transport::protocol_snapshot::{
    OriginalProtocolPayloadOwner, OriginalProtocolSnapshot, ProtocolSnapshotReservation,
};
use crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile;
use crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt;

/// Selects finite source-side banks before registration of an actual native child.
///
/// These bounds are allocation data, not an installed preservation profile.
#[derive(Clone, Copy, Debug)]
pub struct PacketCompleteCaptureBankLimits {
    /// Bounds this host controller's encoded protocol snapshot independently of
    /// the native endpoint's separately selected before/after snapshot banks.
    pub host_protocol_bytes: usize,
    /// Bounds the complete common operation and input history byte view.
    pub semantic_bytes: usize,
    /// Bounds the complete source-retained first-sealed ancestry byte view.
    pub ancestry_bytes: usize,
    /// Bounds the source-local original Capture settlement journal.
    pub journal_bytes: usize,
}

/// Reports actual allocated capacities of the original source-side banks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketCompleteCaptureBankFacts {
    /// Retains the actual common semantic bank byte capacity.
    pub semantic_bytes: usize,
    /// Retains the actual source ancestry bank byte capacity.
    pub ancestry_bytes: usize,
    /// Retains the actual local settlement bank byte capacity.
    pub journal_bytes: usize,
    /// Includes encoded protocol storage and its independent literal-copy bank.
    pub protocol_bytes: usize,
    /// Retains the independent returned native whole-snapshot byte bank.
    pub native_snapshot_bytes: usize,
    /// Retains the independent returned native Control snapshot byte bank.
    pub native_control_bytes: usize,
    /// Retains the independent returned unchanged-cut anchor byte bank.
    pub native_anchor_bytes: usize,
    /// Retains the separately selected fourth native-after return byte bank.
    /// Zero means that this optional bank was not selected before the child.
    pub native_after_protocol_bytes: usize,
    /// Includes every independently allocated selected source bank role.
    pub total_bytes: usize,
}

pub(super) struct PacketCompleteCaptureBanks {
    // A detached host owner remains in execution; final output belongs to Core.
    pub(super) protocol_detached: bool,
    pub(super) transferred: bool,
    pub(super) semantic: Option<CnpSemanticSnapshotReservation>,
    pub(super) semantic_snapshot: Option<CnpOriginalSemanticSnapshot>,
    pub(super) ancestry: Option<CnpSemanticSnapshotReservation>,
    pub(super) ancestry_record: Option<InputPayload>,
    pub(super) journal: Option<CnpSemanticSnapshotReservation>,
    pub(super) journal_record: Option<InputPayload>,
    pub(super) capture_response: Option<ResponseBody>,
    pub(super) confirmation_response: Option<(ResponseBody, PacketNativeAfterConfirmationReceipt)>,
    pub(super) protocol: Option<ProtocolSnapshotReservation>,
    pub(super) settled_protocol: Option<OriginalProtocolSnapshot>,
    pub(super) protocol_payload: Option<(OriginalProtocolPayloadOwner, Vec<u8>)>,
    pub(super) native_banks: [Option<CnpSemanticSnapshotReservation>; 3],
    pub(super) native_objects: [Option<InputPayload>; 3],
    pub(super) native_after_bank: Option<CnpSemanticSnapshotReservation>,
    pub(super) native_after_object: Option<InputPayload>,
}

impl PacketCompleteCaptureBanks {
    fn reserve(
        selected: &PacketNative5StorageSelection,
        profile: &PacketNative5CaptureProfile,
        limits: PacketCompleteCaptureBankLimits,
        host_metadata_rows: Option<usize>,
        admitted: usize,
    ) -> Result<Self, OperationFailure> {
        let protocol_maximum = limits.host_protocol_bytes;
        let history = usize::try_from(selected.storage.frame_bank_bytes.get())
            .map_err(|_| refused("source literal bank is not representable"))?;
        let frames = usize::try_from(selected.storage.frames_per_direction.get())
            .map_err(|_| refused("source literal descriptors are not representable"))?;

        let native_snapshot = usize::try_from(selected.storage.snapshot_bytes.get())
            .map_err(|_| refused("native snapshot return bank is not representable"))?;
        let native_control = usize::try_from(selected.storage.control_snapshot_bytes.get())
            .map_err(|_| refused("native control return bank is not representable"))?;
        let native_anchor = 8192;

        let minimum = [
            limits.semantic_bytes,
            limits.ancestry_bytes,
            limits.journal_bytes,
            protocol_maximum,
            history,
            native_snapshot,
            native_control,
            native_anchor,
        ]
        .into_iter()
        .try_fold(0usize, |sum, size| sum.checked_add(size))
        .filter(|minimum| *minimum <= admitted)
        .ok_or_else(|| refused("selected source banks exceed preallocation credit"))?;
        // The logical minimum excludes private SDK descriptor storage. Its exact
        // actual allocation is checked below before any native association.
        let _ = minimum;

        let semantic = CnpSemanticSnapshotReservation::reserve(limits.semantic_bytes, admitted)?;
        let ancestry = CnpSemanticSnapshotReservation::reserve(limits.ancestry_bytes, admitted)?;
        let journal = CnpSemanticSnapshotReservation::reserve(limits.journal_bytes, admitted)?;
        let protocol = match profile {
            PacketNative5CaptureProfile::OriginalArrays6 => {
                ProtocolSnapshotReservation::reserve_complete(protocol_maximum, history, frames)
            }
            PacketNative5CaptureProfile::CompactBytes7 { .. } => {
                ProtocolSnapshotReservation::reserve_complete_compact(
                    protocol_maximum,
                    history,
                    frames,
                )
            }
            PacketNative5CaptureProfile::OwnedProtocol11 { .. } => {
                ProtocolSnapshotReservation::reserve_complete_owned11(
                    protocol_maximum,
                    history,
                    frames,
                    host_metadata_rows
                        .ok_or_else(|| refused("owned host protocol metadata rows absent"))?,
                )
            }
        }
        .map_err(unknown)?;
        let native_banks = [
            Some(CnpSemanticSnapshotReservation::reserve(
                native_snapshot,
                admitted,
            )?),
            Some(CnpSemanticSnapshotReservation::reserve(
                native_control,
                admitted,
            )?),
            Some(CnpSemanticSnapshotReservation::reserve(
                native_anchor,
                admitted,
            )?),
        ];
        let original = Self {
            protocol_detached: false,
            transferred: false,
            semantic: Some(semantic),
            semantic_snapshot: None,
            ancestry: Some(ancestry),
            ancestry_record: None,
            journal: Some(journal),
            journal_record: None,
            capture_response: None,
            confirmation_response: None,
            protocol: Some(protocol),
            settled_protocol: None,
            protocol_payload: None,
            native_banks,
            native_objects: [None, None, None],
            native_after_bank: None,
            native_after_object: None,
        };
        if original.facts()?.total_bytes > admitted {
            return Err(refused(
                "actual complete source bank allocations exceed admission",
            ));
        }
        Ok(original)
    }

    pub(super) fn facts(&self) -> Result<PacketCompleteCaptureBankFacts, OperationFailure> {
        self.facts_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn facts_with_error<E: StorageError>(
        &self,
    ) -> Result<PacketCompleteCaptureBankFacts, E> {
        let semantic_bytes = match (&self.semantic, &self.semantic_snapshot) {
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(snapshot)) => snapshot.payload().bytes.capacity(),
            (None, None) if self.transferred => 0,
            _ => {
                return Err(E::refused(
                    "original semantic bank association is incomplete",
                ));
            }
        };
        let ancestry_bytes = match (&self.ancestry, &self.ancestry_record) {
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(record)) => record.bytes.capacity(),
            (None, None) if self.transferred => 0,
            _ => {
                return Err(E::refused(
                    "original ancestry bank association is incomplete",
                ));
            }
        };
        let journal_bytes = match (&self.journal, &self.journal_record) {
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(record)) => record.bytes.capacity(),
            (None, None) if self.transferred => 0,
            _ => {
                return Err(E::refused(
                    "original journal bank association is incomplete",
                ));
            }
        };
        let protocol_bytes = match (
            &self.protocol,
            &self.settled_protocol,
            &self.protocol_payload,
        ) {
            (Some(bank), None, None) => {
                bank.original_allocation_facts()
                    .map_err(E::unknown)?
                    .allocated_bytes
            }
            (None, Some(snapshot), None) => {
                snapshot
                    .original_allocation_facts()
                    .map_err(E::unknown)?
                    .allocated_bytes
            }
            (None, None, Some((owner, bytes))) => {
                // The owner retains the literal bank and immutable issuance facts,
                // but the moved vector is the sole current encoded allocation.
                let facts = owner.original_allocation_facts().map_err(E::unknown)?;
                let literal = facts.literal.map_or(0, |literal| literal.allocated_bytes);
                let records = owner
                    .original_metadata_record_allocation_facts()
                    .map_err(E::unknown)?
                    .map_or(0, |facts| facts.allocated_bytes);
                let aliases = owner
                    .original_alias_allocation_facts()
                    .map_err(E::unknown)?
                    .map(|facts| facts.row_bytes.checked_add(facts.lookup_bytes))
                    .unwrap_or(Some(0))
                    .ok_or_else(|| E::refused("original protocol alias extent overflow"))?;
                bytes
                    .capacity()
                    .checked_add(literal)
                    .and_then(|bytes| bytes.checked_add(records))
                    .and_then(|bytes| bytes.checked_add(aliases))
                    .ok_or_else(|| E::refused("original protocol payload allocation overflow"))?
            }
            (None, None, None) if self.protocol_detached => 0,
            _ => {
                return Err(E::refused(
                    "original protocol bank association is incomplete",
                ));
            }
        };
        let mut native_capacity = [0usize; 3];
        for (index, capacity) in native_capacity.iter_mut().enumerate() {
            *capacity = match (&self.native_banks[index], &self.native_objects[index]) {
                (Some(bank), None) => bank.allocated_bytes(),
                (None, Some(object)) => object.bytes.capacity(),
                (None, None) if self.transferred => 0,
                _ => return Err(E::refused("native return bank association is incomplete")),
            };
        }
        let [
            native_snapshot_bytes,
            native_control_bytes,
            native_anchor_bytes,
        ] = native_capacity;
        let native_after_protocol_bytes = match (&self.native_after_bank, &self.native_after_object)
        {
            (None, None) => 0,
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(object)) => object.bytes.capacity(),
            _ => {
                return Err(E::refused(
                    "native-after return bank association is incomplete",
                ));
            }
        };
        let total_bytes = [
            semantic_bytes,
            ancestry_bytes,
            journal_bytes,
            protocol_bytes,
            native_snapshot_bytes,
            native_control_bytes,
            native_anchor_bytes,
            native_after_protocol_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, size| sum.checked_add(size))
        .ok_or_else(|| E::refused("complete source bank allocation overflow"))?;
        Ok(PacketCompleteCaptureBankFacts {
            semantic_bytes,
            ancestry_bytes,
            journal_bytes,
            protocol_bytes,
            native_snapshot_bytes,
            native_control_bytes,
            native_anchor_bytes,
            native_after_protocol_bytes,
            total_bytes,
        })
    }
}

impl PacketCompleteSemanticSource {
    /// Reserves the original source-side closure banks before native registration.
    ///
    /// The source remains Capture-refused until its complete snapshot and local
    /// settlement codecs are installed. This method accounts only these banks;
    /// the whole factory separately charges controller/native banks, histories,
    /// metadata, return objects and simultaneous copies before any effect.
    ///
    /// # Errors
    /// Refuses a foreign creator, an already-associated native child, repeated
    /// allocation, nonpositive bounds or actual capacities exceeding admission.
    pub fn reserve_complete_capture_banks(
        &mut self,
        limits: PacketCompleteCaptureBankLimits,
        admitted_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.reserve_complete_capture_banks_selected(limits, None, admitted_bytes)
    }

    /// Reserves the host owning codec with independently selected metadata rows.
    ///
    /// Native-before and native-after rows are separate original selections.
    /// Their numeric bounds cannot supply host metadata or capture authority.
    ///
    /// # Errors
    /// Refuses another source phase/profile, absent or invalid host rows,
    /// repeated storage, allocation failure or aggregate bank exhaustion.
    pub fn reserve_complete_capture_banks_owned11(
        &mut self,
        limits: PacketCompleteCaptureBankLimits,
        host_metadata_rows: usize,
        admitted_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.reserve_complete_capture_banks_selected(
            limits,
            Some(host_metadata_rows),
            admitted_bytes,
        )
    }

    fn reserve_complete_capture_banks_selected(
        &mut self,
        limits: PacketCompleteCaptureBankLimits,
        host_metadata_rows: Option<usize>,
        admitted_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.native_import18_bank_attempted.get() {
            return Err(refused(
                "import18 bank construction cannot renew through a legacy reservation",
            ));
        }
        if matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) != host_metadata_rows.is_some()
        {
            return Err(refused(
                "host protocol metadata selection differs from original profile",
            ));
        }
        if self.capture_banks.get_mut().is_some() {
            return Err(refused(
                "original complete source banks were already selected",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "complete source banks must precede native association",
            ));
        }
        let profile = self.selected_capture_profile()?;
        if !profile.is_original_arrays()
            && profile
                .host_bytes(&self.selected_storage_selection()?.storage)
                .get()
                != u64::try_from(limits.host_protocol_bytes)
                    .map_err(|_| refused("host protocol bank bound is not representable"))?
        {
            return Err(refused(
                "host protocol bank differs from the original compact profile",
            ));
        }

        let memory = usize::try_from(
            self.installation()
                .realize
                .resource_limits
                .memory_bytes
                .get(),
        )
        .map_err(|_| refused("complete source memory bound is not representable"))?;
        let admitted = admitted_bytes.min(memory);
        let original = PacketCompleteCaptureBanks::reserve(
            self.selected_storage_selection()?,
            profile,
            limits,
            host_metadata_rows,
            admitted,
        )?;
        *self.capture_banks.get_mut() = Some(original);
        Ok(())
    }

    /// Reads actual retained source-side allocations without manufacturing geometry.
    ///
    /// # Errors
    /// Refuses a foreign creator, absent original banks or allocation overflow.
    pub fn original_capture_bank_facts(
        &self,
    ) -> Result<PacketCompleteCaptureBankFacts, OperationFailure> {
        self.ensure_origin()?;
        self.capture_banks
            .try_borrow()
            .map_err(|_| refused("original complete source banks are busy"))?
            .as_ref()
            .ok_or_else(|| refused("complete source capture banks are absent"))?
            .facts()
    }
}

impl PacketCompleteSemanticSource {
    /// Retains the actual settled host protocol under the original source attempt.
    ///
    /// This component is placed in its preowned slot before final source checks.
    /// Its complete bytes and actual allocation remain owned on every refusal;
    /// completion alone does not validate the native Capture or seal a journal.
    ///
    /// # Errors
    /// Refuses foreign or changed original custody, absent or already attempted
    /// banks, unresolved I/O, exhausted codec credit or final source revocation.
    pub fn record_settled_original_protocol(
        &self,
        scope: &mut CnpSemanticCaptureScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(&scope.realization()?)?;
        let mut banks = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original settled protocol banks are busy"))?;
        let banks = banks
            .as_mut()
            .ok_or_else(|| refused("original settled protocol banks are absent"))?;
        if banks.protocol_payload.is_some() {
            return Err(refused(
                "original settled protocol payload was already transferred",
            ));
        }

        if matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            scope.take_settled_original_complete_protocol_snapshot_into(
                &mut banks.protocol,
                &mut banks.settled_protocol,
            )?;
            self.record_original_complete_registry(scope)?;
        } else {
            scope.take_settled_original_protocol_snapshot_into(
                &mut banks.protocol,
                &mut banks.settled_protocol,
            )?;
        }
        self.authenticate_witness_scope(&scope.realization()?)
    }

    /// Moves the original encoded protocol vector into its retained source slot.
    ///
    /// The opaque owner and the same vector remain together before subsequent
    /// body and source checks. No encoded return bank or byte copy is allocated.
    /// This correspondence component does not seal a journal or authorize capture.
    ///
    /// # Errors
    /// Refuses foreign or changed original custody, absent completed storage,
    /// repeated transfer, changed payload bytes or final source revocation.
    pub fn retain_settled_original_protocol_payload(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(&scope.realization()?)?;
        let mut banks = self
            .capture_banks
            .try_borrow_mut()
            .map_err(|_| refused("original protocol payload banks are busy"))?;
        let banks = banks
            .as_mut()
            .ok_or_else(|| refused("original protocol payload banks are absent"))?;
        if banks.protocol.is_some() || banks.protocol_payload.is_some() {
            return Err(refused(
                "original protocol payload transfer is not available",
            ));
        }

        let snapshot = banks
            .settled_protocol
            .take()
            .ok_or_else(|| refused("original settled protocol snapshot is absent"))?;
        banks.protocol_payload = Some(snapshot.into_original_payload());

        let (owner, bytes) = banks
            .protocol_payload
            .as_ref()
            .ok_or_else(|| refused("original protocol payload slot is incomplete"))?;
        owner.validate_original_payload(bytes).map_err(unknown)?;
        self.authenticate_witness_scope(&scope.realization()?)
    }
}

impl PacketCompleteSemanticSource {
    pub(super) fn authenticate_preconstruction_protocol_bound(
        &self,
        selected: &PacketNative5CaptureProfile,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("preconstruction protocol banks are busy"))?;
        let banks = banks
            .as_ref()
            .ok_or_else(|| refused("preconstruction protocol banks are absent"))?;
        if banks.settled_protocol.is_some() || banks.protocol_payload.is_some() {
            return Err(refused(
                "preconstruction protocol bank was already consumed",
            ));
        }
        let facts = banks
            .protocol
            .as_ref()
            .ok_or_else(|| refused("preconstruction protocol reservation is absent"))?
            .original_allocation_facts()
            .map_err(unknown)?;
        let expected = usize::try_from(
            selected
                .host_bytes(&self.selected_storage_selection()?.storage)
                .get(),
        )
        .map_err(|_| refused("selected host protocol extent is not representable"))?;
        if facts.maximum_encoded_bytes != expected || facts.encoded_length != 0 {
            return Err(refused("preconstruction host protocol extent differs"));
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Reserves a separate fourth native-after return bank before native association.
    ///
    /// The selected profile supplies its finite encoded native-after bound. This
    /// allocation coexists with the controller content cache and the independent
    /// settled host protocol owner. It installs no confirmation mechanism and
    /// cannot prove that the remote native-after snapshot was issued.
    ///
    /// # Errors
    /// Refuses foreign origin, absent source banks, a prior native association,
    /// repeated selection, an unrepresentable bound or exhausted total credit.
    /// Any bank already retained in this source remains owned on refusal.
    pub fn reserve_original_native_after_return_bank(
        &mut self,
        admitted_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "native-after return bank follows native association",
            ));
        }

        let maximum = usize::try_from(
            self.selected_capture_profile()?
                .native_after_bytes(&self.selected_storage_selection()?.storage)
                .get(),
        )
        .map_err(|_| refused("native-after return bound is not representable"))?;
        let banks = self
            .capture_banks
            .get_mut()
            .as_mut()
            .ok_or_else(|| refused("native-after return has no original source banks"))?;
        if banks.native_after_bank.is_some() || banks.native_after_object.is_some() {
            return Err(refused("native-after return bank was already selected"));
        }
        let remaining = admitted_total_bytes
            .checked_sub(banks.facts()?.total_bytes)
            .filter(|remaining| *remaining >= maximum)
            .ok_or_else(|| refused("native-after return bank exceeds total admission"))?;

        let bank = CnpSemanticSnapshotReservation::reserve(maximum, remaining)?;
        banks.native_after_bank = Some(bank);
        if banks.facts()?.total_bytes > admitted_total_bytes {
            return Err(refused(
                "actual native-after return capacity exceeds admission",
            ));
        }
        Ok(())
    }
}

#[path = "capture_banks/import18_reservation.rs"]
mod import18_reservation;
pub use import18_reservation::OriginalImport18CaptureBankConstructionData;
pub(super) use import18_reservation::{
    Import18CaptureBankHistoryData, Import18CaptureBankOwnerHistoryData,
    Import18CaptureBankReservation,
};
