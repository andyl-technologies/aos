//! Retains a bounded byte view of the actual original common semantic journals.
//!
//! The view preserves every common custody field, including unresolved originals
//! and complete input context bytes. Opaque operation and activation permissions
//! remain in the original capsule. The emitted data cannot reconstruct them or
//! authorize capture, fresh adoption or readiness. Source-specific ancestry and
//! protocol journals are independently required by the whole-world mechanism.

use super::{CnpSemanticCaptureScope, refused};
use crate::{
    node_contract::{OperationFailure, WorldActivation},
    node_scheduling::InputPayload,
};
use crucible_node_contract::canonical;
use std::io::{self, Write};

mod view;
pub(super) use view::restored_base17_counter_scratch_data;
pub(super) use view::{ActivationView, BatchView, RestoredBaseCustodyView};

/// Reserves one finite original semantic snapshot bank before native effects.
///
/// Reserving this bank grants no capture permission. The complete factory must
/// charge its actual capacity together with all protocol and settlement banks.
pub struct CnpSemanticSnapshotReservation {
    storage_origin: super::retained_storage::StorageOrigin,
    bytes: Vec<u8>,
    maximum: usize,
    started: bool,
}

impl CnpSemanticSnapshotReservation {
    /// Allocates the selected semantic bank within an independently admitted bound.
    ///
    /// # Errors
    /// Refuses zero or excess bounds, overflow or allocation failure.
    pub fn reserve(maximum: usize, admitted_bytes: usize) -> Result<Self, OperationFailure> {
        Self::reserve_with_error::<OperationFailure>(maximum, admitted_bytes)
    }

    pub(in crate::node_adapters::cnp::semantic) fn reserve_with_error<
        E: super::packet_complete_source::storage_error::StorageError,
    >(
        maximum: usize,
        admitted_bytes: usize,
    ) -> Result<Self, E> {
        let mut completed = None;
        Self::reserve_into_with_error::<E>(maximum, admitted_bytes, &mut completed)?;
        completed.ok_or_else(|| E::refused("semantic snapshot bank is absent"))
    }

    pub(in crate::node_adapters::cnp::semantic) fn reserve_into_with_error<
        E: super::packet_complete_source::storage_error::StorageError,
    >(
        maximum: usize,
        admitted_bytes: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), E> {
        if completed.is_some() {
            return Err(E::refused("semantic snapshot bank slot is occupied"));
        }
        if maximum == 0 || maximum > admitted_bytes {
            return Err(E::limit("semantic snapshot bank exceeds admitted bytes"));
        }
        // The actual containing Source keeps the new owner before reservation
        // and post-cap checks. A spent action cannot lose its partial bank.
        *completed = Some(Self {
            storage_origin: super::retained_storage::StorageOrigin::current(),
            bytes: Vec::new(),
            maximum,
            started: false,
        });
        let owner = completed
            .as_mut()
            .ok_or_else(|| E::refused("semantic snapshot bank is absent"))?;
        owner
            .bytes
            .try_reserve_exact(maximum)
            .map_err(|_| E::limit("semantic snapshot bank allocation failed"))?;
        if owner.bytes.capacity() > admitted_bytes {
            return Err(E::limit(
                "actual semantic snapshot capacity exceeds admission",
            ));
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn reservation_counter_scratch_data() -> usize {
        // The allocation bank itself is the retained requested term. These
        // actual owner/result/borrow views are simultaneous fixed construction
        // scratch, separate from compiler frames and allocator physical memory.
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Option<Self>>()
            + std::mem::size_of::<&mut Option<Self>>()
            + std::mem::size_of::<std::collections::TryReserveError>()
            + std::mem::size_of::<[usize; 2]>()
    }

    pub(super) fn maximum_bytes(&self) -> usize {
        self.maximum
    }

    /// Returns the actual retained byte allocation, independent of logical length.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}

/// Retains original semantic bytes alongside their actual opaque activation.
///
/// Only an owning source capture loan can construct this object. Its activation
/// association is process local and is never decoded from the data view.
pub struct CnpOriginalSemanticSnapshot {
    storage_origin: super::retained_storage::StorageOrigin,
    payload: InputPayload,
    active: WorldActivation,
}

impl CnpOriginalSemanticSnapshot {
    /// Borrows the complete original semantic byte object.
    pub fn payload(&self) -> &InputPayload {
        &self.payload
    }

    // Only the complete owning adapter calls this after validating this exact
    // snapshot's original opaque activation and all output slots by borrow.
    pub(in crate::node_adapters::cnp::semantic) fn into_original_payload(self) -> InputPayload {
        self.payload
    }

    /// Authenticates the original opaque activation associated with these bytes.
    ///
    /// # Errors
    /// Refuses a different actual activation, including equal portable records.
    pub fn authenticate_activation(
        &self,
        active: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        if !self.active.same_authority(active) {
            return Err(refused("semantic snapshot has another original activation"));
        }
        Ok(())
    }
}

struct BankWriter<'a>(&'a mut CnpSemanticSnapshotReservation);

impl Write for BankWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .0
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|total| *total <= self.0.maximum && *total <= self.0.bytes.capacity())
            .ok_or_else(|| io::Error::other("original semantic bank exhausted"))?;
        self.0.bytes.extend_from_slice(bytes);
        debug_assert_eq!(total, self.0.bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CnpSemanticCaptureScope<'_> {
    /// Records the same original semantic custody into its preallocated bank.
    ///
    /// This local recording performs no native request or modeled effect. It
    /// runs before administrative Capture and preserves the original common
    /// ledgers unchanged. Failure retains the supplied bank and forbids reuse.
    ///
    /// # Errors
    /// Refuses changed native/source custody, a used or absent reservation,
    /// missing original active authority or a complete view exceeding the bank.
    pub fn take_original_semantic_snapshot(
        &self,
        reservation: &mut Option<CnpSemanticSnapshotReservation>,
    ) -> Result<CnpOriginalSemanticSnapshot, OperationFailure> {
        let mut completed = None;
        self.take_original_semantic_snapshot_into(reservation, &mut completed)?;
        completed.ok_or_else(|| refused("original semantic snapshot was not retained"))
    }

    /// Retains the original semantic producer before the final custody fence.
    ///
    /// The same preallocated bank and opaque activation move into the supplied
    /// destination. A later refusal or unwind leaves that owner in the caller.
    ///
    /// # Errors
    /// Refuses occupied custody and the same foreign, changed, used or excessive
    /// source conditions as the original semantic snapshot operation.
    pub fn take_original_semantic_snapshot_into(
        &self,
        reservation: &mut Option<CnpSemanticSnapshotReservation>,
        completed: &mut Option<CnpOriginalSemanticSnapshot>,
    ) -> Result<(), OperationFailure> {
        self.realization()?;
        if completed.is_some() {
            return Err(refused(
                "original semantic snapshot destination is occupied",
            ));
        }
        let runtime = self
            .native
            .runtime
            .as_ref()
            .ok_or_else(|| refused("original semantic custody is absent"))?;
        let active = runtime
            .active
            .as_ref()
            .ok_or_else(|| refused("original semantic active authority is absent"))?;
        let bank = reservation
            .as_mut()
            .filter(|bank| !bank.started && bank.bytes.is_empty())
            .ok_or_else(|| refused("original semantic reservation is absent or used"))?;
        record_into_bank(runtime, bank)?;
        self.realization()?;
        let reference = canonical::content_ref(
            &bank.bytes,
            "application/vnd.source-owned.packet-semantic-custody.v5+json",
        )
        .map_err(super::unknown)?;
        let active = active.clone();
        let bank = reservation
            .take()
            .ok_or_else(|| refused("original semantic reservation disappeared"))?;
        *completed = Some(CnpOriginalSemanticSnapshot {
            storage_origin: super::retained_storage::StorageOrigin::current(),
            payload: InputPayload {
                reference,
                bytes: bank.bytes,
            },
            active,
        });
        self.realization()?;
        Ok(())
    }
}

pub(super) fn record_original_bytes(
    reservation: &mut Option<CnpSemanticSnapshotReservation>,
    reference: &crucible_node_contract::ContentRef,
    bytes: &[u8],
) -> Result<InputPayload, OperationFailure> {
    let bank = reservation
        .as_mut()
        .filter(|bank| !bank.started && bank.bytes.is_empty())
        .ok_or_else(|| refused("original return bank is absent or used"))?;
    bank.started = true;
    if bytes.len() > bank.maximum || bytes.len() > bank.bytes.capacity() {
        return Err(refused(
            "complete native return object exceeds its original bank",
        ));
    }
    reference.verify(bytes).map_err(super::unknown)?;
    bank.bytes.extend_from_slice(bytes);
    let reference = reference.clone();
    let bank = reservation
        .take()
        .ok_or_else(|| refused("original return bank disappeared"))?;
    Ok(InputPayload {
        reference,
        bytes: bank.bytes,
    })
}

// Canonical backend data may contain arbitrary allowed extension Values.
// The caller precharges Value construction and both canonical passes, including
// canonical string/UTF-16 sorting scratch, before creating that Value.
pub(super) fn record_canonical_component(
    reservation: &mut Option<CnpSemanticSnapshotReservation>,
    value: &serde_json::Value,
) -> Result<(), OperationFailure> {
    let bank = reservation
        .as_mut()
        .filter(|bank| !bank.started && bank.bytes.is_empty())
        .ok_or_else(|| refused("original canonical bank is absent or used"))?;
    bank.started = true;
    let mut count = CanonicalBankCount {
        bytes: 0,
        maximum: bank.maximum,
    };
    canonical::canonical_json_to_writer(value, &mut count).map_err(super::unknown)?;
    canonical::canonical_json_to_writer(value, &mut BankWriter(bank)).map_err(super::unknown)
}

pub(super) fn authenticate_canonical_component(
    original: &InputPayload,
    value: &serde_json::Value,
) -> Result<(), OperationFailure> {
    original
        .reference
        .verify(&original.bytes)
        .map_err(super::unknown)?;
    let mut writer = OriginalBytesWriter {
        original: &original.bytes,
        position: 0,
    };
    canonical::canonical_json_to_writer(value, &mut writer).map_err(super::unknown)?;
    if writer.position != original.bytes.len() {
        return Err(refused("original canonical component extent differs"));
    }
    Ok(())
}

struct CanonicalBankCount {
    bytes: usize,
    maximum: usize,
}

impl Write for CanonicalBankCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.maximum)
            .ok_or_else(|| io::Error::other("original canonical bank exceeds selection"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn record_component(
    reservation: &mut Option<CnpSemanticSnapshotReservation>,
    value: &impl serde::Serialize,
) -> Result<(), OperationFailure> {
    let bank = reservation
        .as_mut()
        .filter(|bank| !bank.started && bank.bytes.is_empty())
        .ok_or_else(|| refused("original component bank is absent or used"))?;
    bank.started = true;
    super::budget::serialized_size(value, bank.maximum)?;
    serde_json::to_writer(BankWriter(bank), value)
        .map_err(|_| refused("complete original component serialization failed"))
}

struct OriginalBytesWriter<'a> {
    original: &'a [u8],
    position: usize,
}

impl Write for OriginalBytesWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("original component extent overflow"))?;
        if self.original.get(self.position..end) != Some(bytes) {
            return Err(io::Error::other("original component bytes changed"));
        }
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The closed full reference has a fixed canonical key order. Stream that
// exact spelling into a borrowed comparison sink; ordinary whole HashRef serde
// has a different key order and provider-private parsing APIs are unnecessary.
pub(super) fn authenticate_canonical_reference_bytes(
    bytes: &[u8],
    original: &crucible_node_contract::ContentRef,
) -> Result<(), OperationFailure> {
    let mut writer = OriginalBytesWriter {
        original: bytes,
        position: 0,
    };
    reference_chunk(&mut writer, b"{\"hash\":{\"algorithm\":")?;
    reference_string(&mut writer, &original.hash.algorithm)?;
    reference_chunk(&mut writer, b",\"digest\":")?;
    reference_string(&mut writer, &original.hash.digest)?;
    reference_chunk(&mut writer, b",\"domain\":")?;
    reference_string(&mut writer, &original.hash.domain)?;
    reference_chunk(&mut writer, b"},\"length\":\"")?;

    let mut value = original.length.get();
    let mut digits = [0u8; 20];
    let mut first = digits.len();
    loop {
        first -= 1;
        digits[first] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    reference_chunk(&mut writer, &digits[first..])?;
    reference_chunk(&mut writer, b"\",\"media_type\":")?;
    reference_string(&mut writer, &original.media_type)?;
    reference_chunk(&mut writer, b"}")?;
    if writer.position != bytes.len() {
        return Err(refused("original canonical reference extent differs"));
    }
    Ok(())
}

fn reference_string(
    writer: &mut OriginalBytesWriter<'_>,
    value: &str,
) -> Result<(), OperationFailure> {
    // A JSON string scalar has the same escaping in serde and JCS. This writes
    // directly to the sink without serde_json::to_string's owning String.
    serde_json::to_writer(writer, value)
        .map_err(|_| refused("original canonical reference scalar differs"))
}

fn reference_chunk(
    writer: &mut OriginalBytesWriter<'_>,
    value: &[u8],
) -> Result<(), OperationFailure> {
    writer
        .write_all(value)
        .map_err(|_| refused("original canonical reference fields differ"))
}

pub(super) fn authenticate_component(
    original: &InputPayload,
    value: &impl serde::Serialize,
) -> Result<(), OperationFailure> {
    original
        .reference
        .verify(&original.bytes)
        .map_err(super::unknown)?;
    let mut writer = OriginalBytesWriter {
        original: &original.bytes,
        position: 0,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| refused("recorded original component differs from current custody"))?;
    if writer.position != original.bytes.len() {
        return Err(refused(
            "recorded original component has another complete extent",
        ));
    }
    Ok(())
}

pub(super) fn take_component(
    reservation: &mut Option<CnpSemanticSnapshotReservation>,
    content_type: &str,
) -> Result<InputPayload, OperationFailure> {
    let bank = reservation
        .as_ref()
        .filter(|bank| bank.started && !bank.bytes.is_empty())
        .ok_or_else(|| refused("original component bank is incomplete"))?;
    let reference = canonical::content_ref(&bank.bytes, content_type).map_err(super::unknown)?;
    let bank = reservation
        .take()
        .ok_or_else(|| refused("original component bank disappeared"))?;
    Ok(InputPayload {
        reference,
        bytes: bank.bytes,
    })
}

fn record_into_bank(
    runtime: &super::state::SemanticRuntimeCustody,
    bank: &mut CnpSemanticSnapshotReservation,
) -> Result<(), OperationFailure> {
    if bank.started || !bank.bytes.is_empty() {
        return Err(refused("original semantic bank has already been attempted"));
    }
    // Attempt identity is retained even when the complete no-copy count refuses.
    bank.started = true;
    super::budget::serialized_size(&view::CustodyView(runtime), bank.maximum)?;
    serde_json::to_writer(BankWriter(bank), &view::CustodyView(runtime))
        .map_err(|_| refused("complete original semantic serialization failed"))
}

pub(super) fn complete_size(
    runtime: &super::state::SemanticRuntimeCustody,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    super::budget::serialized_size(&view::CustodyView(runtime), maximum)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Assertion failure is the modeled data-control verdict.
    #![allow(clippy::unwrap_used)]

    use super::super::{budget::SemanticCredit, state::*};
    use super::*;
    use crucible_node_contract::{Extensions, Id, U64, canonical};
    use crucible_node_provider::{
        bodies::{BeginKind, BeginRequest},
        envelope::Nullable,
    };

    fn custody() -> SemanticRuntimeCustody {
        let admission = crate::node_contract::test_original_admission("semantic-custody-history");
        let active = admission.activation().clone();
        let original = OriginalOperation {
            begin: BeginRequest {
                kind: BeginKind::ExactRun,
                binding_hash: canonical::json_hash("inert-binding", &"original").unwrap(),
                owner_generation: active.record().owners[0].generation,
                activation_id: Nullable(Some(active.record().activation_id.clone())),
                world_generation: active.record().generation,
                arguments: serde_json::Map::new(),
                extensions: Extensions::new(),
            },
            admission,
            outcome: None,
            failure: Some(refused("retained original refusal")),
            polls: U64::new(7),
            begin_acknowledged: true,
            cancellation: OriginalCancellation::Failed(refused("cancel")),
            acknowledged: true,
            retirement: Some(InputPayload {
                reference: canonical::content_ref(&[0, 255, 1], "application/octet-stream")
                    .unwrap(),
                bytes: vec![0, 255, 1],
            }),
        };
        let mut runtime = SemanticRuntimeCustody {
            active: Some(active),
            observe_sequence: U64::new(9),
            watermark: U64::new(3),
            ..SemanticRuntimeCustody::default()
        };
        runtime.credit = SemanticCredit::default();
        runtime.credit.reserve_bytes(1234, 1234).unwrap();
        runtime
            .operations
            .insert(Id::new("same-original-request").unwrap(), original);
        runtime
    }

    #[test]
    fn complete_history_keeps_raw_retirement_and_failed_original_without_mutation() {
        let runtime = custody();
        let before = complete_size(&runtime, 65_536).unwrap();
        let mut bank = CnpSemanticSnapshotReservation::reserve(before, before).unwrap();
        let capacity = bank.allocated_bytes();

        record_into_bank(&runtime, &mut bank).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bank.bytes).unwrap();
        let original = &value["operations"]["same-original-request"];
        assert_eq!(
            original["retirement"]["bytes"],
            serde_json::json!([0, 255, 1])
        );
        assert_eq!(original["failure"]["reason"], "retained original refusal");
        assert_eq!(original["cancellation"][0], "failed");
        assert_eq!(original["polls"], "7");
        assert_eq!(value["retained_credit"], 1234);
        assert_eq!(runtime.operations.len(), 1);
        assert_eq!(complete_size(&runtime, 65_536).unwrap(), before);
        assert_eq!(bank.allocated_bytes(), capacity);
    }

    #[test]
    fn full_extent_precharge_and_attempt_are_sticky_before_partial_write() {
        let runtime = custody();
        let extent = complete_size(&runtime, 65_536).unwrap();
        let mut bank = CnpSemanticSnapshotReservation::reserve(extent - 1, extent - 1).unwrap();
        let capacity = bank.allocated_bytes();

        assert!(record_into_bank(&runtime, &mut bank).is_err());
        assert!(bank.started);
        assert!(bank.bytes.is_empty());
        assert!(record_into_bank(&runtime, &mut bank).is_err());
        assert_eq!(bank.allocated_bytes(), capacity);
        assert_eq!(runtime.operations.len(), 1);
    }
    #[test]
    fn original_native_return_copy_keeps_controller_bytes_independent_and_capacity_fixed() {
        let mut controller_bytes = vec![0, 255, 17, 128];
        let reference =
            canonical::content_ref(&controller_bytes, "application/octet-stream").unwrap();
        let mut bank = Some(CnpSemanticSnapshotReservation::reserve(1024, 1024).unwrap());
        let capacity = bank.as_ref().unwrap().allocated_bytes();

        let returned = record_original_bytes(&mut bank, &reference, &controller_bytes).unwrap();

        assert!(bank.is_none());
        assert_eq!(returned.bytes.capacity(), capacity);
        assert_eq!(returned.bytes, controller_bytes);
        assert_ne!(returned.bytes.as_ptr(), controller_bytes.as_ptr());
        controller_bytes[0] = 19;
        assert_eq!(returned.bytes, [0, 255, 17, 128]);
        returned.reference.verify(&returned.bytes).unwrap();
    }

    #[test]
    fn original_native_return_hash_refusal_retains_attempted_bank_and_forbids_reuse() {
        let original = [0, 255, 17, 128];
        let reference = canonical::content_ref(&original, "application/octet-stream").unwrap();
        let mut bank = Some(CnpSemanticSnapshotReservation::reserve(1024, 1024).unwrap());
        let capacity = bank.as_ref().unwrap().allocated_bytes();

        assert!(record_original_bytes(&mut bank, &reference, &[1, 255, 17, 128]).is_err());

        let retained = bank.as_ref().unwrap();
        assert_eq!(retained.allocated_bytes(), capacity);
        assert!(retained.started);
        assert!(retained.bytes.is_empty());
        assert!(record_original_bytes(&mut bank, &reference, &original).is_err());
        reference.verify(&original).unwrap();
    }
}

impl CnpSemanticSnapshotReservation {
    /// Observes metadata apart from the caller's already counted byte-bank capacity.
    ///
    /// This object has no independent metadata heap. Its fixed fields belong to
    /// the caller's containing slot; `allocated_bytes` is a separate actual bank
    /// term. A zero metadata result grants no capture or reservation permission.
    ///
    /// # Errors
    /// Refuses a view from another original process or creator thread.
    pub fn retained_metadata_requested_storage_data(&self) -> Result<usize, OperationFailure> {
        self.storage_origin.check()?;
        Ok(0)
    }
}

impl CnpOriginalSemanticSnapshot {
    /// Observes actual full-reference and opaque-activation metadata backing.
    ///
    /// The payload byte capacity and this value's inline containing slot remain
    /// separate caller-owned terms. Shared Core allocations receive actual
    /// identity-bound credit; no serialized activation label identifies them.
    ///
    /// # Errors
    /// Refuses foreign creators, unsupported Core metadata or exhausted credit.
    pub fn retained_metadata_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<super::CnpRetainedStorageReport, OperationFailure> {
        self.storage_origin.check()?;
        let mut counter = super::retained_storage::Counter::new(maximum);
        counter.charge(&self.payload.reference)?;
        super::retained_storage::common::activation(&self.active, &mut counter)?;
        self.storage_origin.check()?;
        Ok(counter.finish())
    }
}

#[cfg(test)]
#[path = "semantic_snapshot/reference_tests.rs"]
mod reference_tests;

#[cfg(test)]
#[path = "semantic_snapshot/canonical_component_tests.rs"]
mod canonical_component_tests;

impl CnpSemanticSnapshotReservation {
    pub(in crate::node_adapters::cnp::semantic) fn retained_metadata_requested_storage_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.storage_origin.check_precredit_data()?;
        Ok(0)
    }
}

impl CnpOriginalSemanticSnapshot {
    pub(in crate::node_adapters::cnp::semantic) fn retained_metadata_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<super::CnpRetainedStorageReport, crate::node_contract::RuntimeError> {
        self.storage_origin.check_precredit_data()?;
        let mut counter = super::retained_storage::preparation::PreparationCounter::new(maximum);
        counter.content_reference(&self.payload.reference)?;
        counter.activation(&self.active)?;
        self.storage_origin.check_precredit_data()?;
        Ok(counter.finish())
    }
}

#[cfg(test)]
mod original_raw_reservation_tests {
    use super::*;
    use crate::node_contract::RuntimeError;

    #[test]
    fn original_raw_reservation_exact_and_short_preserve_real_destination() {
        let mut completed = None;
        assert_eq!(
            CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
                64,
                63,
                &mut completed,
            ),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(completed.is_none());

        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            64,
            64,
            &mut completed,
        )
        .unwrap();
        let original = completed.as_ref().unwrap();
        let pointer = original.bytes.as_ptr();
        let capacity = original.allocated_bytes();
        assert_eq!(capacity, 64);
        assert_eq!(
            original.retained_metadata_requested_storage_precredit_data(),
            Ok(0)
        );
        assert!(!original.started);

        assert!(
            CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
                32,
                32,
                &mut completed,
            )
            .is_err()
        );
        let still_original = completed.as_ref().unwrap();
        assert_eq!(still_original.bytes.as_ptr(), pointer);
        assert_eq!(still_original.allocated_bytes(), capacity);
        assert!(!still_original.started);
    }

    #[test]
    fn original_raw_reservation_keeps_legacy_bound_refusal_and_byte_extent() {
        assert!(CnpSemanticSnapshotReservation::reserve(0, 64).is_err());
        assert!(CnpSemanticSnapshotReservation::reserve(65, 64).is_err());
        let legacy = CnpSemanticSnapshotReservation::reserve(64, 64).unwrap();
        let raw =
            CnpSemanticSnapshotReservation::reserve_with_error::<RuntimeError>(64, 64).unwrap();
        assert_eq!(legacy.maximum_bytes(), raw.maximum_bytes());
        assert_eq!(legacy.allocated_bytes(), raw.allocated_bytes());
        assert!(legacy.bytes.is_empty() && raw.bytes.is_empty());
        assert!(!legacy.started && !raw.started);
        assert!(
            CnpSemanticSnapshotReservation::reservation_counter_scratch_data()
                >= std::mem::size_of::<CnpSemanticSnapshotReservation>()
        );
    }
}
