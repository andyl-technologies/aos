//! Joins the explicitly selected outer record12 to original receipt/report custody.
//!
//! The same controller retains all raw bodies before this readonly Source walk.
//! The report is borrowed through a fixed-field parser, without another report
//! DOM. This establishes correlation only: authentic original source/native
//! guards, underlying model validation and whole allocation action remain
//! mandatory. No portable report scalar or matching reference issues rights.

use super::*;
use crucible_node_transport::envelope::Method;
use crucible_node_transport::reference_packet::{
    control::PacketNative5Record,
    service::capture_allocation::{
        PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
        PacketNative5CaptureAllocationSelection, PacketNativeCaptureAllocationRecord,
        PacketNativeCaptureAllocationReportView,
    },
};

pub(in crate::node_adapters::cnp::semantic) struct CompleteReceiptData<'a> {
    pub(in crate::node_adapters::cnp::semantic) receipt: PacketNative5Record,
    pub(in crate::node_adapters::cnp::semantic) allocation:
        Option<OriginalCaptureAllocationData<'a>>,
}

/// Retains the full original report reference beside its same-controller body loan.
///
/// Only current Source receipt validation constructs this view. It is not an
/// allocation issuer or evidence of an accepted Capture/restoration class.
pub struct OriginalCaptureAllocationData<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    report: PacketNativeCaptureAllocationReportView<'a>,
}

impl OriginalCaptureAllocationData<'_> {
    /// Borrows the complete original report identity, including media and length.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the actual report bytes already retained by this controller.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Borrows checked report data without making a currency or budget claim.
    pub fn report_data(&self) -> &PacketNativeCaptureAllocationReportView<'_> {
        &self.report
    }
}

/// Counts fixed original report-view and receipt-result counter headers.
///
/// The installed operation must preadmit this counter before the corresponding
/// Source walk. Existing receipt DOM/typed decoder, raw content hashing and
/// enclosing Source/kernel/currentness phases remain separately accounted.
pub fn original_capture_allocation_witness_counter_scratch_data() -> usize {
    std::mem::size_of::<CompleteReceiptData<'static>>()
        + std::mem::size_of::<OriginalCaptureAllocationData<'static>>()
        + crucible_node_transport::reference_packet::service::capture_allocation::original_capture_allocation_report_counter_scratch_data()
}

pub(in crate::node_adapters::cnp::semantic) fn decode_complete_receipt_value(
    value: serde_json::Value,
    selection: Option<PacketNative5CaptureAllocationSelection>,
) -> Result<(PacketNative5Record, Option<ContentRef>), OperationFailure> {
    if value.get("schema").and_then(serde_json::Value::as_str)
        == Some(PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD)
    {
        if selection != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12) {
            return Err(refused("unselected outer native allocation record"));
        }
        let outer: PacketNativeCaptureAllocationRecord =
            serde_json::from_value(value).map_err(unknown)?;
        outer.validate_data().map_err(unknown)?;
        return Ok((outer.native, Some(outer.allocation)));
    }
    let receipt: PacketNative5Record = serde_json::from_value(value).map_err(unknown)?;
    if selection.is_some() && receipt.original.method == Method::Observe {
        return Err(refused(
            "selected Observe lacks complete allocation wrapper",
        ));
    }
    Ok((receipt, None))
}

pub(in crate::node_adapters::cnp::semantic) fn decode_complete_receipt_data<'a>(
    scope: &CnpSemanticRealizationScope<'a>,
    bytes: &[u8],
    value: serde_json::Value,
    selection: Option<PacketNative5CaptureAllocationSelection>,
) -> Result<CompleteReceiptData<'a>, OperationFailure> {
    let (receipt, allocation) = decode_complete_receipt_value(value, selection)?;
    let allocation = if let Some(reference) = allocation {
        crucible_node_transport::reference_packet::service::capture_allocation::original_capture_allocation_native_bytes_data(bytes, &reference).map_err(unknown)?;
        let owning_profile = matches!(
            receipt.capture_profile,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        );
        let born_metadata = receipt.protocol_metadata_limits.is_some()
            && receipt.protocol_metadata_birth_facts.is_some();
        let canonical_ack = receipt.ack_emitter_selection == Some(
            crucible_node_transport::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5
        );
        if !owning_profile || !born_metadata || !canonical_ack {
            return Err(refused(
                "allocation receipt lost selected owning native tuple",
            ));
        }
        if !scope
            .controller
            .authority()
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
        {
            return Err(refused("selected allocation feature not negotiated"));
        }
        let bytes = scope
            .controller
            .original_capture_allocation_body_data(&reference)
            .map_err(unknown)?;
        let report =
            PacketNativeCaptureAllocationReportView::from_original_bytes(bytes).map_err(unknown)?;
        let digest = scope
            .controller
            .original_capture_allocation_observe_hash_data(&receipt.original)
            .map_err(unknown)?;
        report
            .authenticate_receipt_data(&receipt, &digest)
            .map_err(unknown)?;
        if Some(report.metadata_banks_data()) != receipt.protocol_metadata_birth_facts {
            return Err(refused(
                "report metadata banks differ from same born receipt",
            ));
        }
        let before = scope
            .controller
            .originals_by_origin(crucible_node_transport::envelope::RequestOrigin::Controller)
            .filter(|original| {
                original.request.sequence < receipt.original.sequence
                    && !matches!(
                        original.request.method,
                        Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                    )
            })
            .count();
        if u64::try_from(before).map_err(unknown)? != report.control_originals_before_data().get()
            || scope
                .controller
                .original_capture_allocation_first_proof_sequence_data(&receipt.native_record)
                .map_err(unknown)?
                != report.provider_next_sequence_before_data()
        {
            return Err(refused("allocation report original/proof frontier differs"));
        }
        Some(OriginalCaptureAllocationData {
            reference,
            bytes,
            report,
        })
    } else {
        None
    };
    Ok(CompleteReceiptData {
        receipt,
        allocation,
    })
}

pub(in crate::node_adapters::cnp::semantic) fn authenticate_allocation_cursor(
    allocation: Option<&OriginalCaptureAllocationData<'_>>,
    cursor: Position,
) -> Result<(), OperationFailure> {
    if allocation.is_some_and(|allocation| allocation.report.model_cursor_data() != cursor) {
        return Err(refused(
            "original allocation report model cursor differs from verified raw record",
        ));
    }
    Ok(())
}

// The original Observe may be read historically. Its quote data is current only
// while no later controller request (including upload/failed request) exists.
fn original_frontier_current(mut sequences: impl Iterator<Item = U64>, observe: U64) -> bool {
    !sequences.any(|sequence| sequence > observe)
}

impl PacketCompleteSemanticSource {
    /// Borrows the latest selected report beneath the exact current Source frontier.
    ///
    /// This data view requires no later controller original after its Observe.
    /// Source/kernel/actor guards run again before return. The native owning
    /// currency and a separate whole-world action are still required for Capture.
    ///
    /// # Errors
    /// Refuses an absent selection/report, changed source/currentness, any later
    /// original, mismatched proof or incomplete native witness.
    pub fn latest_original_capture_allocation_witness_data<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
    ) -> Result<super::witness::PacketCompleteNativeWitness<'a>, OperationFailure> {
        if self.selected_capture_allocation_selection()?
            != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(refused("original capture allocation is not selected"));
        }
        let witness = self.latest_original_native_witness(scope)?;
        let report = witness
            .allocation_data()
            .ok_or_else(|| refused("selected report not retained"))?;
        if !original_frontier_current(
            scope
                .controller
                .originals_by_origin(crucible_node_transport::envelope::RequestOrigin::Controller)
                .map(|original| original.request.sequence),
            witness.receipt().original.sequence,
        ) || report.report_data().model_cursor_data()
            != match witness.native_record() {
                super::witness::PacketCompleteNativeRecord::Producer(record) => {
                    record.inventory.reached
                }
                super::witness::PacketCompleteNativeRecord::Reactive(record) => {
                    record.inventory.reached
                }
            }
        {
            return Err(refused(
                "original report no longer has the sole current frontier",
            ));
        }
        self.authenticate_witness_scope(scope)?;
        Ok(witness)
    }

    pub(super) fn selected_allocation_observation(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        root: &ContentRef,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let result = (|| {
            let witness = self.original_native_witness(scope, root)?;
            let allocation = witness
                .allocation_data()
                .ok_or_else(|| refused("selected observation omitted allocation report"))?;
            let report = allocation.report_data();
            if report.activation_data() != activation.record().activation_id.as_str()
                || report.world_generation_data() != activation.record().generation
            {
                return Err(refused(
                    "original allocation activation differs from actual world",
                ));
            }
            let observation = match (&self.original, witness.native_record()) {
                (
                    CompletePacketOriginal::Producer(source),
                    super::witness::PacketCompleteNativeRecord::Producer(record),
                ) => source.observation(activation, root, record),
                (
                    CompletePacketOriginal::Reactive(source),
                    super::witness::PacketCompleteNativeRecord::Reactive(record),
                ) => source.observation(activation, root, record),
                _ => Err(refused(
                    "allocation observation changed original model family",
                )),
            }?;
            Ok(observation)
        })();
        // Preserve the selected Reactive path's final original-source fence on
        // both success and refusal after model/report inspection.
        self.authenticate_witness_scope(scope)?;
        result
    }
}

#[cfg(test)]
mod tests {
    //! DATA-only closed decoder controls; none substitutes Source/native guards.
    use super::*;
    use crucible_node_transport::envelope::{Envelope, MessageKind, Nullable};
    use crucible_node_transport::handshake::Limits;
    use crucible_node_transport::reference_packet::{
        control::PacketNative5StorageSelection, service::PacketNative5StorageLimits,
    };
    use serde_json::{Value, json};

    fn receipt(method: Method) -> PacketNative5Record {
        let id = |name: &str| Id::new(name).unwrap();
        let hash = canonical::hash("cnp.owner-binding.v1", b"decoder model").unwrap();
        PacketNative5Record {
            schema: "source-owned.packet-receipt/5".into(),
            native_pid: U64::new(42),
            original: Envelope {
                protocol: "CNP/1".into(),
                message: MessageKind::Request,
                session_id: Nullable(Some(id("session"))),
                incarnation_id: Nullable(Some(id("incarnation"))),
                node_id: Nullable(Some(id("node"))),
                execution_owner_id: Nullable(Some(id("owner"))),
                capture_owner_id: Nullable(None),
                request_id: Nullable(Some(id("request"))),
                operation_id: Nullable(None),
                sequence: U64::new(3),
                method,
                body: serde_json::Map::new(),
                extensions: Extensions::new(),
            },
            binding_hash: hash.clone(),
            session: id("session"),
            incarnation: id("incarnation"),
            node: id("node"),
            owner: id("owner"),
            owner_generation: U64::new(1),
            input_epoch: id("epoch"),
            world: canonical::hash("cnp.world-binding.v1", b"decoder world").unwrap(),
            native_record: canonical::content_ref(b"raw model", "application/json").unwrap(),
            storage_selection: PacketNative5StorageSelection {
                storage: PacketNative5StorageLimits {
                    snapshot_bytes: U64::new(4096),
                    control_snapshot_bytes: U64::new(1024),
                    protocol_snapshot_bytes: U64::new(1024),
                    frame_bank_bytes: U64::new(131072),
                    frames_per_direction: U64::new(256),
                    hello_bytes: U64::new(65536),
                    settlement_bytes: U64::new(4096),
                },
                limits: Limits {
                    frame_bytes: U64::new(65536),
                    nesting: U64::new(64),
                    requests: U64::new(256),
                    journal_entries: U64::new(4096),
                    blob_chunk_bytes: U64::new(4096),
                },
            },
            capture_profile: PacketNative5CaptureProfile::OriginalArrays6,
            confirmation_selection: None,
            ack_emitter_selection: None,
            complete_restore_selection: None,
            protocol_metadata_limits: None,
            protocol_metadata_birth_facts: None,
            restore_input_emitter_selection: None,
        }
    }

    #[test]
    fn legacy_receipt5_stays_exact_and_selected_observe_cannot_downgrade() {
        let observe = receipt(Method::Observe);
        let value = serde_json::to_value(&observe).unwrap();
        let (decoded, allocation) = decode_complete_receipt_value(value.clone(), None).unwrap();
        assert_eq!(decoded, observe);
        assert!(allocation.is_none());
        assert!(
            decode_complete_receipt_value(
                value,
                Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            )
            .is_err()
        );
        let realize = receipt(Method::Realize);
        let (decoded, allocation) = decode_complete_receipt_value(
            serde_json::to_value(&realize).unwrap(),
            Some(PacketNative5CaptureAllocationSelection::OriginalObserve12),
        )
        .unwrap();
        assert_eq!(decoded, realize);
        assert!(allocation.is_none());
    }

    #[test]
    fn outer12_requires_actual_choice_full_reference_and_closed_data() {
        let native = receipt(Method::Observe);
        let reference = canonical::content_ref(b"inert report DATA", crucible_node_transport::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA).unwrap();
        let record = PacketNativeCaptureAllocationRecord {
            schema: PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD.into(),
            native: native.clone(),
            allocation: reference.clone(),
        };
        let value = serde_json::to_value(&record).unwrap();
        let choice = Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
        assert!(decode_complete_receipt_value(value.clone(), None).is_err());
        let (decoded, allocation) = decode_complete_receipt_value(value.clone(), choice).unwrap();
        assert_eq!(decoded, native);
        assert_eq!(allocation.as_ref(), Some(&reference));
        for axis in 0..4 {
            let mut other = value.clone();
            match axis {
                0 => other["allocation"]["media_type"] = json!("application/json"),
                1 => other["allocation"]["length"] = json!("16385"),
                2 => {
                    other["native"]["original"]["method"] =
                        serde_json::to_value(Method::Realize).unwrap()
                }
                _ => {
                    other
                        .as_object_mut()
                        .unwrap()
                        .insert("permission".into(), Value::Bool(true));
                }
            }
            assert!(
                decode_complete_receipt_value(other, choice).is_err(),
                "axis {axis}"
            );
        }
    }
    #[test]
    fn later_original_refuses_current_report_without_consuming_retained_data() {
        let originals = [U64::new(1), U64::new(4), U64::new(7)];
        assert!(original_frontier_current(
            originals.iter().copied(),
            U64::new(7)
        ));
        assert!(!original_frontier_current(
            originals.iter().copied(),
            U64::new(4)
        ));
        assert_eq!(originals, [U64::new(1), U64::new(4), U64::new(7)]);
    }
}
