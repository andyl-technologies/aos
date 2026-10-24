//! Frames the complete, nonauthorizing Create Storage Ready input bundle.
//!
//! ```text
//! AOSXBR01 | lane[16] | twenty-five (length:u32be, exact-field) pairs
//! fields = Intent record, Intent native receipt, Spec, Source Held,
//!          Cache Held, complete Cache node quotas, AssignmentPlanned,
//!          Ownership Begin request/response, completed request/response,
//!          claim, lease, lease signature, transaction receipt/signature,
//!          Storage ClientHello/BrokerHello, Inventory request/response,
//!          Inventory checkpoint, proposed Storage model,
//!          current Controller admission, signed policy sources,
//!          complete compiler origin/input/candidate
//! ```
//!
//! Only the Begin response may be empty: the original sent Begin can remain
//! uncertain while a later authenticated Query completes the same transaction.
//! Every other field must be present. This borrowed framing performs no typed
//! protobuf/CBOR decoding, signature verification, replay or native observation.
//! The independent Root consumer must price and validate those nested owners
//! and its own current cut before selecting a positive transition.

use super::super::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RecordEnvelopeV1, nonzero, reader,
};
use super::super::assignment_planned::AssignmentPlannedBodyDataV1;
use super::super::cache_held::CacheHeldReceiptDataV1;
use super::super::controller_intent::{ControllerIntentBodyDataV1, controller_intent_seed_v1};
use super::super::source_held::SourceHeldReceiptDataV1;
use super::super::super::protected_names::ProtectedJournalNamesV1;

mod framing;

const MAGIC: &[u8; 8] = b"AOSXBR01";
const FIXED_BYTES: usize = 24;
const FIELD_COUNT: usize = 25;
const OPTIONAL_BEGIN_RESPONSE: usize = 8;

/// Borrows complete original inputs without constructing current authority.
///
/// Each field retains its existing nested canonical schema and ceiling. A
/// producer must obtain it from the actual live original and reserve the
/// checked complete width before allocating its output. The frame's lane and
/// its checksums are correlation DATA, never a loan, signer or Root verdict.
#[derive(Clone, Copy)]
pub struct ReadyBundleDataV1<'fields> {
    /// The genuine continuation lane, compared with every included history row.
    pub lane: [u8; 16],
    /// The complete first Controller Intent record containing all A fields.
    pub intent_record: &'fields [u8],
    /// Its exact returned head, protected names, NEXT and durable end.
    pub intent_native_receipt: &'fields [u8],
    /// The original complete canonical Spec bytes, not just its descriptor.
    pub specification: &'fields [u8],
    /// The complete 508-byte Source Held record/head/native receipt.
    pub source_held: &'fields [u8],
    /// The complete 1052-byte Cache Held record/head/native receipt.
    pub cache_held: &'fields [u8],
    /// The complete original node-quota rows under the selected Cache cut.
    pub cache_node_quotas: &'fields [u8],
    /// The committed phase12 record including the exact assignment preimage.
    pub assignment_planned: &'fields [u8],
    /// The actual earliest sent authenticated Begin frame, never regenerated.
    pub ownership_begin_request: &'fields [u8],
    /// Its actual response frame, or empty if that original response was absent.
    pub ownership_begin_response: &'fields [u8],
    /// The actual authenticated request that observed the completed transaction.
    pub ownership_completed_request: &'fields [u8],
    /// Its exact authenticated completed response frame.
    pub ownership_completed_response: &'fields [u8],
    /// The exact original canonical acquisition claim.
    pub ownership_claim: &'fields [u8],
    /// The original verified canonical lease, still independently verified by Root.
    pub ownership_lease: &'fields [u8],
    /// Its complete detached canonical signature.
    pub ownership_signature: &'fields [u8],
    /// The issuer's complete canonical transaction receipt.
    pub ownership_receipt: &'fields [u8],
    /// The complete detached transaction-receipt signature.
    pub ownership_receipt_signature: &'fields [u8],
    /// The actual same-Session signed narrow ClientHello.
    pub storage_client_hello: &'fields [u8],
    /// The actual signed BrokerHello that completed that same Session.
    pub storage_broker_hello: &'fields [u8],
    /// The exact authenticated Inventory request installed on that Session.
    pub storage_inventory_request: &'fields [u8],
    /// Its complete authenticated terminal, including the catalog observation.
    pub storage_inventory_response: &'fields [u8],
    /// The actual canonical terminal checkpoint/currentness predecessor.
    pub storage_inventory_checkpoint: &'fields [u8],
    /// The unsigned proposed quota/reservation/expiry and catalog-bound model.
    pub proposed_storage: &'fields [u8],
    /// The actual current Controller bank/admission comparison from this paid cut.
    pub controller_admission: &'fields [u8],
    /// The original signed Project/Deployment packets and their exact inputs.
    pub policy_sources: &'fields [u8],
    /// The complete proposed compiler input and candidate in its existing format.
    pub compiler_origin: &'fields [u8],
}

impl<'fields> ReadyBundleDataV1<'fields> {
    /// Bounds the complete allocation-free fixed historical framing work.
    ///
    /// This counts the compiled fixed invocation roster and return planes of
    /// this codec only. It excludes the already-owned encoded input, variable
    /// output, typed protobuf/CBOR decoders, replay, crypto and native custody.
    /// No declared byte count or borrowed view creates a receiving permission.
    #[doc(hidden)]
    #[must_use]
    pub fn fixed_framing_receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        framing::receiving_demand_v1()
    }

    /// Borrows exact framing and checks the shared historical row associations.
    ///
    /// # Errors
    /// Rejects wrong magic, a reserved lane, missing required fields, truncated
    /// or trailing data, invalid Held/Intent/Assignment framing or mismatched
    /// original associations. Nested signatures, models and live state are not
    /// accepted by this operation and require independent paid validation.
    pub fn decode(bytes: &'fields [u8]) -> Result<Self, HistoryErrorV1> {
        let value = Self::borrow_field_framing_data_v1(bytes)?;
        value.encoded_bytes()?;
        Ok(value)
    }

    /// Borrows only exact twenty-five-field byte framing as comparison DATA.
    ///
    /// This shares the full decoder's parser without repeating nested history
    /// checks. It checks neither required fields, reserved lane, nested models
    /// nor associations. Closed consumers may reuse an earlier complete check
    /// only on the SAME immutable original; this grants no authority.
    ///
    /// # Errors
    /// Rejects wrong magic, truncated fields or trailing bytes.
    #[doc(hidden)]
    pub fn borrow_field_framing_data_v1(bytes: &'fields [u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *MAGIC {
            return Err(HistoryErrorV1::Malformed);
        }
        let lane = input.array()?;
        let mut fields = [&[][..]; FIELD_COUNT];
        for field in &mut fields {
            let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
            *field = input.bytes(length)?;
        }
        input.finish()?;

        let [intent_record, intent_native_receipt, specification, source_held,
            cache_held, cache_node_quotas, assignment_planned,
            ownership_begin_request, ownership_begin_response,
            ownership_completed_request, ownership_completed_response,
            ownership_claim, ownership_lease, ownership_signature,
            ownership_receipt, ownership_receipt_signature,
            storage_client_hello, storage_broker_hello, storage_inventory_request,
            storage_inventory_response, storage_inventory_checkpoint,
            proposed_storage, controller_admission, policy_sources,
            compiler_origin] = fields;
        let value = Self {
            lane, intent_record, intent_native_receipt, specification,
            source_held, cache_held, cache_node_quotas, assignment_planned,
            ownership_begin_request, ownership_begin_response,
            ownership_completed_request, ownership_completed_response,
            ownership_claim, ownership_lease, ownership_signature,
            ownership_receipt, ownership_receipt_signature,
            storage_client_hello, storage_broker_hello, storage_inventory_request,
            storage_inventory_response, storage_inventory_checkpoint,
            proposed_storage, controller_admission, policy_sources,
            compiler_origin,
        };
        Ok(value)
    }

    /// Measures the checked complete encoding from the actual borrowed extents.
    ///
    /// No smaller global cap is introduced. Each existing nested owner retains
    /// its own schema bound; the actual complete sum must pass the genuine
    /// receiving ledger before output storage or nested decoder growth.
    ///
    /// # Errors
    /// Rejects a missing required field, invalid shared history association,
    /// an individual field beyond its `u32` wire width or total-size overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        nonzero(&self.lane)?;
        self.require_history_association()?;
        self.fields().into_iter().enumerate().try_fold(
            FIXED_BYTES + 4 * FIELD_COUNT,
            |total, (index, field)| {
                if field.is_empty() && index != OPTIONAL_BEGIN_RESPONSE {
                    return Err(HistoryErrorV1::Malformed);
                }
                u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
                total.checked_add(field.len()).ok_or(HistoryErrorV1::Extent)
            },
        )
    }

    /// Writes the complete frame into exactly sized, prepaid caller storage.
    ///
    /// # Errors
    /// Rejects the same invalid framing and associations as [`Self::encoded_bytes`]
    /// or a nonexact destination width before writing any output bytes.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        if output.len() != self.encoded_bytes()? {
            return Err(HistoryErrorV1::Extent);
        }
        output[..8].copy_from_slice(MAGIC);
        output[8..FIXED_BYTES].copy_from_slice(&self.lane);
        let mut offset = FIXED_BYTES;
        for field in self.fields() {
            let length = u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
            output[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
            offset += 4;
            let end = offset + field.len();
            output[offset..end].copy_from_slice(field);
            offset = end;
        }
        Ok(())
    }

    fn fields(self) -> [&'fields [u8]; FIELD_COUNT] {
        [self.intent_record, self.intent_native_receipt, self.specification,
            self.source_held, self.cache_held, self.cache_node_quotas,
            self.assignment_planned, self.ownership_begin_request,
            self.ownership_begin_response, self.ownership_completed_request,
            self.ownership_completed_response, self.ownership_claim,
            self.ownership_lease, self.ownership_signature, self.ownership_receipt,
            self.ownership_receipt_signature, self.storage_client_hello,
            self.storage_broker_hello, self.storage_inventory_request,
            self.storage_inventory_response, self.storage_inventory_checkpoint,
            self.proposed_storage, self.controller_admission, self.policy_sources,
            self.compiler_origin]
    }

    fn require_history_association(self) -> Result<(), HistoryErrorV1> {
        let intent_key = KeyV1::new(self.lane, OwnerV1::Controller, 1)?;
        let intent = RecordEnvelopeV1::decode(self.intent_record, intent_key,
            PhaseV1::new(OwnerV1::Controller, 1)?)?;
        let association = ControllerIntentBodyDataV1::decode(intent.body())?;
        let original = association.identity;
        let seed = controller_intent_seed_v1(intent.body())?;
        if original.lane != self.lane || intent.coordinates().correlation != seed {
            return Err(HistoryErrorV1::Correlation);
        }
        let native = IntentNativeReceiptDataV1::decode(self.intent_native_receipt)?;
        let head_key = KeyV1::new(self.lane, OwnerV1::Controller, 0)?;
        LatestHeadV1::decode(&native.latest_head, head_key)?.check_record(head_key, intent)?;
        if native.names != original.j_names || native.after_next <= original.j_commit
            || native.after_end <= original.j_end {
            return Err(HistoryErrorV1::Correlation);
        }

        let source = SourceHeldReceiptDataV1::decode(self.source_held, self.lane)?;
        let source_body = source.body(self.lane)?;
        let fixed = source_body.association();
        if fixed.operation != original.operation || fixed.project != original.project
            || fixed.sandbox != original.sandbox
            || fixed.accepted_request != original.accepted_request
            || fixed.coissuance_binding != original.coissuance_binding
            || fixed.seed != seed || fixed.controller_nonce != original.controller_nonce
            || fixed.boot != original.boot || fixed.started != original.started
            || fixed.cutoff != original.cutoff {
            return Err(HistoryErrorV1::Correlation);
        }
        let cache = CacheHeldReceiptDataV1::decode(self.cache_held, self.lane)?;
        cache.compare_source(self.lane, source)?;
        let cache_body = cache.body(self.lane)?;
        let quotas = crate::cache_state::complete_node_quotas::CompleteNodeQuotaRowsDataV1::decode(
            self.cache_node_quotas).map_err(|_| HistoryErrorV1::Malformed)?;
        let j_head = crate::domain_ledger::resource_bank::AccountHead::decode(association.j_head)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if quotas.digest_v2().as_bytes() != &cache_body.quota
            || quotas.node() != j_head.native_fields().enrollment.native_fields().node
            || !quotas.rows().any(|row| row[..32] == cache_body.selected_partition) {
            return Err(HistoryErrorV1::Correlation);
        }
        let assignment = RecordEnvelopeV1::decode(self.assignment_planned,
            KeyV1::new(self.lane, OwnerV1::Controller, 2)?,
            PhaseV1::new(OwnerV1::Controller, 12)?)?;
        assignment.check_predecessor(intent)?;
        let planned = AssignmentPlannedBodyDataV1::decode(assignment.body())?;
        let source_record = RecordEnvelopeV1::decode(source.record,
            KeyV1::new(self.lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
        let cache_record = RecordEnvelopeV1::decode(cache.record,
            KeyV1::new(self.lane, OwnerV1::Cache, 1)?, PhaseV1::new(OwnerV1::Cache, 1)?)?;
        if planned.association != fixed || planned.source_held != source_record.checksum()
            || planned.cache_held != cache_record.checksum()
            || assignment.coordinates().correlation != seed {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

/// Carries the actual first Intent return as fixed historical comparison DATA.
///
/// ```text
/// latest-head[40] | protected-names[48] | after-NEXT:u64be | after-end:u64be
/// ```
#[derive(Clone, Copy)]
pub struct IntentNativeReceiptDataV1 {
    /// The head body atomically appended with the first Intent record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The unchanged actual protected Controller writer names.
    pub names: ProtectedJournalNamesV1,
    /// Its actual returned/read-back NEXT after Intent.
    pub after_next: u64,
    /// Its actual returned/read-back durable end after Intent.
    pub after_end: u64,
}

impl IntentNativeReceiptDataV1 {
    /// Borrows and checks the exact fixed native receipt framing.
    ///
    /// # Errors
    /// Rejects wrong extent, malformed physical names or zero native coordinates.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            latest_head: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?,
            after_end: input.u64()?,
        };
        input.finish()?;
        if value.after_next == 0 || value.after_end == 0 {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(value)
    }

    /// Writes the complete fixed native receipt without allocating.
    ///
    /// # Errors
    /// Rejects invalid physical names or zero native coordinates.
    pub fn encode(self) -> Result<[u8; HEAD_BYTES + 64], HistoryErrorV1> {
        let mut bytes = [0; HEAD_BYTES + 64];
        bytes[..HEAD_BYTES].copy_from_slice(&self.latest_head);
        bytes[HEAD_BYTES..HEAD_BYTES + 48].copy_from_slice(&self.names.to_bytes());
        bytes[HEAD_BYTES + 48..HEAD_BYTES + 56].copy_from_slice(&self.after_next.to_be_bytes());
        bytes[HEAD_BYTES + 56..].copy_from_slice(&self.after_end.to_be_bytes());
        Self::decode(&bytes)?;
        Ok(bytes)
    }
}

/// Borrows the three current logical bank records carried by B as DATA.
///
/// ```text
/// Controller-head-length:u32be | head | Sandbox-head-length:u32be | head |
/// J-claim-length:u32be | claim
/// ```
///
/// This is exact framing only. Root independently validates the existing bank
/// codecs, accepted original, current native head and complete resource limits.
#[derive(Clone, Copy)]
pub struct ControllerAdmissionDataV1<'records> {
    /// The actual current logical Controller account record.
    pub controller: &'records [u8],
    /// The actual current logical Sandbox C-child account record.
    pub sandbox: &'records [u8],
    /// The same entered J claim on that actual held Controller writer.
    pub intake: &'records [u8],
}

impl<'records> ControllerAdmissionDataV1<'records> {
    /// Borrows the three exact, nonempty recorded bank fields without allocation.
    ///
    /// # Errors
    /// Rejects missing, truncated or trailing fields. Bank semantics stay with
    /// their existing format owner and independently held native consumer.
    pub fn decode(bytes: &'records [u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let mut fields = [&[][..]; 3];
        for field in &mut fields {
            let count = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
            *field = input.bytes(count)?;
        }
        input.finish()?;
        let [controller, sandbox, intake] = fields;
        let value = Self { controller, sandbox, intake };
        value.encoded_bytes()?;
        Ok(value)
    }

    /// Measures the complete original records and their three length prefixes.
    ///
    /// # Errors
    /// Rejects an empty field or checked wire-width/total-size overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        [self.controller, self.sandbox, self.intake].into_iter().try_fold(12, |total: usize, field| {
            if field.is_empty() { return Err(HistoryErrorV1::Malformed); }
            u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
            total.checked_add(field.len()).ok_or(HistoryErrorV1::Extent)
        })
    }

    /// Encodes the exact recorded fields into a prepaid exact output slice.
    ///
    /// # Errors
    /// Rejects malformed input or a nonexact destination before writing bytes.
    pub fn encode_into(self, bytes: &mut [u8]) -> Result<(), HistoryErrorV1> {
        if bytes.len() != self.encoded_bytes()? { return Err(HistoryErrorV1::Extent); }
        let mut offset = 0;
        for field in [self.controller, self.sandbox, self.intake] {
            let count = u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
            bytes[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
            offset += 4;
            let end = offset + field.len();
            bytes[offset..end].copy_from_slice(field);
            offset = end;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_only_view_cannot_substitute_for_complete_history_validation() {
        let mut bytes = vec![0; FIXED_BYTES + 4 * FIELD_COUNT];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..FIXED_BYTES].fill(1);

        let view = ReadyBundleDataV1::borrow_field_framing_data_v1(&bytes).unwrap();

        assert!(view.intent_record.is_empty());
        assert!(ReadyBundleDataV1::decode(&bytes).is_err());
        assert!(ReadyBundleDataV1::borrow_field_framing_data_v1(&bytes[..bytes.len() - 1]).is_err());
        bytes[FIXED_BYTES..FIXED_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ReadyBundleDataV1::borrow_field_framing_data_v1(&bytes).is_err());
    }

    #[test]
    fn current_admission_borrows_each_exact_record_and_rejects_partial_fields() {
        let original = ControllerAdmissionDataV1 {
            controller: b"controller head", sandbox: b"sandbox head", intake: b"entered claim",
        };
        let mut bytes = vec![0; original.encoded_bytes().unwrap()];
        original.encode_into(&mut bytes).unwrap();
        let parsed = ControllerAdmissionDataV1::decode(&bytes).unwrap();
        assert_eq!(parsed.controller, original.controller);
        assert_eq!(parsed.sandbox, original.sandbox);
        assert_eq!(parsed.intake, original.intake);
        assert!(std::ptr::eq(parsed.controller.as_ptr(), bytes[4..].as_ptr()));
        for width in 0..bytes.len() {
            assert!(ControllerAdmissionDataV1::decode(&bytes[..width]).is_err());
        }
        let mut declared = bytes.clone();
        declared[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ControllerAdmissionDataV1::decode(&declared).is_err());
        assert!(ControllerAdmissionDataV1::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn intent_native_receipt_keeps_head_and_physical_coordinates_distinct() {
        let original = IntentNativeReceiptDataV1 {
            latest_head: [1; HEAD_BYTES],
            names: ProtectedJournalNamesV1::from_historical_fields((2, 3), (4, 5), (6, 7)),
            after_next: 8, after_end: 9,
        };
        let bytes = original.encode().unwrap();
        let parsed = IntentNativeReceiptDataV1::decode(&bytes).unwrap();
        assert_eq!(parsed.latest_head, original.latest_head);
        assert_eq!(parsed.names, original.names);
        assert_eq!(parsed.after_next, original.after_next);
        assert_eq!(parsed.after_end, original.after_end);
        assert_eq!(&bytes[HEAD_BYTES + 48..HEAD_BYTES + 56], &8_u64.to_be_bytes());
        assert_eq!(&bytes[HEAD_BYTES + 56..], &9_u64.to_be_bytes());
        for width in 0..bytes.len() {
            assert!(IntentNativeReceiptDataV1::decode(&bytes[..width]).is_err());
        }
        let mut zero_next = bytes;
        zero_next[HEAD_BYTES + 48..HEAD_BYTES + 56].fill(0);
        assert!(IntentNativeReceiptDataV1::decode(&zero_next).is_err());
    }

    #[test]
    fn announced_outer_extent_is_rejected_before_nested_decoding() {
        let mut prefix = vec![0; FIXED_BYTES + 4];
        prefix[..8].copy_from_slice(MAGIC);
        prefix[8..FIXED_BYTES].fill(1);
        prefix[FIXED_BYTES..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ReadyBundleDataV1::decode(&prefix).is_err());
        for width in 0..prefix.len() {
            assert!(ReadyBundleDataV1::decode(&prefix[..width]).is_err());
        }
    }
}
