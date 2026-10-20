//! Separates post-confirmation native proof from the later Source Journal17.
//!
//! Capture transfers snapshot, Control and anchor; its final confirmation then
//! transfers native-after. Source must validate those actual outputs before its
//! admin bridge, final semantic bytes and Journal17 exist. The cold archive
//! reader subsequently joins those later objects; no fake Journal breaks this
//! ordering and no output DATA can issue a live Capture or fresh-adoption right.

use super::*;
use crate::client::OriginalCompletedRestoredSettledCaptureData;
use crate::reference_packet::control::PacketNative5UnderlyingRecord;
use crate::reference_packet::service::{
    complete_restore::{
        PacketNativeRestoredRecord, settled_recapture::PacketRestoredSettledCaptureOutputLimits,
    },
    native_snapshot::PacketNativeRestoredSettled17SnapshotPlan,
};
use crucible_node_format::Validate;

/// Borrows the four actual SDK-transferred native objects without a Source Journal.
///
/// This framing plan is deliberately distinct from complete native graph
/// acceptance. Its defining reader must still check Endpoint, Connection, Boot,
/// current Control/model, immutable ancestry and the exact retained SDK pairs
/// before constructing [`ValidatedRestoredSettledNative17CaptureOutputs`].
pub struct RestoredSettledNative17CaptureOutputPlan<'a> {
    sdk: &'a OriginalCompletedRestoredSettledCaptureData<'a>,
    snapshot: PacketNativeRestoredSettled17SnapshotPlan<'a>,
    roles: [(&'a ContentRef, &'a [u8]); 4],
}

impl<'a> RestoredSettledNative17CaptureOutputPlan<'a> {
    /// Bounds exact transferred objects before any native graph reconstruction.
    ///
    /// The actual Controller-owned loan was obtained under the same Source SDK
    /// emitter/current frontier. The supplied output ceilings are independently
    /// admitted DATA; they neither replace that loan nor fund this Source decoder.
    ///
    /// # Errors
    /// Refuses incomplete receipts, missing or changed actual transferred objects,
    /// an independent output/capacity excess, changed embedded Control fullref or
    /// an invalid distinct snapshot17 frame. No Source Journal is consumed here.
    pub fn validate_data(
        sdk: &'a OriginalCompletedRestoredSettledCaptureData<'a>,
        limits: &PacketRestoredSettledCaptureOutputLimits,
    ) -> Result<Self, ProviderError> {
        limits.validate_data()?;
        let receipt = sdk.receipt_data();
        receipt.validate_data()?;
        let request = sdk.request_data();
        request.validate_data()?;
        if sdk.prefix_frontier_data()? != request.history_next_sequence
            || sdk.confirmation_request_data() != &receipt.capture
            || sdk.frontier_data() <= sdk.confirmation_pair_data().0.sequence
            || receipt.capture.capture_operation_id != request.capture_operation
        {
            return Err(invalid());
        }
        let references = [
            &receipt.capture.native_snapshot_ref,
            &receipt.capture.native_control_ref,
            &receipt.capture.native_anchor_ref,
            &receipt.native_after_ref,
        ];
        let maxima = [
            limits.native_snapshot_bytes,
            limits.current_control_bytes,
            limits.anchor_bytes,
            limits.native_after_bytes,
        ];
        let mut roles = [(references[0], &[][..]); 4];
        for (index, (reference, maximum)) in references.into_iter().zip(maxima).enumerate() {
            let bytes = sdk.transferred_object_data(reference)?;
            if bytes.is_empty()
                || u64::try_from(bytes.len()).map_err(|_| invalid())? > maximum.get()
            {
                return Err(invalid());
            }
            verify_role_body_data(reference, bytes)?;
            roles[index] = (reference, bytes);
        }
        if receipt.native_after_capacity.get() > limits.native_after_bytes.get() {
            return Err(invalid());
        }
        let snapshot = PacketNativeRestoredSettled17SnapshotPlan::validate(
            roles[0].1,
            usize::try_from(limits.native_snapshot_bytes.get()).map_err(|_| invalid())?,
            usize::try_from(limits.native_before_bytes.get()).map_err(|_| invalid())?,
        )?;
        // The embedded original is the actual proof-filled SDK assignment,
        // including its Source extension. A separately well-formed request with
        // equal arguments cannot replace this exact once-assigned envelope.
        let (capture_original, capture_terminal, _) = sdk.capture_pair_data();
        let (confirmation_original, confirmation_terminal, _) = sdk.confirmation_pair_data();
        capture_original.matches_response(capture_terminal)?;
        confirmation_original.matches_response(confirmation_terminal)?;
        if snapshot.capture_request_bytes() != sdk.canonical_original_data()
            || capture_original.request_id.0.as_ref() != Some(&receipt.capture.capture_request_id)
            || capture_original.operation_id.0.as_ref() != Some(&request.capture_operation)
            || capture_terminal.sequence != receipt.capture.capture_terminal_sequence
        {
            return Err(invalid());
        }
        verify_role_body_data(
            &receipt.capture.settled_capture_request,
            sdk.canonical_original_data(),
        )?;
        crate::protocol_snapshot::owned11::correspondence::envelope(
            capture_original,
            snapshot.capture_request_bytes(),
        )?;
        restored_settled_native17_reference_matches_data(
            roles[1].0,
            snapshot.control_reference_bytes(),
        )?;
        if snapshot.control_bytes() != roles[1].1 {
            return Err(invalid());
        }
        Ok(Self {
            sdk,
            snapshot,
            roles,
        })
    }

    /// Installs caller-owned partial custody before copying or decoding outputs.
    ///
    /// The Source independently admits the actual defining output-validation
    /// row before this call. Its inline `Option<DecodeAttempt>` belongs to the
    /// Source owner; this row covers separate retained backing and parser work.
    /// Completed raw/typed children remain in that once-slot on every error.
    /// This phase only retains the four real outputs: it does not
    /// construct a validated graph or invent the later semantic/Journal object.
    ///
    /// # Errors
    /// Refuses a used destination, zero/short admitted output backing, allocation
    /// refusal, invalid framing or actual retained demand outside that same row.
    pub fn retain_decode_attempt_into(
        &self,
        destination: &mut Option<super::sealed::RestoredSettledNative17DecodeAttempt>,
        row: &crate::reference_packet::service::native_startup::PacketRestoredSettledNativeOutputValidationStorageData,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(invalid());
        }
        // Install the empty once-attempt before any body/reference clone,
        // reservation, parse or later correspondence can fail.
        *destination = Some(super::sealed::RestoredSettledNative17DecodeAttempt::new());
        let partial = destination.as_mut().ok_or_else(invalid)?;
        partial.stage = super::sealed::DecodeStage::Failed;
        let maximum = row.retained_requested_bytes_data();
        let limits = row.output_limits_data();
        limits.validate_data()?;
        for ((_, raw), limit) in self.roles.iter().zip([
            limits.native_snapshot_bytes,
            limits.current_control_bytes,
            limits.anchor_bytes,
            limits.native_after_bytes,
        ]) {
            if u64::try_from(raw.len()).map_err(|_| invalid())? > limit.get() {
                return Err(invalid());
            }
        }
        if u64::try_from(self.snapshot.before().original_capacity()).map_err(|_| invalid())?
            > limits.native_before_bytes.get()
        {
            return Err(invalid());
        }
        let total = self
            .roles
            .iter()
            .try_fold(0usize, |sum, (_, raw)| sum.checked_add(raw.len()))
            .ok_or_else(invalid)?;
        if total == 0 || total > maximum {
            return Err(invalid());
        }
        // Retain in the common sealed-role order. Role4 remains genuinely absent
        // until the later cold reader receives the final Source Journal17.
        for (source, target) in [(0usize, 0usize), (1, 2), (2, 3), (3, 1)] {
            let (reference, bytes) = self.roles[source];
            partial.retain_reference_data(target, reference, maximum)?;
            let retained = partial.retained_requested_storage_data(maximum)?;
            if retained.checked_add(bytes.len()).ok_or_else(invalid)? > maximum {
                return Err(invalid());
            }
            partial.raw[target]
                .try_reserve_exact(bytes.len())
                .map_err(|_| invalid())?;
            partial.raw[target].extend_from_slice(bytes);
            partial.retained_requested_storage_data(maximum)?;
        }
        // The compact before leaf is a fifth independent allocation, not an
        // ephemeral buffer discarded before its strict graph reader completes.
        // Its original spare capacity is part of the output-validation row.
        let before_capacity = self.snapshot.before().original_capacity();
        let retained = partial.retained_requested_storage_data(maximum)?;
        if retained.checked_add(before_capacity).ok_or_else(invalid)? > maximum {
            return Err(invalid());
        }
        partial
            .before_encoded
            .try_reserve_exact(before_capacity)
            .map_err(|_| invalid())?;
        partial.retained_requested_storage_data(maximum)?;
        self.snapshot
            .before()
            .fill_preowned(&mut partial.before_encoded)?;
        partial.retained_requested_storage_data(maximum)?;
        // The complete typed graph readers consume these retained raw banks
        // directly. Creating an otherwise unused DOM here would duplicate the
        // graph and lose internally decoded partials on a parse error.
        partial.stage = super::sealed::DecodeStage::Framed;
        Ok(())
    }

    /// Checks both actual native cuts and moves only their completed proof owner.
    ///
    /// The Source admits this independent row before the Capture operation. Raw
    /// banks and every partial typed child remain in `attempt` on refusal. The
    /// actual SDK loan supplies both completed pairs and all four transferred
    /// objects; neither a final Source Journal nor a live adoption is fabricated.
    ///
    /// # Errors
    /// Refuses reused destinations, invalid output framing, insufficient actual
    /// backing or target credit, a changed native model or lineage, invalid
    /// Capture proof/anchor, or mismatch with the genuine SDK completion.
    pub fn validate_retained_outputs_into(
        &self,
        attempt: &mut Option<super::sealed::RestoredSettledNative17DecodeAttempt>,
        output: &mut Option<ValidatedRestoredSettledNative17CaptureOutputs>,
        row: &crate::reference_packet::service::native_startup::PacketRestoredSettledNativeOutputValidationStorageData,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || output.is_some() {
            return Err(invalid());
        }

        self.retain_decode_attempt_into(attempt, row)?;
        let partial = attempt.as_mut().ok_or_else(invalid)?;
        partial.stage = super::sealed::DecodeStage::Failed;
        let maximum_nodes = partial
            .before_encoded
            .len()
            .max(partial.raw[1].len())
            .max(1);
        super::reader::read_graph_pair_into_data(
            partial,
            row.retained_requested_bytes_data(),
            row.maximum_typed_graph_requested_bytes_data(),
            maximum_nodes,
        )?;
        let (before, after) = super::reader::completed_graph_pair_data(partial)?;
        let (capture_original, capture_terminal, _) = self.sdk.capture_pair_data();
        let (confirmation_original, _, _) = self.sdk.confirmation_pair_data();
        super::output_pair::authenticate_output_pair17_data(
            before,
            after,
            super::output_pair::OutputPairSdk17Data {
                capture_original,
                capture_terminal,
                confirmation_original,
                request: self.sdk.request_data(),
                confirmation_request: self.sdk.confirmation_request_data(),
                receipt: self.sdk.receipt_data(),
            },
            &self.snapshot,
            self.roles[2].1,
            usize::try_from(row.output_limits_data().current_control_bytes.get())
                .map_err(|_| invalid())?,
            before
                .maximum_frame_bytes_data()?
                .min(after.maximum_frame_bytes_data()?),
        )?;

        partial.retained_requested_storage_data(row.retained_requested_bytes_data())?;
        partial.stage = super::sealed::DecodeStage::Validated;
        let complete = attempt.take().ok_or_else(invalid)?;
        *output = Some(ValidatedRestoredSettledNative17CaptureOutputs { decoded: complete });
        Ok(())
    }

    /// Borrows exact snapshot, Control, anchor and final native-after role order.
    pub const fn roles_data(&self) -> [(&'a ContentRef, &'a [u8]); 4] {
        self.roles
    }

    /// Borrows the distinct framed snapshot and its authenticated embedded before.
    pub const fn snapshot_data(&self) -> &PacketNativeRestoredSettled17SnapshotPlan<'a> {
        &self.snapshot
    }

    /// Borrows the real Controller-owned completed pair and fourth receipt.
    pub const fn completed_sdk_data(&self) -> &OriginalCompletedRestoredSettledCaptureData<'a> {
        self.sdk
    }
}

/// Owns a complete checked native post-confirmation graph before Source Journal17.
///
/// Only the defining native graph reader constructs this owner after retaining
/// raw/typed partials and proving all same-graph and SDK-output correspondences.
/// It supplies no current Source witness, publication status or live adoption.
pub struct ValidatedRestoredSettledNative17CaptureOutputs {
    pub(super) decoded: super::sealed::RestoredSettledNative17DecodeAttempt,
}

impl ValidatedRestoredSettledNative17CaptureOutputs {
    /// Borrows the exact retained native-before protocol body.
    ///
    /// The complete output reader independently retained these bytes from the
    /// original Snapshot17 before leaf. This loan neither reparses that graph
    /// nor substitutes the native-after body or grants a fresh native owner.
    ///
    /// # Errors
    /// Refuses an incomplete output owner or an absent native-before body.
    pub fn before_protocol_bytes_data(&self) -> Result<&[u8], ProviderError> {
        self.ensure_validated()?;
        if self.decoded.before_encoded.is_empty() {
            return Err(invalid());
        }
        Ok(&self.decoded.before_encoded)
    }

    /// Borrows the exact fourth `receipt.native_after_ref` full reference.
    ///
    /// # Errors
    /// Refuses an incomplete native output owner; no earlier before bank or
    /// Source Journal reference is substituted for this current output identity.
    pub fn body_reference(&self) -> Result<&ContentRef, ProviderError> {
        self.ensure_validated()?;
        self.decoded.references[1].as_ref().ok_or_else(invalid)
    }

    /// Compares the pre-Capture checkpoint with the same complete current model.
    ///
    /// Source separately authenticates its actual completed SDK loan and keyed
    /// current SourceRead fence before issuing the admin bridge. It independently
    /// admits two bounded proof DOM/canonical rechecks; native-process reserve
    /// cannot pay for this second process's retained or transient owners.
    ///
    /// # Errors
    /// Refuses changed proof refs, immutable lineage, owner/World, grant or full
    /// current inventory/cursor, using the same defining cold proof predicate.
    pub fn authenticate_current_checkpoint_data(
        &self,
        restored: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.ensure_validated()?;
        super::sealed::authenticate_current_checkpoint_data(
            &self.decoded,
            restored,
            underlying,
            measurement,
        )
    }

    /// Counts retained independent Source decoding backing, excluding inline root.
    ///
    /// # Errors
    /// Refuses an incomplete graph, invalid layout arithmetic or backing above
    /// the independently admitted Source output-validation maximum.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        self.ensure_validated()?;
        self.decoded.retained_requested_storage_data(maximum)
    }

    fn ensure_validated(&self) -> Result<(), ProviderError> {
        if !self.decoded.is_validated_data() {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<RestoredSettledNative17CaptureOutputPlan<'static>>()
        +size_of::<ValidatedRestoredSettledNative17CaptureOutputs>()
        +size_of::<Result<RestoredSettledNative17CaptureOutputPlan<'static>,ProviderError>>()
        +size_of::<&OriginalCompletedRestoredSettledCaptureData<'static>>()
        +size_of::<&PacketRestoredSettledCaptureOutputLimits>()
        +size_of::<[(&ContentRef,&[u8]);4]>()
        +size_of::<[&ContentRef;4]>()
        +size_of::<[crucible_node_format::U64;4]>()
        +size_of::<std::array::IntoIter<&'static ContentRef,4>>()
        +size_of::<std::array::IntoIter<crucible_node_format::U64,4>>()
        +size_of::<std::iter::Enumerate<std::iter::Zip<std::array::IntoIter<&'static ContentRef,4>,std::array::IntoIter<crucible_node_format::U64,4>>>>()
        +size_of::<Option<(usize,(&ContentRef,crucible_node_format::U64))>>()
        +size_of::<Result<&[u8],ProviderError>>()
        +size_of::<Result<usize,std::num::TryFromIntError>>()
        +size_of::<Result<u64,std::num::TryFromIntError>>()
        +size_of::<Result<(),ProviderError>>()
        +size_of::<&mut Option<super::sealed::RestoredSettledNative17DecodeAttempt>>()
        +size_of::<&crate::reference_packet::service::native_startup::PacketRestoredSettledNativeOutputValidationStorageData>()
        +size_of::<Result<(),std::collections::TryReserveError>>()
        +size_of::<[(&ContentRef,&[u8]);4]>()
        +size_of::<std::slice::Iter<'static,(&'static ContentRef,&'static [u8])>>()
        +size_of::<std::iter::Zip<std::slice::Iter<'static,(&'static ContentRef,&'static [u8])>,std::array::IntoIter<crucible_node_format::U64,4>>>()
        +size_of::<Option<(&'static (&'static ContentRef,&'static [u8]),crucible_node_format::U64)>>()
        +size_of::<[(usize,usize);4]>()
        +size_of::<std::array::IntoIter<(usize,usize),4>>()
        +size_of::<[usize;4]>()
        +size_of::<std::array::IntoIter<usize,4>>()
}

#[cfg(test)]
mod before_protocol_loan_tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn empty_incomplete_owner_cannot_lend_before_protocol() {
        let output = ValidatedRestoredSettledNative17CaptureOutputs {
            decoded: super::super::sealed::RestoredSettledNative17DecodeAttempt::new(),
        };
        let retained = output
            .decoded
            .retained_requested_storage_data(usize::MAX)
            .unwrap();

        assert!(output.before_protocol_bytes_data().is_err());
        assert!(output.decoded.before_encoded.is_empty());
        assert_eq!(output.decoded.before_encoded.capacity(), 0);
        assert_eq!(
            output
                .decoded
                .retained_requested_storage_data(usize::MAX)
                .unwrap(),
            retained
        );
    }

    #[test]
    fn reference_copy_refusal_preserves_partial_owner_when_before_loan_refuses() {
        let mut decoded = super::super::sealed::RestoredSettledNative17DecodeAttempt::new();
        let reference =
            canonical::content_ref(b"retained native prefix", "application/json").unwrap();
        assert!(decoded.retain_reference_data(0, &reference, 64).is_err());
        let output = ValidatedRestoredSettledNative17CaptureOutputs { decoded };
        let retained = output
            .decoded
            .retained_requested_storage_data(usize::MAX)
            .unwrap();
        let initialized = output.decoded.references[0].as_ref().unwrap();
        assert_eq!(initialized.hash.algorithm, reference.hash.algorithm);
        assert!(retained > 0);

        assert!(output.before_protocol_bytes_data().is_err());
        assert_eq!(
            output.decoded.references[0]
                .as_ref()
                .unwrap()
                .hash
                .algorithm,
            reference.hash.algorithm
        );
        assert_eq!(
            output
                .decoded
                .retained_requested_storage_data(usize::MAX)
                .unwrap(),
            retained
        );
    }
}
