//! Joins five actual archive roles to the completed Controller Capture history.
//!
//! This borrowed phase checks only framing and exact historical correspondence.
//! The independently admitted narrow native graph decoder must still establish
//! modeled state, signed lineage and the safe point before sealing any owner.

use super::*;
use crate::protocol_snapshot::{
    current_controller17::ValidatedHistoricalRestoredSettledCapture17,
    owned11::{OriginalOwned11Fields as Fields, original_owned11_plain_string as plain},
    restored_journal17::PacketRestoredSettledJournal17Plan,
};
use crate::reference_packet::service::native_snapshot::PacketNativeRestoredSettled17SnapshotPlan;

/// Borrows exactly framed native roles and their final Source Journal17.
///
/// The plan cannot authorize native adoption or report semantic completion.
/// Its inputs remain the caller's immutable verified archive bodies.
pub struct RestoredSettledNative17Plan<'a> {
    roles: [(&'a ContentRef, &'a [u8]); 5],
    snapshot: PacketNativeRestoredSettled17SnapshotPlan<'a>,
    journal: PacketRestoredSettledJournal17Plan<'a>,
    maximum_requested: usize,
    limits: RestoredSettledNative17Limits,
}

impl<'a> RestoredSettledNative17Plan<'a> {
    /// Checks exact role fullrefs, snapshot framing and the final journal map.
    ///
    /// This phase performs no owning parse or immutable-object traversal. The
    /// full native/Source/Controller conjunction remains required for sealing.
    ///
    /// # Errors
    /// Refuses changed or oversized input, another snapshot/journal family,
    /// missing or additional journal roles, or unequal embedded native bodies.
    pub fn validate_data(
        input: &RestoredSettledNative17Input<'a>,
        limits: &RestoredSettledNative17Limits,
    ) -> Result<Self, ProviderError> {
        Self::validate_with_optional_admission_data(input, limits, None)
    }

    /// Checks exact cold role framing under an independently observed fixed workspace.
    ///
    /// # Errors
    /// Refuses the same framing failures as [`Self::validate_data`] or admission refusal.
    pub fn validate_with_admission_data(
        input: &RestoredSettledNative17Input<'a>,
        limits: &RestoredSettledNative17Limits,
        admission: &dyn NativeCold17Admission,
    ) -> Result<Self, ProviderError> {
        Self::validate_with_optional_admission_data(input, limits, Some(admission))
    }

    fn validate_with_optional_admission_data(
        input: &RestoredSettledNative17Input<'a>,
        limits: &RestoredSettledNative17Limits,
        admission: Option<&dyn NativeCold17Admission>,
    ) -> Result<Self, ProviderError> {
        let boundary = admission.map(super::cold_admission::NativeCold17Boundary::new);
        if let Some(boundary) = &boundary {
            let scratch = super::restored_settled_native17_counter_scratch_data();
            boundary.begin_data(NativeCold17Work::Framing, 0, scratch)?;
            boundary.construct_data(NativeCold17Work::Framing, 0, 0, scratch)?;
        }
        input.authenticate_role_bytes_data(limits)?;

        let snapshot = PacketNativeRestoredSettled17SnapshotPlan::validate(
            input.snapshot.1,
            limits.input_roles[0],
            limits.maximum_requested_bytes,
        )?;
        let journal =
            PacketRestoredSettledJournal17Plan::validate(input.journal.1, limits.input_roles[4])?;
        if snapshot.control_bytes() != input.control.1 {
            return Err(invalid());
        }
        restored_settled_native17_reference_matches_data(
            input.control.0,
            snapshot.control_reference_bytes(),
        )?;

        let mut objects = Fields::object(journal.objects_bytes())?;
        let after = objects.named("after")?;
        let anchor = objects.named("anchor")?;
        let before = objects.named("before")?;
        let control = objects.named("control")?;
        let _coordinator_checkpoint = objects.named("coordinator_checkpoint")?;
        let _host_protocol = objects.named("host_protocol")?;
        let _runtime_object = objects.named("runtime_object")?;
        let _semantic = objects.named("semantic")?;
        let snapshot_reference = objects.named("snapshot")?;
        objects.finish()?;

        for (reference, encoded) in [
            (input.snapshot.0, snapshot_reference),
            (input.current_protocol.0, after),
            (input.control.0, control),
            (input.anchor.0, anchor),
        ] {
            restored_settled_native17_reference_matches_data(reference, encoded)?;
        }
        // Both encodings come from closed canonical field walkers. Compare the
        // complete reference, including its domain/media, rather than a digest.
        if before != snapshot.before().reference_bytes() {
            return Err(invalid());
        }
        let result = Self {
            roles: input.roles_data(),
            snapshot,
            journal,
            maximum_requested: limits.maximum_requested_bytes,
            limits: *limits,
        };
        if let Some(boundary) = &boundary {
            boundary.finish_data(NativeCold17Work::Framing, 0)?;
        }
        Ok(result)
    }

    /// Joins final journal literals to the genuinely completed SDK pair owner.
    ///
    /// The historical SDK loan has already authenticated its actual Controller
    /// journals and both auxiliary uploads. Native cached receipts and signed
    /// lineage are independently checked by the complete native decoder.
    ///
    /// # Errors
    /// Refuses changed assigned envelopes, original/terminal correlation,
    /// prefix frontier, or any of the four actual transferred native fullrefs.
    pub fn authenticate_completed_sdk_data(
        &self,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
    ) -> Result<(), ProviderError> {
        let (capture_original, capture_terminal, _) = sdk.capture_pair_data();
        let (confirmation_original, confirmation_terminal, _) = sdk.confirmation_pair_data();
        let capture = self.journal.capture_bytes();
        let confirmation = self.journal.confirmation_bytes();
        for (original, literal) in [
            (capture_original, capture.0),
            (capture_terminal, capture.1),
            (confirmation_original, confirmation.0),
            (confirmation_terminal, confirmation.1),
            (capture_original, self.snapshot.capture_request_bytes()),
        ] {
            super::super::owned11::correspondence::envelope(original, literal)?;
        }
        capture_original.matches_response(capture_terminal)?;
        confirmation_original.matches_response(confirmation_terminal)?;
        if self.snapshot.capture_request_bytes() != sdk.canonical_original_data() {
            return Err(invalid());
        }

        let mut objects = Fields::object(self.journal.objects_bytes())?;
        objects.named("after")?;
        objects.named("anchor")?;
        objects.named("before")?;
        objects.named("control")?;
        restored_settled_native17_reference_matches_data(
            &sdk.request_data().coordinator_checkpoint,
            objects.named("coordinator_checkpoint")?,
        )?;
        objects.named("host_protocol")?;
        restored_settled_native17_reference_matches_data(
            &sdk.request_data().runtime_object,
            objects.named("runtime_object")?,
        )?;
        objects.named("semantic")?;
        objects.named("snapshot")?;
        objects.finish()?;

        let request = sdk.request_data();
        let mut ancestry = Fields::object(self.journal.ancestry_bytes())?;
        restored_settled_native17_reference_matches_data(
            &request.scope.restoration.captured_journal,
            ancestry.named("first_journal")?,
        )?;
        restored_settled_native17_reference_matches_data(
            &request.first_observation,
            ancestry.named("first_observation")?,
        )?;
        ancestry.named("first_semantic")?;
        restored_settled_native17_reference_matches_data(
            &request.parent_archive,
            ancestry.named("parent_archive_index")?,
        )?;
        ancestry.named("parent_manifest")?;
        restored_settled_native17_reference_matches_data(
            &request.scope.restoration.commit_request,
            ancestry.named("restoration_commit")?,
        )?;
        ancestry.named("restoration_hold")?;
        ancestry.finish()?;

        let receipt = sdk.receipt_data();
        for (actual, expected) in [
            (self.roles[0].0, &receipt.capture.native_snapshot_ref),
            (self.roles[1].0, &receipt.native_after_ref),
            (self.roles[2].0, &receipt.capture.native_control_ref),
            (self.roles[3].0, &receipt.capture.native_anchor_ref),
        ] {
            if actual != expected {
                return Err(invalid());
            }
        }

        let mut cut = Fields::object(self.journal.history_cut_bytes())?;
        let frontier =
            super::super::owned11::typed::unsigned(plain(cut.named("next_sequence")?)?.as_bytes())?;
        restored_settled_native17_reference_matches_data(
            &sdk.request_data().history_prefix,
            cut.named("prefix")?,
        )?;
        cut.finish()?;
        if frontier != sdk.prefix_frontier_data().get()
            || frontier != sdk.request_data().history_next_sequence.get()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Validates native proof cuts and retains their sealed archive-side owner.
    ///
    /// The SDK loan and Controller are genuinely decoded historical owners.
    /// Source/Node authentication and signed reachable archive closure remain
    /// separate mandatory conjunctions of the enclosing cold group. This native
    /// result cannot create a fresh backend, transport or administrative claim.
    ///
    /// # Errors
    /// Refuses reused owners, malformed roles, changed actual SDK pairs, short
    /// independently admitted backing/target work, native proof/model/anchor
    /// disagreement or a Journal Hold reference outside the actual lineage.
    pub fn validate_retained_into(
        &self,
        attempt: &mut Option<RestoredSettledNative17DecodeAttempt>,
        sealed: &mut Option<SealedHistoricalRestoredSettledNative17>,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
    ) -> Result<(), ProviderError> {
        self.validate_retained_with_optional_admission_into(attempt, sealed, sdk, controller, None)
    }

    /// Validates cold native constructors under independent per-constructor admission.
    ///
    /// Completed graph/SDK/lineage semantics remain mandatory. Callback success
    /// cannot seal a malformed owner or replace the original historical guards.
    ///
    /// # Errors
    /// Refuses any ordinary native validation failure, stale admission or short
    /// independently supplied constructor credit, retaining initialized partials.
    pub fn validate_retained_with_admission_into(
        &self,
        attempt: &mut Option<RestoredSettledNative17DecodeAttempt>,
        sealed: &mut Option<SealedHistoricalRestoredSettledNative17>,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        admission: &dyn NativeCold17Admission,
    ) -> Result<(), ProviderError> {
        self.validate_retained_with_optional_admission_into(
            attempt,
            sealed,
            sdk,
            controller,
            Some(admission),
        )
    }

    fn validate_retained_with_optional_admission_into(
        &self,
        attempt: &mut Option<RestoredSettledNative17DecodeAttempt>,
        sealed: &mut Option<SealedHistoricalRestoredSettledNative17>,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        admission: Option<&dyn NativeCold17Admission>,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || sealed.is_some() {
            return Err(invalid());
        }
        let boundary = admission.map(super::cold_admission::NativeCold17Boundary::new);
        if let Some(boundary) = &boundary {
            let scratch = super::restored_settled_native17_counter_scratch_data();
            boundary.begin_data(NativeCold17Work::RawInputs, 20, scratch)?;
            let raw = self.raw_input_construction_bytes_data()?;
            let temporary = super::output_pair::construction::sdk_correspondence_data(
                sdk,
                controller,
                self.maximum_requested,
            )?;
            boundary.construct_data(NativeCold17Work::RawInputs, raw, temporary, scratch)?;
        }
        self.authenticate_completed_sdk_data(sdk)?;
        let (original, terminal, _) = sdk.capture_pair_data();
        controller.authenticate_historical_controller_pair17_data(original, terminal)?;
        let (original, terminal, _) = sdk.confirmation_pair_data();
        controller.authenticate_historical_controller_pair17_data(original, terminal)?;

        self.retain_decode_attempt_into(attempt)?;
        let partial = attempt.as_mut().ok_or_else(invalid)?;
        partial.stage = super::sealed::DecodeStage::Failed;
        if let Some(boundary) = &boundary {
            boundary.finish_data(
                NativeCold17Work::RawInputs,
                partial.retained_requested_storage_data(self.maximum_requested)?,
            )?;
        }
        super::reader::read_graph_pair_with_admission_into_data(
            partial,
            self.maximum_requested,
            self.maximum_requested,
            self.limits.maximum_nodes_data(),
            boundary.as_ref(),
        )?;
        if let Some(boundary) = &boundary {
            self.authenticate_outputs_with_admission_data(partial, sdk, boundary)?;
        } else {
            self.authenticate_native_outputs_data(partial, sdk)?;
        }

        partial.retained_requested_storage_data(self.maximum_requested)?;

        partial.stage = super::sealed::DecodeStage::Validated;
        let complete = attempt.take().ok_or_else(invalid)?;
        *sealed = Some(SealedHistoricalRestoredSettledNative17 { decoded: complete });
        Ok(())
    }

    fn raw_input_construction_bytes_data(&self) -> Result<usize, ProviderError> {
        let mut bytes = self.snapshot.before().original_capacity();
        for (reference, raw) in self.roles {
            for extent in [
                raw.len(),
                reference.hash.algorithm.len(),
                reference.hash.domain.len(),
                reference.hash.digest.len(),
                reference.media_type.len(),
            ] {
                bytes = bytes.checked_add(extent).ok_or_else(invalid)?;
            }
        }
        if bytes > self.maximum_requested {
            return Err(invalid());
        }
        Ok(bytes)
    }

    fn authenticate_outputs_with_admission_data(
        &self,
        decoded: &RestoredSettledNative17DecodeAttempt,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
        boundary: &super::cold_admission::NativeCold17Boundary<'_>,
    ) -> Result<(), ProviderError> {
        let scratch = super::restored_settled_native17_counter_scratch_data();
        boundary.begin_data(NativeCold17Work::OutputPairQuote, 0, scratch)?;
        let (before, after) = super::reader::completed_graph_pair_data(decoded)?;
        let (capture_original, capture_terminal, _) = sdk.capture_pair_data();
        let (confirmation_original, _, _) = sdk.confirmation_pair_data();
        let sdk = super::output_pair::OutputPairSdk17Data {
            capture_original,
            capture_terminal,
            confirmation_original,
            request: sdk.request_data(),
            confirmation_request: sdk.confirmation_request_data(),
            receipt: sdk.receipt_data(),
        };
        let formatter = super::output_pair::construction::formatter_data(before, &sdk)?;
        boundary.construct_data(NativeCold17Work::OutputPairQuote, 0, formatter, scratch)?;
        let temporary =
            super::output_pair::construction::quote_data(before, &sdk, self.maximum_requested)?;
        boundary.finish_data(
            NativeCold17Work::OutputPairQuote,
            decoded.retained_requested_storage_data(self.maximum_requested)?,
        )?;
        boundary.begin_data(NativeCold17Work::OutputPair, 0, scratch)?;
        boundary.construct_data(NativeCold17Work::OutputPair, 0, temporary, scratch)?;
        super::output_pair::authenticate_output_pair17_data(
            before,
            after,
            sdk,
            &self.snapshot,
            self.roles[3].1,
            self.limits.input_roles[2],
            before
                .maximum_frame_bytes_data()?
                .min(after.maximum_frame_bytes_data()?),
        )?;
        boundary.finish_data(
            NativeCold17Work::OutputPair,
            decoded.retained_requested_storage_data(self.maximum_requested)?,
        )?;

        boundary.begin_data(NativeCold17Work::RestorationHoldQuote, 0, scratch)?;
        let held = after.restoration_hold_data()?;
        let formatter = super::output_pair::construction::held_formatter_data(held)?;
        boundary.construct_data(
            NativeCold17Work::RestorationHoldQuote,
            0,
            formatter,
            scratch,
        )?;
        let temporary =
            super::output_pair::construction::held_quote_data(held, self.maximum_requested)?;
        boundary.finish_data(
            NativeCold17Work::RestorationHoldQuote,
            decoded.retained_requested_storage_data(self.maximum_requested)?,
        )?;
        boundary.begin_data(NativeCold17Work::RestorationHold, 0, scratch)?;
        boundary.construct_data(NativeCold17Work::RestorationHold, 0, temporary, scratch)?;
        self.authenticate_restoration_hold_data(decoded)?;
        boundary.finish_data(
            NativeCold17Work::RestorationHold,
            decoded.retained_requested_storage_data(self.maximum_requested)?,
        )
    }

    pub(super) fn authenticate_native_outputs_data(
        &self,
        decoded: &RestoredSettledNative17DecodeAttempt,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_pair_data(decoded, sdk)?;
        self.authenticate_restoration_hold_data(decoded)
    }

    fn authenticate_native_pair_data(
        &self,
        decoded: &RestoredSettledNative17DecodeAttempt,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
    ) -> Result<(), ProviderError> {
        let (before, after) = super::reader::completed_graph_pair_data(decoded)?;
        let (capture_original, capture_terminal, _) = sdk.capture_pair_data();
        let (confirmation_original, _, _) = sdk.confirmation_pair_data();
        super::output_pair::authenticate_output_pair17_data(
            before,
            after,
            super::output_pair::OutputPairSdk17Data {
                capture_original,
                capture_terminal,
                confirmation_original,
                request: sdk.request_data(),
                confirmation_request: sdk.confirmation_request_data(),
                receipt: sdk.receipt_data(),
            },
            &self.snapshot,
            self.roles[3].1,
            self.limits.input_roles[2],
            before
                .maximum_frame_bytes_data()?
                .min(after.maximum_frame_bytes_data()?),
        )?;
        Ok(())
    }

    fn authenticate_restoration_hold_data(
        &self,
        decoded: &RestoredSettledNative17DecodeAttempt,
    ) -> Result<(), ProviderError> {
        let (_, after) = super::reader::completed_graph_pair_data(decoded)?;
        let mut ancestry = Fields::object(self.journal.ancestry_bytes())?;
        for name in [
            "first_journal",
            "first_observation",
            "first_semantic",
            "parent_archive_index",
            "parent_manifest",
            "restoration_commit",
        ] {
            ancestry.named(name)?;
        }
        let held_reference = ancestry.named("restoration_hold")?;
        ancestry.finish()?;
        let held = after.restoration_hold_data()?;
        crate::connection::serialized_credit(held, 65_536)?;
        let held_value =
            serde_json::to_value(held).map_err(crucible_node_format::ContractError::from)?;
        let held_bytes = crucible_node_format::canonical::canonical_json(&held_value)?;
        if held_bytes.len() > 65_536 {
            return Err(invalid());
        }
        let reference =
            crucible_node_format::canonical::content_ref(&held_bytes, "application/json")?;
        restored_settled_native17_reference_matches_data(&reference, held_reference)
    }

    /// Installs the actual once-attempt before retaining any input allocation.
    ///
    /// A later reader preserves these banks and all initialized typed children
    /// on refusal. This method marks framing only and cannot seal an owner.
    ///
    /// # Errors
    /// Refuses reuse, an allocation failure, or actual retained backing above
    /// the independently admitted bound before or after a body reservation.
    pub fn retain_decode_attempt_into(
        &self,
        destination: &mut Option<RestoredSettledNative17DecodeAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(invalid());
        }

        *destination = Some(RestoredSettledNative17DecodeAttempt::new());
        let partial = destination.as_mut().ok_or_else(invalid)?;
        partial.stage = super::sealed::DecodeStage::Failed;
        partial.limits = Some(self.limits);
        for (index, (reference, bytes)) in self.roles.iter().enumerate() {
            partial.retain_reference_data(index, reference, self.maximum_requested)?;
            partial.retained_requested_storage_data(self.maximum_requested)?;
            let retained = partial.retained_requested_storage_data(self.maximum_requested)?;
            if retained.checked_add(bytes.len()).ok_or_else(invalid)? > self.maximum_requested {
                return Err(invalid());
            }
            partial.raw[index]
                .try_reserve_exact(bytes.len())
                .map_err(|_| invalid())?;
            partial.retained_requested_storage_data(self.maximum_requested)?;
            partial.raw[index].extend_from_slice(bytes);
        }
        let capacity = self.snapshot.before().original_capacity();
        let retained = partial.retained_requested_storage_data(self.maximum_requested)?;
        if retained.checked_add(capacity).ok_or_else(invalid)? > self.maximum_requested {
            return Err(invalid());
        }
        partial
            .before_encoded
            .try_reserve_exact(capacity)
            .map_err(|_| invalid())?;
        partial.retained_requested_storage_data(self.maximum_requested)?;
        self.snapshot
            .before()
            .fill_preowned(&mut partial.before_encoded)?;
        partial.stage = super::sealed::DecodeStage::Framed;
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;

    size_of::<RestoredSettledNative17Plan<'static>>()
        + size_of::<Result<RestoredSettledNative17Plan<'static>, ProviderError>>()
        + size_of::<PacketRestoredSettledJournal17Plan<'static>>()
        + size_of::<Result<PacketRestoredSettledJournal17Plan<'static>, ProviderError>>()
        + 4 * size_of::<Fields<'static>>()
        + size_of::<[(&ContentRef, &[u8]); 5]>()
        + size_of::<std::array::IntoIter<(&ContentRef, &[u8]), 5>>()
        + size_of::<[(&ContentRef, &ContentRef); 4]>()
        + size_of::<std::array::IntoIter<(&ContentRef, &ContentRef), 4>>()
        + size_of::<[(&crate::envelope::Envelope, &[u8]); 5]>()
        + size_of::<std::array::IntoIter<(&crate::envelope::Envelope, &[u8]), 5>>()
        + size_of::<
            std::iter::Enumerate<std::slice::Iter<'static, (&'static ContentRef, &'static [u8])>>,
        >()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), ProviderError>>()
        + 8 * size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use crucible_node_format::canonical;

    // These deliberately inert fixtures establish framing only. No native
    // decoder, signed Source history or live issuer accepts their empty DTOs.
    fn roles() -> [(ContentRef, Vec<u8>); 5] {
        let before = br#"{"framing":"before"}"#.to_vec();
        let before_ref = canonical::content_ref(&before, "application/json").unwrap();
        let control = br#"{"framing":"control"}"#.to_vec();
        let control_ref = canonical::content_ref(&control, "application/json").unwrap();
        let after = br#"{"framing":"after"}"#.to_vec();
        let after_ref = canonical::content_ref(&after, "application/json").unwrap();
        let anchor = br#"{"framing":"anchor"}"#.to_vec();
        let anchor_ref = canonical::content_ref(&anchor, "application/json").unwrap();
        let snapshot = canonical::canonical_json(&serde_json::json!({
            "capture": {},
            "capture_request": {},
            "control": serde_json::from_slice::<serde_json::Value>(&control).unwrap(),
            "control_reference": control_ref,
            "protocol": [
                "source-private.native-before-protocol/17", before_ref,
                before.capacity(), BorrowedCompactBytes::new(&before)
            ],
            "schema": "source-owned.packet-native-continuation/17"
        }))
        .unwrap();
        let snapshot_ref = canonical::content_ref(&snapshot, "application/json").unwrap();
        let journal = canonical::canonical_json(&serde_json::json!({
            "ancestry": {},
            "capture_request": {},
            "capture_terminal": {},
            "confirmation_request": {},
            "confirmation_terminal": {},
            "history_cut": {},
            "objects": {
                "snapshot": snapshot_ref,
                "before": before_ref,
                "control": control_ref,
                "anchor": anchor_ref,
                "after": after_ref,
                "host_protocol": after_ref,
                "semantic": after_ref,
                "runtime_object": after_ref,
                "coordinator_checkpoint": after_ref
            },
            "schema": "source-private.source-restored-settled-journal/17"
        }))
        .unwrap();
        let journal_ref = canonical::content_ref(&journal, "application/json").unwrap();
        [
            (snapshot_ref, snapshot),
            (after_ref, after),
            (control_ref, control),
            (anchor_ref, anchor),
            (journal_ref, journal),
        ]
    }

    fn input(roles: &[(ContentRef, Vec<u8>); 5]) -> RestoredSettledNative17Input<'_> {
        RestoredSettledNative17Input {
            snapshot: (&roles[0].0, &roles[0].1),
            current_protocol: (&roles[1].0, &roles[1].1),
            control: (&roles[2].0, &roles[2].1),
            anchor: (&roles[3].0, &roles[3].1),
            journal: (&roles[4].0, &roles[4].1),
        }
    }

    fn limits(roles: &[(ContentRef, Vec<u8>); 5]) -> RestoredSettledNative17Limits {
        RestoredSettledNative17Limits::new(
            std::array::from_fn(|index| roles[index].1.len()),
            1,
            1,
            1,
            4096,
            65_536,
        )
        .unwrap()
    }

    struct FramingAdmission {
        stop: usize,
        calls: std::cell::Cell<usize>,
    }

    impl NativeCold17Admission for FramingAdmission {
        fn begin_data(&self, row: NativeCold17PrewalkData) -> Result<(), ProviderError> {
            assert_eq!(row.work_data(), NativeCold17Work::Framing);
            assert_eq!(row.prior_native_cache_retained_bytes_data(), 0);
            self.step()
        }

        fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError> {
            assert_eq!(row.work_data(), NativeCold17Work::Framing);
            assert_eq!(row.maximum_new_retained_bytes_data(), 0);
            assert_eq!(row.constructor_transient_bytes_data(), 0);
            self.step()
        }

        fn finish_data(&self, work: NativeCold17Work, actual: usize) -> Result<(), ProviderError> {
            assert_eq!(work, NativeCold17Work::Framing);
            assert_eq!(actual, 0);
            self.step()
        }
    }

    impl FramingAdmission {
        fn step(&self) -> Result<(), ProviderError> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.stop {
                Err(invalid())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn real_framing_admission_refuses_each_boundary_without_skipping_the_guard() {
        let mut roles = roles();
        let limits = limits(&roles);
        for stop in 1..=4 {
            let admission = FramingAdmission {
                stop,
                calls: std::cell::Cell::new(0),
            };
            let result = RestoredSettledNative17Plan::validate_with_admission_data(
                &input(&roles),
                &limits,
                &admission,
            );
            assert_eq!(result.is_ok(), stop == 4);
            assert_eq!(admission.calls.get(), stop.min(3));
        }
        roles[1].1[1] ^= 1;
        let admission = FramingAdmission {
            stop: 4,
            calls: std::cell::Cell::new(0),
        };
        assert!(
            RestoredSettledNative17Plan::validate_with_admission_data(
                &input(&roles),
                &limits,
                &admission
            )
            .is_err()
        );
        assert_eq!(admission.calls.get(), 2);
    }

    #[test]
    fn role_hash_authentication_precedes_any_retained_allocation() {
        let mut roles = roles();
        let bounds = limits(&roles);
        RestoredSettledNative17Plan::validate_data(&input(&roles), &bounds).unwrap();
        roles[1].1[1] ^= 1;

        assert!(RestoredSettledNative17Plan::validate_data(&input(&roles), &bounds).is_err());
    }

    #[test]
    fn rehashed_journal_cannot_substitute_another_before_reference() {
        let mut roles = roles();
        let mut journal: serde_json::Value = serde_json::from_slice(&roles[4].1).unwrap();
        journal["objects"]["before"] = serde_json::to_value(&roles[1].0).unwrap();
        roles[4].1 = canonical::canonical_json(&journal).unwrap();
        roles[4].0 = canonical::content_ref(&roles[4].1, "application/json").unwrap();

        assert!(
            RestoredSettledNative17Plan::validate_data(&input(&roles), &limits(&roles)).is_err()
        );
    }

    #[test]
    fn extra_journal_object_role_is_refused_after_valid_hashing() {
        let mut roles = roles();
        let mut journal: serde_json::Value = serde_json::from_slice(&roles[4].1).unwrap();
        journal["objects"]["unknown"] = serde_json::to_value(&roles[1].0).unwrap();
        roles[4].1 = canonical::canonical_json(&journal).unwrap();
        roles[4].0 = canonical::content_ref(&roles[4].1, "application/json").unwrap();

        assert!(
            RestoredSettledNative17Plan::validate_data(&input(&roles), &limits(&roles)).is_err()
        );
    }
}
