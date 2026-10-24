//! Borrows modeled Source17 state inside the real Capture owner's safe point.
//!
//! ```text
//! semantic = {schema,ancestry,node,source}
//! source = {schema,installation,world,once,limits,first_observation,producer,
//!           current_observations,input_history,capture,inherited}
//! ```
//!
//! A private preencoder cut emits Preparing only during its synchronous callback.
//! Final output independently borrows the genuinely completed Capture ledger.
//! Live SourceRead, supervisor, World/native currency and whole-row admission
//! remain the owning caller's guards; none is reconstructed from these bytes.

use super::super::super::*;
use super::{
    source_fields::{OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17},
    source_reader::OriginalSourceRestoredSettled17Read,
};
use crate::{
    node_adapters::cnp::semantic::node::OriginalRestoredSettledNodeHistoryView,
    node_admission::OriginalRestoredCaptureClaim,
    node_contract::{
        WorldActivation, restored_owner_history::OriginalRestoredOwnerCapacityAliases,
    },
};
use crucible_node_transport::{
    client::{CnpController, OriginalCanonicalBlobAckEmitter},
    protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
    retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{cell::RefCell, mem::size_of};

/// Borrows real current participants and immutable imported evidence.
///
/// The owning Window supplies ancestry from the authenticated imported archive
/// and retains the actual prior opaque Source read with its independent Node
/// body. These DATA references never issue a claim or renew an original bound.
///
/// Every semantic pass must begin with the same admitted alias traversal state,
/// with Node first and no preceding roster traversal. The actual output owner
/// must retain identical canonical Node bytes for its standalone Node object;
/// an independent second serialization is not an authenticated reference.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalSourceRestoredSettled17WriteInputs<
    'a,
    'claim,
> {
    pub(crate) source: &'a PacketCompleteSemanticSource,
    pub(crate) controller: &'a CnpController,
    pub(crate) emitter: &'a OriginalCanonicalBlobAckEmitter,
    pub(crate) world: &'a WorldActivation,
    pub(crate) claim: &'a OriginalRestoredCaptureClaim<'claim>,
    pub(crate) launch: &'a PacketNative5SourceLaunch,
    pub(crate) canonical_launch5: &'a [u8],
    pub(crate) key: &'a [u8; 32],
    pub(crate) node: &'a OriginalRestoredSettledNodeHistoryView<'a>,
    /// Borrows ancestry from the actual authenticated imported archive roles.
    /// Syntax and three first-checkpoint joins below do not issue provenance.
    pub(crate) ancestry: &'a PacketRestoredSettledAncestry17,
    pub(crate) inherited: Option<&'a OriginalSourceRestoredSettled17Read>,
    pub(crate) aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    pub(crate) records: &'a RefCell<MetadataRecordBank>,
    pub(crate) provider_aliases: &'a RefCell<MetadataAliasBank>,
}

/// Borrows a complete semantic root while its actual live owners stay retained.
///
/// No public constructor, deserializer, clone or conversion into live ownership
/// exists. The final branch requires a real Complete ledger on every pass.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalSourceRestoredSettledSemantic17View<
    'a,
    'claim,
    'cut,
> {
    input: &'a OriginalSourceRestoredSettled17WriteInputs<'a, 'claim>,
    cut: Option<&'a super::super::owner::CapturePreEncoderCut<'cut>>,
}

impl PacketCompleteSemanticSource {
    /// Borrows final semantic state after actual Capture confirmation completes.
    ///
    /// # Errors
    /// Refuses another Source/claim/World, unready launch or boot, old16/Input
    /// activity, partial Producer history, renewed original bounds, a different
    /// inherited Node edge, or an incomplete/stale actual Capture bridge.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_completed_semantic17_data<
        'a,
        'claim,
    >(
        &'a self,
        input: &'a OriginalSourceRestoredSettled17WriteInputs<'a, 'claim>,
    ) -> Result<OriginalSourceRestoredSettledSemantic17View<'a, 'claim, 'a>, RuntimeError> {
        if !std::ptr::eq(self, input.source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let view = OriginalSourceRestoredSettledSemantic17View { input, cut: None };
        view.authenticate_data()?;
        Ok(view)
    }
}

impl super::super::owner::CaptureOnceOwner {
    /// Encodes the full semantic17 prefix inside this owner's real Preparing cut.
    ///
    /// The caller has admitted the complete live census, defining serialization
    /// views and prefix/DOM/canonical output row. It retains the same SourceRead,
    /// supervisor and current Window/World/native guards across this callback.
    /// Every failed partial remains owned by this same once-spent Capture.
    ///
    /// # Errors
    /// Refuses a repeated attempt, foreign claim/participants, unsupported active
    /// families, a changed original bound/frontier or failed bounded encoding.
    ///
    /// # Panics
    /// An unwinding serializer leaves the real Capture phase spent at Preparing.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn prepare_source_semantic17_prefix_data(
        &mut self,
        input: &OriginalSourceRestoredSettled17WriteInputs<'_, '_>,
        maximum_checkpoint: usize,
        maximum_prefix: usize,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.prepare_prefix_with_data(
            input.source,
            input.controller,
            input.emitter,
            input.claim,
            maximum_checkpoint,
            maximum_prefix,
            recheck_read,
            |cut, encoder| {
                let history = OriginalSourceRestoredSettledSemantic17View {
                    input,
                    cut: Some(cut),
                };
                history.authenticate_data()?;
                encoder.encode_data(&history)?;
                history.authenticate_data()
            },
        )
    }
}

impl OriginalSourceRestoredSettledSemantic17View<'_, '_, '_> {
    fn authenticate_data(&self) -> Result<(), RuntimeError> {
        let input = self.input;
        input.source.storage_origin_with_error::<RuntimeError>()?;
        // Signed17 Observe and Input histories have no archived native proof
        // conjunction yet. Used owners must refuse rather than disappear.
        input
            .source
            .authenticate_unused_signed_observation17_owner_data()?;
        input.source.authenticate_unused_input17_owner_data()?;
        input
            .claim
            .authenticate_current_data(input.source, input.controller as *const _)?;
        if !input.claim.world_data().same_authority(input.world) {
            return Err(RuntimeError::ForeignAuthority);
        }
        input
            .source
            .authenticate_original_restored_settled_source17_launch_data(
                input.launch,
                input.canonical_launch5,
            )?;
        input
            .ancestry
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let association = input
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(emitter, input.emitter) {
            return Err(RuntimeError::ForeignAuthority);
        }
        emitter
            .authenticate_original(input.controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let producer = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let current = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        current.require_unused_logical17_data()?;
        let limits = self.limits_data(&producer)?;
        input.node.authenticate_source17_projection_data(
            input.source,
            input.claim,
            input.world,
            input
                .inherited
                .map(OriginalSourceRestoredSettled17Read::node_reference_data),
            producer.attempts.len(),
        )?;
        if let CompletePacketOriginal::Reactive(source) = &input.source.original {
            source.require_unused_restored_source17_input_data()?;
            if !producer.attempts.is_empty() {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        let first = original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let _ = first.borrowed_logical17_data(input.source, input.controller)?;
        let (record, _, measurement) = first.original_capture_checkpoint_data()?;
        if input.ancestry.first_observation != *measurement
            || input.ancestry.first_journal != record.captured_journal
            || input.ancestry.restoration_commit != record.restore_commit
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let header = input.source.borrowed_settled17_header_data(input.aliases)?;
        let _ = original.borrowed_completed_once17_data(
            input.source,
            input.controller,
            input.key,
            header,
        )?;
        match self.cut {
            Some(cut) => cut.authenticate_owner_data(
                input.source,
                original.restored_capture.as_ptr().cast(),
                input.controller,
            )?,
            None => {
                let capture = original
                    .restored_capture
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                capture.current_bridge_data()?;
                let _ = capture.borrowed_housekeeping_ledger_data(
                    input.source,
                    input.controller,
                    emitter,
                    input.world,
                    input.key,
                )?;
            }
        }
        if limits.current_observations_used != 0 || limits.input_used != 0 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        input
            .claim
            .authenticate_current_data(input.source, input.controller as *const _)?;
        Ok(())
    }

    fn limits_data(
        &self,
        producer: &ProducerProgressHistory,
    ) -> Result<OriginalSourceRestoredLimits17, RuntimeError> {
        producer.origin_data()?;
        if producer.failed
            || producer
                .attempts
                .iter()
                .any(|attempt| attempt.stage.get() != Stage::Verified)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        for attempt in &producer.attempts {
            if attempt.signature != Some(proof::signature_data(attempt, self.input.key)?) {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        let installation = self.input.source.installation();
        let inherited_used = match self.input.inherited {
            None => 0,
            Some(prior) => {
                if prior.original_generic_limits_data()
                    != (
                        installation.maximum_operations,
                        installation.maximum_semantic_bytes,
                        installation.maximum_result_bytes,
                        installation.maximum_authorization_bytes,
                    )
                    || prior.logical_limits_data().current_observations_used != 0
                    || prior.logical_limits_data().input_used != 0
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                prior.logical_limits_data().producer_used
            }
        };
        let producer_used = cumulative_producer_use_data(
            inherited_used,
            producer.attempts.len(),
            installation.maximum_operations,
        )?;
        // This is THIS incarnation's actual Boot reservation. It does not reset
        // lifetime Producer use and need not equal an ancestor's Boot capacity.
        let maximum_originals = self
            .input
            .source
            .original_restored_settled_source17_boot_original_limit_data()?;
        Ok(OriginalSourceRestoredLimits17 {
            maximum_operations: installation.maximum_operations,
            maximum_originals,
            producer_used,
            current_observations_used: 0,
            input_used: 0,
        })
    }
}

struct SourceRoot17<'view, 'input, 'claim, 'cut>(
    &'view OriginalSourceRestoredSettledSemantic17View<'input, 'claim, 'cut>,
);

impl Serialize for OriginalSourceRestoredSettledSemantic17View<'_, '_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.authenticate_data().map_err(S::Error::custom)?;
        let input = self.input;
        let node = (*input.node)
            .with_aliases(input.aliases)
            .with_metadata_banks(input.records, input.provider_aliases);
        let mut root = serializer.serialize_struct("RestoredSettledSemantic17", 4)?;
        root.serialize_field(
            "schema",
            "source-private.semantic-state-restored-settled/17",
        )?;
        root.serialize_field("ancestry", input.ancestry)?;
        root.serialize_field("node", &node)?;
        root.serialize_field("source", &SourceRoot17(self))?;
        self.authenticate_data().map_err(S::Error::custom)?;
        root.end()
    }
}

impl Serialize for SourceRoot17<'_, '_, '_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let view = self.0;
        view.authenticate_data().map_err(S::Error::custom)?;
        let input = view.input;
        let association = input
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(S::Error::custom)?;
        let original = association
            .as_ref()
            .ok_or_else(|| S::Error::custom("Source association is absent"))?;
        let producer = original
            .producer_progress
            .try_borrow()
            .map_err(S::Error::custom)?;
        let current = original
            .current_observations
            .try_borrow()
            .map_err(S::Error::custom)?;
        let first = original
            .restoration_observation
            .as_ref()
            .ok_or_else(|| S::Error::custom("first observation is absent"))?
            .borrowed_logical17_data(input.source, input.controller)
            .map_err(S::Error::custom)?;
        let header = input
            .source
            .borrowed_settled17_header_data(input.aliases)
            .map_err(S::Error::custom)?;
        let once = original
            .borrowed_completed_once17_data(input.source, input.controller, input.key, header)
            .map_err(S::Error::custom)?;
        let limits = view.limits_data(&producer).map_err(S::Error::custom)?;
        let mut root = serializer.serialize_struct("RestoredSettledSource17", 11)?;
        root.serialize_field("schema", "source-private.source-restored-settled-state/17")?;
        root.serialize_field(
            "installation",
            &OriginalSourceRestoredInstallationExpected17(
                input.source.installation(),
                input.launch,
            ),
        )?;
        root.serialize_field(
            "world",
            &super::OriginalSourceRestoredWorld17View::new_data(input.world.record()),
        )?;
        root.serialize_field("once", &once)?;
        root.serialize_field("limits", &limits)?;
        root.serialize_field("first_observation", &first)?;
        root.serialize_field(
            "producer",
            &producer
                .borrowed_logical17_data()
                .map_err(S::Error::custom)?,
        )?;
        root.serialize_field(
            "current_observations",
            &current
                .borrowed_logical17_data()
                .map_err(S::Error::custom)?,
        )?;
        root.serialize_field("input_history", &None::<()>)?;
        match view.cut {
            Some(cut) => {
                root.serialize_field("capture", &cut.state_data().map_err(S::Error::custom)?)?
            }
            None => {
                let capture = original
                    .restored_capture
                    .try_borrow()
                    .map_err(S::Error::custom)?;
                let emitter = original
                    .emitter
                    .as_ref()
                    .ok_or_else(|| S::Error::custom("Source emitter is absent"))?;
                let ledger = capture
                    .borrowed_housekeeping_ledger_data(
                        input.source,
                        input.controller,
                        emitter,
                        input.world,
                        input.key,
                    )
                    .map_err(S::Error::custom)?;
                root.serialize_field("capture", &ledger)?;
            }
        }
        root.serialize_field(
            "inherited",
            &input
                .inherited
                .map(OriginalSourceRestoredSettled17Read::reference_data),
        )?;
        view.authenticate_data().map_err(S::Error::custom)?;
        root.end()
    }
}

impl OriginalSourceRestoredSettledSemantic17View<'_, '_, '_> {
    /// Reports defining serializer-only transient demand from actual operands.
    ///
    /// The caller separately admits output DOM/canonical buffers, prefix storage,
    /// Node/provider/common banks and all existing live owners. No output sizing
    /// or serialization is performed by this borrowed measurement.
    ///
    /// # Errors
    /// Refuses origin, unavailable child views or checked extent overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn serialization_transient_bytes_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.input
            .source
            .original_restored_settled_source17_serialization_transient_data(
                self.input.controller,
                self.input.launch,
            )
    }

    /// Names complete fixed root and defining child views before row admission.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow in the full simultaneous obligation.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn counter_scratch_data()
    -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::header17::SourceHeader17;
        use std::cell::Ref;
        [
            size_of::<Self>() + size_of::<Result<Self, RuntimeError>>(),
            size_of::<OriginalSourceRestoredSettled17WriteInputs<'static, 'static>>(),
            size_of::<SourceRoot17<'static, 'static, 'static, 'static>>()
                + super::OriginalSourceRestoredWorld17View::counter_scratch_data(),
            size_of::<OriginalRestoredSettledNodeHistoryView<'static>>(),
            size_of::<OriginalSourceRestoredLimits17>(),
            size_of::<OriginalSourceRestoredInstallationExpected17<'static>>(),
            size_of::<Option<&OriginalSourceRestoredSettled17Read>>(),
            size_of::<[usize; 5]>()
                + size_of::<[usize; 20]>()
                + size_of::<std::array::IntoIter<usize, 20>>()
                + size_of::<[usize; 6]>()
                + size_of::<std::array::IntoIter<usize, 6>>(),
            size_of::<String>() * 2,
            size_of::<Ref<'static, ProducerProgressHistory>>(),
            size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>(),
            size_of::<settled17_once::SourceOnce17View<SourceHeader17<'static>>>(),
            ProducerProgressHistory::logical17_counter_scratch_data(),
            restoration_observation::CurrentObservationHistory::unused_logical17_counter_scratch_data(),
            restoration_observation::OriginalSourceRestorationObservationAttempt::logical17_counter_scratch_data(),
            PacketCompleteSemanticSource::settled17_header_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restored_settled_startup_counter_scratch_data()?,
            PacketCompleteSemanticSource::original_restored_producer_launch_counter_scratch_data(),
            crucible_node_transport::reference_packet::service::native_startup::original_native_settled_carrier_counter_scratch_data(),
            super::super::owner::CaptureOnceOwner::counter_scratch_data(),
        ].into_iter().try_fold(0usize, |total, bytes| total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit))
    }
}

impl PacketCompleteSemanticSource {
    /// Measures actual Source serializer temporaries before a Capture row exists.
    ///
    /// This origin-only metadata walk emits no output or grant. Its caller must
    /// authenticate the same live controller and launch after admitting the
    /// complete row; it must not treat this measurement as current readiness.
    ///
    /// # Errors
    /// Refuses foreign origin, absent defining owners, unsupported old16 state
    /// or checked arithmetic overflow in actual serializer temporary geometry.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_restored_settled_source17_serialization_transient_data(
        &self,
        controller: &CnpController,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<usize, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let first = original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .borrowed_logical17_data(self, controller)?;
        let producer = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let current = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        current.require_unused_logical17_data()?;
        let launch =
            crucible_node_transport::retained_metadata::observe_retained_native_launch(launch)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        // Every typed launch Bytes child is one of the defining actual Vec
        // observations. Four times their total capacity conservatively covers
        // all base64 strings, including independent nested payload occurrences.
        let launch_bytes = launch
            .vector_capacity_bytes
            .checked_mul(4)
            .ok_or(RuntimeError::ResourceLimit)?;
        [
            first.serialization_transient_bytes_data()?,
            producer
                .borrowed_logical17_data()?
                .serialization_transient_bytes_data()?,
            current
                .borrowed_logical17_data()?
                .serialization_transient_bytes_data()?,
            launch_bytes,
            PacketCompleteSemanticSource::settled17_header_serialization_temporary_data(),
            20, // The independently live Capture/frontier U64 decimal buffer.
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

fn cumulative_producer_use_data(
    inherited: usize,
    local: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    inherited
        .checked_add(local)
        .filter(|used| *used <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_used_count_survives_a_new_boot_and_exhausts_the_original_cap() {
        let original_generic_cap = 7;
        let earlier_boot_originals = 9;
        let new_boot_originals = 19;
        assert_ne!(earlier_boot_originals, new_boot_originals);
        assert_eq!(
            cumulative_producer_use_data(5, 2, original_generic_cap).unwrap(),
            7
        );
        assert!(cumulative_producer_use_data(7, 1, original_generic_cap).is_err());
        assert!(cumulative_producer_use_data(usize::MAX, 1, usize::MAX).is_err());
    }
}
