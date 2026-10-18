//! Joins a completed modeled Source17 root to its exact immutable evidence.
//!
//! The opaque result preserves literal histories, admission counts, first and
//! latest checkpoints, once outcomes and the actual completed Capture ledger.
//! New runtime, Source, SDK, native and World authority is issued independently
//! by the complete cold group. No deserialized scalar supplies a live guard.

use super::{
    capture_ledger_reader::{
        OriginalSourceCaptureHousekeeping17Read, OriginalSourcePreEncoderCaptureHousekeeping17Read,
    },
    first_observation_reader::OriginalSourceRestoredFirstObservationHistory17Read,
    producer_fields::{field, object, read},
    producer_reader::{
        OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredProducerHistory17Read,
    },
    source_ancestry::authenticate_ancestry_data,
    source_fields::{self, OriginalSourceRestoredInstallation17, OriginalSourceRestoredLimits17},
    source_prefix::{Prefix17, semantic_data},
};
use crate::{
    node_adapters::cnp::CnpRestoredSettledValidatedNode17,
    node_adapters::cnp::semantic::packet_complete_source::{
        PacketCompleteSourceRole,
        ack_peer::association::settled17_once::OriginalSourceRestoredOnce17Read, header17,
    },
    node_contract::{RuntimeError, SavedRuntimeActivation},
};
use crucible_node_contract::{ContentRef, U64, canonical};
use crucible_node_provider::{
    protocol_snapshot::{
        current_controller17::ValidatedControllerSettledHistory17,
        restored_journal17::{PacketRestoredSettledAncestry17, RESTORED_SETTLED_SEMANTIC17_MEDIA},
        restored_settled17::SealedHistoricalRestoredSettledNative17,
    },
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::{PacketConnectedSourceProgram, complete_restore::PacketNativeRestoredCommitHold},
    },
};
use serde_json::Value;
use std::{mem::size_of, rc::Rc};

#[path = "source_reader/construction.rs"]
mod construction;
pub(crate) use construction::{
    OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17DecodeConstructionData,
};

#[path = "source_reader/prelude.rs"]
mod prelude;
pub(crate) use prelude::OriginalSourceRestoredSettled17Prelude;

/// Borrows actual independently authenticated participants for one cold read.
///
/// This aggregate is DATA. The native and SDK operands are defining opaque
/// validated owners; the outer archive still binds them to the exact same
/// signed owner roster, backend, implementation and full content closure.
pub(crate) struct OriginalSourceRestoredSettled17ReadInputs<'a> {
    pub(crate) controller: &'a ValidatedControllerSettledHistory17,
    pub(crate) native: &'a SealedHistoricalRestoredSettledNative17,
    pub(crate) node: &'a CnpRestoredSettledValidatedNode17,
    pub(crate) held: &'a PacketNativeRestoredCommitHold,
    pub(crate) world: &'a SavedRuntimeActivation,
    pub(crate) inherited: Option<&'a OriginalSourceRestoredSettled17Read>,
    pub(crate) prefix_bytes: &'a [u8],
    pub(crate) runtime_reference: &'a ContentRef,
    pub(crate) parent_archive_reference: &'a ContentRef,
    /// Borrows the actual imported parent manifest from the cold archive owner.
    pub(crate) parent_manifest_reference: &'a ContentRef,
    /// Borrows this World's originally imported semantic object from that owner.
    pub(crate) first_semantic_reference: &'a ContentRef,
    /// Borrows the full canonical Hold reference authenticated by native/Commit.
    pub(crate) restoration_hold_reference: &'a ContentRef,
    /// Borrows the complete ancestry parsed from the actual final Journal17.
    ///
    /// The cold group separately authenticates the signed parent Index3/DAG and
    /// the imported manifest/semantic/Hold roles before publishing live owners.
    pub(crate) journal_ancestry: &'a PacketRestoredSettledAncestry17,
    pub(crate) checkpoint_reference: &'a ContentRef,
    pub(crate) checkpoint_bytes: &'a [u8],
    pub(crate) maximum_coordinator_records: usize,
    pub(crate) maximum_bank_bytes: usize,
    pub(crate) maximum_transcript: usize,
}

/// Retains the complete validated modeled Source and original evidence identities.
///
/// Only the defining aggregate constructs this result. It has no public
/// constructor, Clone, Deserialize, live-owner conversion or Ready operation.
pub(crate) struct OriginalSourceRestoredSettled17Read {
    reference: ContentRef,
    node_reference: ContentRef,
    raw: Rc<Value>,
    first: OriginalSourceRestoredFirstObservationHistory17Read,
    producer: Option<OriginalSourceRestoredProducerCheckpoint17>,
    once: OriginalSourceRestoredOnce17Read,
    capture: OriginalSourceCaptureHousekeeping17Read,
    limits: OriginalSourceRestoredLimits17,
    generic_limits: (usize, usize, usize, usize),
    installation: OriginalSourceRestoredInstallation17,
    associations: usize,
}

impl OriginalSourceRestoredSettled17Read {
    /// Verifies a final Source root, actual uploaded prefix and all defining joins.
    ///
    /// The defining predecode attempt retains these raw and canonical inputs
    /// after admitting every typed, canonical and native-verifier intermediate.
    /// A failed read cannot publish a replacement live owner.
    ///
    /// # Errors
    /// Refuses malformed/noncanonical roots, another actual installation/World,
    /// nonrenewing counts or original limits, unsupported Input/old16 recurrence,
    /// incomplete once phases, unequal Node/Producer facts, a broken SDK/native
    /// chain, substituted prefix/checkpoint, or failed completed Capture evidence.
    fn validate_completed_data(
        reference: &ContentRef,
        literal: &[u8],
        raw: Rc<Value>,
        checked_canonical: &[u8],
        input: &OriginalSourceRestoredSettled17ReadInputs<'_>,
    ) -> Result<Self, RuntimeError> {
        if reference.media_type != RESTORED_SETTLED_SEMANTIC17_MEDIA {
            return Err(RuntimeError::InvalidReceipt);
        }
        if literal.len() > input.maximum_bank_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        reference
            .verify(literal)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if checked_canonical != literal {
            return Err(RuntimeError::InvalidReceipt);
        }
        let semantic = semantic_data(raw.as_ref())?;
        let root = source_fields::root_data(field(semantic, "source")?)?;
        let installation = source_fields::installation_data(field(root, "installation")?)?;
        // The actual sealed cold Boot authenticates canonical archived raw5.
        // No old process, live Source installation or fresh target is borrowed.
        input
            .native
            .authenticate_original_launch_data(&installation.launch)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let reactive = match &installation.launch.program {
            PacketConnectedSourceProgram::Producer { .. } => None,
            PacketConnectedSourceProgram::Reactive { program } => Some(program),
        };
        let world: SavedRuntimeActivation = read(field(root, "world")?)?;
        if world != *input.world
            || installation.world_binding_hash != world.world_binding_hash
            || input.node.node_data() != &installation.descriptor.id
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        input.node.authenticate_source_world17_data(&world)?;
        let node_bytes = canonical::canonical_json(field(semantic, "node")?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        input
            .node
            .reference_data()
            .verify(&node_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;

        let associations = associations_data(
            input.node.family_counts_data()?,
            installation.maximum_operations,
        )?;
        let limits = source_fields::limits_data(field(root, "limits")?)?;
        if limits.maximum_operations != installation.maximum_operations {
            return Err(RuntimeError::InvalidReceipt);
        }
        // This defining Recovery getter is a required concrete dependency: the
        // root's own scalar, a caller default and a host row cannot issue it.
        let maximum_originals = input
            .native
            .restored_suffix_maximum_originals_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if limits.maximum_originals
            != usize::try_from(maximum_originals.get()).map_err(|_| RuntimeError::ResourceLimit)?
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        source_fields::empty_current_data(field(root, "current_observations")?)?;
        if !field(root, "input_history")?.is_null()
            || limits.current_observations_used != 0
            || limits.input_used != 0
            || input.node.current_observations_data().len() != 0
        {
            return Err(RuntimeError::UnsupportedFacet);
        }

        let first = OriginalSourceRestoredFirstObservationHistory17Read::validate_data(
            field(root, "first_observation")?,
            input.controller,
            input.native,
            &world,
            &installation.descriptor,
            reactive,
            input.maximum_bank_bytes,
        )?;
        if first.scheduling_data() != input.node.first_observation_data()? {
            return Err(RuntimeError::InvalidReceipt);
        }
        let once_value = field(root, "once")?;
        let once = OriginalSourceRestoredOnce17Read::validate_data(
            once_value,
            input.controller,
            input.native,
            &first,
            input.maximum_transcript,
        )?;
        let outer = object(
            once_value,
            &[
                "association",
                "restore",
                "transfer",
                "activation",
                "first_observation",
                "suffix",
                "outer",
            ],
        )?;
        header17::validate_header17_data(
            field(outer, "outer")?,
            if reactive.is_some() {
                PacketCompleteSourceRole::Reactive
            } else {
                PacketCompleteSourceRole::Producer
            },
            input.maximum_coordinator_records,
        )?;

        let initial = first.checkpoint_data();
        let producer = match initial.1 {
            PacketNative5UnderlyingRecord::Producer(producer) if reactive.is_none() => {
                OriginalSourceRestoredProducerHistory17Read::validate_with_node_data(
                    field(root, "producer")?, input.controller, input.native, &installation.launch,
                    input.held, (initial.0, producer, initial.2),
                    &crate::node_adapters::cnp::semantic::packet_complete_source::OriginalRestoredProducerHistoricalInstallationData {
                        descriptor: &installation.descriptor,
                        owner: &installation.owner.owner.id,
                        incarnation: &installation.binding.authority.incarnation_id,
                        generation: installation.binding.authority.owner_generation,
                        world_binding: &world.world_binding_hash,
                        program: match &installation.launch.program {
                            PacketConnectedSourceProgram::Producer { program } => program,
                            PacketConnectedSourceProgram::Reactive { .. } => return Err(RuntimeError::InvalidReceipt),
                        },
                    },
                    &world, limits.maximum_operations, input.maximum_transcript, input.node,
                )?
            }
            PacketNative5UnderlyingRecord::Reactive(_) if reactive.is_some() => {
                OriginalSourceRestoredProducerHistory17Read::validate_empty_reactive_data(field(root, "producer")?)?
            }
            _ => return Err(RuntimeError::InvalidReceipt),
        };
        if producer.attempts_data().len() != input.node.producer_attempts_data().len() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let local_used = producer.attempts_data().len();
        let inherited_used =
            authenticate_inherited_data(field(root, "inherited")?, input, &installation)?;
        authenticate_producer_used_data(inherited_used, local_used, &limits)?;
        let producer = producer.into_checkpoint_data();
        let (checkpoint, frontier) = match producer.as_ref() {
            Some(producer) => (
                producer.checkpoint_data(),
                producer.completed_frontier_data(),
            ),
            None => (first.checkpoint_data(), first.completed_frontier_data()),
        };
        let capture = OriginalSourceCaptureHousekeeping17Read::validate_settled_data(
            field(root, "capture")?,
            input.controller,
            input.native,
            &world,
            (checkpoint.0, checkpoint.1, checkpoint.2, frontier),
            input.maximum_transcript,
        )?;
        let bridge = capture
            .bridge_data()
            .ok_or(RuntimeError::OutstandingObligations)?;
        let capture_request = bridge.sdk_data().request_data();
        if capture_request.coordinator_checkpoint != *input.checkpoint_reference
            || capture_request.runtime_object != *input.runtime_reference
            || capture_request.parent_archive != *input.parent_archive_reference
            || capture_request.first_observation != *first.checkpoint_data().2
            || capture_request.scope != *first.restoration_scope_data()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        authenticate_ancestry_data(field(semantic, "ancestry")?, input, &first)?;
        let prefix = Prefix17::validate_data(
            input.prefix_bytes,
            &bridge.sdk_data().request_data().history_prefix,
            raw.as_ref(),
            input.checkpoint_reference,
            input.checkpoint_bytes,
            input.maximum_bank_bytes,
        )?;
        OriginalSourcePreEncoderCaptureHousekeeping17Read::validate_data(
            prefix.capture_data()?,
            bridge.sdk_data(),
        )?;
        Ok(Self {
            reference: reference.clone(),
            node_reference: input.node.reference_data().clone(),
            raw,
            first,
            producer,
            once,
            capture,
            limits,
            associations,
            generic_limits: (
                installation.maximum_operations,
                installation.maximum_semantic_bytes,
                installation.maximum_result_bytes,
                installation.maximum_authorization_bytes,
            ),
            installation,
        })
    }

    /// Borrows the complete immutable semantic17 reference, including Node/Source.
    ///
    /// An inherited Source edge names this whole semantic object. Its separate
    /// inherited Node edge names the independently retained Node content object.
    pub(crate) fn reference_data(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the independent actual Node object used by inherited custody.
    pub(crate) fn node_reference_data(&self) -> &ContentRef {
        &self.node_reference
    }

    /// Borrows the owned archived installation, independently of fresh selection.
    pub(crate) fn original_installation_data(&self) -> &OriginalSourceRestoredInstallation17 {
        &self.installation
    }

    /// Returns the authenticated original generic installation limits in order.
    pub(crate) fn original_generic_limits_data(&self) -> (usize, usize, usize, usize) {
        self.generic_limits
    }

    /// Counts all five exact Node families, counting Stage/Commit custody once.
    pub(crate) fn historical_associations_count_data(&self) -> usize {
        self.associations
    }

    /// Borrows exact nonrenewing modeled counts rather than rebuilt Vec lengths.
    pub(crate) fn logical_limits_data(&self) -> &OriginalSourceRestoredLimits17 {
        &self.limits
    }

    /// Borrows exact signed modeled history without reconstructing a live Source.
    pub(crate) fn semantic_data(&self) -> &Value {
        self.raw.as_ref()
    }
}

fn authenticate_inherited_data(
    value: &Value,
    input: &OriginalSourceRestoredSettled17ReadInputs<'_>,
    installation: &OriginalSourceRestoredInstallation17,
) -> Result<usize, RuntimeError> {
    match (value.is_null(), input.inherited) {
        (true, None) if input.node.inherited_node_reference_data().is_none() => Ok(0),
        (false, Some(inherited)) => {
            let reference: ContentRef = read(value)?;
            if reference != inherited.reference
                || input.node.inherited_node_reference_data() != Some(&inherited.node_reference)
                || inherited.generic_limits
                    != (
                        installation.maximum_operations,
                        installation.maximum_semantic_bytes,
                        installation.maximum_result_bytes,
                        installation.maximum_authorization_bytes,
                    )
                || inherited.limits.current_observations_used != 0
                || inherited.limits.input_used != 0
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            // Native original reservations belong to their authenticated Boot
            // generation. Semantic associations retain their original lifetime
            // limits independently of a fresh transport reservation.
            Ok(inherited.limits.producer_used)
        }
        _ => Err(RuntimeError::InvalidReceipt),
    }
}

impl OriginalSourceRestoredSettled17Read {
    /// Borrows the immutable first-observation ancestry separately from currentness.
    pub(crate) fn first_observation_data(
        &self,
    ) -> &OriginalSourceRestoredFirstObservationHistory17Read {
        &self.first
    }

    /// Borrows the completed administrative bridge after exact native/SDK joins.
    pub(crate) fn capture_data(&self) -> &OriginalSourceCaptureHousekeeping17Read {
        &self.capture
    }

    /// Counts all typed read results and immutable raw root backing conservatively.
    ///
    /// The archive separately retains exact literal bytes and content owners.
    /// This census does not turn diagnostic geometry into modeled admission.
    ///
    /// # Errors
    /// Refuses defining metadata/layout overflow or the independently admitted bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error;
        use crate::node_contract::NodeRuntime;
        let terms = [
            size_of::<Self>(),
            self.installation.retained_heap_storage_data(maximum)?,
            NodeRuntime::capture_reference_storage(&self.reference)?,
            NodeRuntime::capture_reference_storage(&self.node_reference)?,
            value_storage_with_error::<RuntimeError>(self.raw.as_ref(), 0, maximum)?,
            size_of::<Value>(),
            NodeRuntime::capture_protocol_shared_header_storage(
                1,
                std::mem::align_of::<Value>(),
                maximum,
            )?,
            self.first.retained_requested_storage_data(maximum)?,
            self.producer
                .as_ref()
                .map(|producer| producer.retained_requested_storage_data(maximum))
                .transpose()?
                .unwrap_or(0),
            self.once.retained_requested_storage_data(maximum)?,
            self.capture.retained_requested_storage_data(maximum)?,
        ];
        terms.into_iter().try_fold(0usize, |sum, term| {
            sum.checked_add(term)
                .filter(|sum| *sum <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Names fixed aggregate controls beside independently admitted defining parsers.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<OriginalSourceRestoredSettled17ReadInputs<'static>>()
            + OriginalSourceRestoredInstallation17::counter_scratch_data()
            + size_of::<OriginalSourceRestoredLimits17>()
            + size_of::<Result<OriginalSourceRestoredLimits17, RuntimeError>>()
            + size_of::<OriginalSourceRestoredProducerHistory17Read<'static>>()
            + size_of::<OriginalSourceRestoredProducerCheckpoint17>()
            + size_of::<Option<OriginalSourceRestoredProducerCheckpoint17>>()
            + size_of::<SavedRuntimeActivation>()
            + size_of::<Result<SavedRuntimeActivation, RuntimeError>>()
            + size_of::<Rc<Value>>()
            + size_of::<ContentRef>() * 3
            + PacketRestoredSettledAncestry17::counter_scratch_data()
            + size_of::<Result<PacketRestoredSettledAncestry17, RuntimeError>>()
            + size_of::<Prefix17>()
            + size_of::<Result<Prefix17, RuntimeError>>()
            + size_of::<[usize; 5]>()
            + size_of::<[&str; 11]>()
            + size_of::<[&str; 20]>()
            + OriginalSourceCaptureHousekeeping17Read::counter_scratch_data()
    }
}

impl OriginalSourceRestoredSettled17Read {
    /// Borrows the exact checked latest model and completed administrative frontier.
    ///
    /// This tuple is historical DATA; a live cold target needs its independently
    /// issued native/Source/World/read publication conjunction before executing.
    ///
    /// # Errors
    /// Refuses an absent completed administrative ledger. The defining positive
    /// constructor requires it; no first-checkpoint fallback can hide refusal.
    pub(crate) fn current_checkpoint_data(&self) -> Result<(
        &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        &PacketNative5UnderlyingRecord, &ContentRef, U64,
    ), RuntimeError>{
        let checkpoint = match &self.producer {
            Some(producer) => producer.checkpoint_data(),
            None => self.first.checkpoint_data(),
        };
        let frontier = self
            .capture
            .completed_frontier_data()
            .ok_or(RuntimeError::OutstandingObligations)?;
        Ok((checkpoint.0, checkpoint.1, checkpoint.2, frontier))
    }
}

fn authenticate_producer_used_data(
    inherited: usize,
    local: usize,
    limits: &OriginalSourceRestoredLimits17,
) -> Result<(), RuntimeError> {
    if inherited.checked_add(local) != Some(limits.producer_used)
        || limits.producer_used > limits.maximum_operations
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn associations_data(counts: [usize; 5], maximum: usize) -> Result<usize, RuntimeError> {
    counts.into_iter().try_fold(0usize, |total, next| {
        total
            .checked_add(next)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_boot_original_capacity_cannot_renew_semantic_associations() {
        // This checks DATA accounting only; neither scalar constructs a Boot
        // reservation or substitutes for its defining native authentication.
        let prior = OriginalSourceRestoredLimits17 {
            maximum_operations: 3,
            maximum_originals: 9,
            producer_used: 2,
            current_observations_used: 0,
            input_used: 0,
        };
        let mut next = OriginalSourceRestoredLimits17 {
            maximum_operations: 3,
            maximum_originals: 19,
            producer_used: 3,
            current_observations_used: 0,
            input_used: 0,
        };
        assert_ne!(prior.maximum_originals, next.maximum_originals);
        authenticate_producer_used_data(prior.producer_used, 1, &next).unwrap();

        next.producer_used = 1;
        assert!(authenticate_producer_used_data(prior.producer_used, 1, &next).is_err());
        next.producer_used = 4;
        assert!(authenticate_producer_used_data(prior.producer_used, 2, &next).is_err());
        assert!(associations_data([1, 1, 1, 1, 0], next.maximum_operations).is_err());
    }

    #[test]
    fn original_generic_limit_covers_all_five_families_not_only_new_producer() {
        assert!(associations_data([1, 1, 1, 1, 1], 4).is_err());
        assert_eq!(associations_data([1, 1, 1, 1, 1], 5).unwrap(), 5);
        assert!(associations_data([usize::MAX, 1, 0, 0, 0], usize::MAX).is_err());
        assert_eq!(associations_data([0; 5], 0).unwrap(), 0);
    }
}
