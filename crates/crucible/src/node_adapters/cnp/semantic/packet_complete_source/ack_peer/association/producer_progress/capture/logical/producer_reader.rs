//! Joins complete Source Producer logical history to inert SDK and native proofs.
//!
//! The enclosing settled reader retains its exact bytes and partial DOM, admits
//! all typed/canonical validation work, and authenticates the signed archive and
//! installation. This component never reconstructs an SDK attempt, grant, live
//! World, Source key or executable owner from the archived logical state.

use super::producer_fields::{ProducerAttemptFields17, array, field, object, read};
use crate::{
    node_adapters::cnp::semantic::packet_complete_source::{
        OriginalRestoredProducerHistoricalAdmissionData,
        OriginalRestoredProducerHistoricalInstallationData, PacketCompleteSemanticSource,
    },
    node_contract::{ExactBoundaryPolicy, OperationRequest, RuntimeError, SavedRuntimeActivation},
};
use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::{
    bodies::{BeginKind, decode_request},
    protocol_snapshot::{
        current_controller17::{
            ValidatedControllerSettledHistory17, ValidatedHistoricalRestoredSuffixPair,
        },
        restored_settled17::SealedHistoricalRestoredSettledNative17,
    },
    reference_packet::{
        control::{PacketNative5UnderlyingRecord, PacketNativeRecord},
        service::{
            PacketNative5SourceLaunch,
            complete_restore::{
                PacketNativeRestoredCommitHold, PacketNativeRestoredRecord,
                producer_progress::{
                    PacketRestoredProducerHistoricalCompletedData,
                    PacketRestoredProducerHistoricalRetiredData,
                    PacketRestoredProducerOperationData, PacketRestoredProducerOperationReportData,
                    authenticate_restored_producer_historical_completed_data,
                    authenticate_restored_producer_historical_retired_data,
                },
            },
        },
    },
};
use serde_json::Value;

/// Borrows a complete checked logical Producer component, without live rights.
///
/// Only the defining reader constructs this component after the complete SDK,
/// native transition, Source transcript and common Outcome correspondence. The
/// enclosing semantic reader must still join current observation/Capture state,
/// native currentness, immutable ancestry and the actual signed owner roster.
pub(crate) struct OriginalSourceRestoredProducerHistory17Read<'a> {
    attempts: &'a [Value],
    checkpoint: Option<OriginalSourceRestoredProducerCheckpoint17>,
}

/// Retains the final actually verified Producer checkpoint as owned inert DATA.
///
/// Its fields move from the defining verifier loop. No public constructor,
/// decoder, clone or conversion can manufacture a current Source permission.
pub(crate) struct OriginalSourceRestoredProducerCheckpoint17 {
    record: PacketNativeRestoredRecord,
    underlying: PacketNative5UnderlyingRecord,
    measurement: ContentRef,
    scheduling: crate::node_scheduling::NativeSchedulingObservation,
    frontier: U64,
}

impl OriginalSourceRestoredProducerCheckpoint17 {
    /// Borrows the exact checked native/model/measurement tuple.
    pub(crate) fn checkpoint_data(
        &self,
    ) -> (
        &PacketNativeRestoredRecord,
        &PacketNative5UnderlyingRecord,
        &ContentRef,
    ) {
        (&self.record, &self.underlying, &self.measurement)
    }

    /// Borrows the checked common scheduling projection without claiming currency.
    pub(crate) fn scheduling_data(&self) -> &crate::node_scheduling::NativeSchedulingObservation {
        &self.scheduling
    }

    /// Returns the actual final post-evidence SDK frontier of this Producer row.
    pub(crate) fn completed_frontier_data(&self) -> U64 {
        self.frontier
    }

    fn producer_checkpoint_data(
        &self,
    ) -> Result<
        (
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        ),
        RuntimeError,
    > {
        let PacketNative5UnderlyingRecord::Producer(producer) = &self.underlying else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        Ok((&self.record, producer, &self.measurement))
    }
}

impl<'a> OriginalSourceRestoredProducerHistory17Read<'a> {
    pub(crate) fn validate_data(
        history: &'a Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        launch: &PacketNative5SourceLaunch,
        held: &PacketNativeRestoredCommitHold,
        initial_checkpoint: (
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        ),
        installation: &OriginalRestoredProducerHistoricalInstallationData<'_>,
        world: &SavedRuntimeActivation,
        maximum_operations: usize,
        maximum_signature_transcript: usize,
    ) -> Result<Self, RuntimeError> {
        Self::validate_inner_data(
            history,
            controller,
            native,
            launch,
            held,
            initial_checkpoint,
            installation,
            world,
            maximum_operations,
            maximum_signature_transcript,
            None,
        )
    }

    /// Validates each existing typed attempt against its exact actual Node row.
    ///
    /// The correspondence runs inside the same defining parse/verification loop;
    /// no attempt is parsed again or turned into a reconstructed admission.
    ///
    /// # Errors
    /// Refuses any defining SDK/native proof or missing, extra or unequal Node row.
    pub(crate) fn validate_with_node_data(
        history: &'a Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        launch: &PacketNative5SourceLaunch,
        held: &PacketNativeRestoredCommitHold,
        initial_checkpoint: (
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        ),
        installation: &OriginalRestoredProducerHistoricalInstallationData<'_>,
        world: &SavedRuntimeActivation,
        maximum_operations: usize,
        maximum_signature_transcript: usize,
        node: &crate::node_adapters::cnp::CnpRestoredSettledValidatedNode17,
    ) -> Result<Self, RuntimeError> {
        Self::validate_inner_data(
            history,
            controller,
            native,
            launch,
            held,
            initial_checkpoint,
            installation,
            world,
            maximum_operations,
            maximum_signature_transcript,
            Some(node),
        )
    }

    fn validate_inner_data(
        history: &'a Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        launch: &PacketNative5SourceLaunch,
        held: &PacketNativeRestoredCommitHold,
        initial_checkpoint: (
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        ),
        installation: &OriginalRestoredProducerHistoricalInstallationData<'_>,
        world: &SavedRuntimeActivation,
        maximum_operations: usize,
        maximum_signature_transcript: usize,
        node: Option<&crate::node_adapters::cnp::CnpRestoredSettledValidatedNode17>,
    ) -> Result<Self, RuntimeError> {
        let root = object(history, &["schema", "failed", "attempts"])?;
        if field(root, "schema")?.as_str()
            != Some("source-private.source-restored-producer-state/17")
            || field(root, "failed")?.as_bool() != Some(false)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let attempts = field(root, "attempts")?.as_array().ok_or_else(invalid)?;
        if attempts.len() > maximum_operations {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut node_attempts = node.map(|node| node.producer_attempts_data());
        if node_attempts
            .as_ref()
            .is_some_and(|rows| rows.len() != attempts.len())
        {
            return Err(invalid());
        }
        let mut previous_signature = [0; 32];
        let mut previous_slot = None;
        let mut previous_frontier: Option<U64> = None;
        let mut checkpoint: Option<OriginalSourceRestoredProducerCheckpoint17> = None;
        for value in attempts {
            let fields = ProducerAttemptFields17::read_data(value)?;
            if let Some(rows) = node_attempts.as_mut() {
                let node = rows.next().ok_or_else(invalid)?;
                if node.operation != &fields.operation
                    || node.request != &fields.request
                    || node.slot != fields.slot
                    || node.retained != Some(&fields.outcome)
                    || node.scheduling != Some(&fields.scheduling)
                {
                    return Err(invalid());
                }
            }
            if fields.previous != previous_signature
                || previous_slot.is_some_and(|slot| fields.slot <= slot)
            {
                return Err(invalid());
            }
            authenticate_world_data(fields.admission, world)?;
            authenticate_limits_data(&fields)?;
            let begin = pair(field(fields.original, "begin")?, controller)?;
            let poll = pair(field(fields.original, "poll")?, controller)?;
            let retire = pair(field(fields.original, "retire")?, controller)?;
            let observe = pair(field(fields.original, "observe")?, controller)?;
            let (begin_original, begin_terminal, _) =
                begin.completed_pair_data().map_err(|_| invalid())?;
            let (poll_original, poll_terminal, _) =
                poll.completed_pair_data().map_err(|_| invalid())?;
            if previous_frontier.is_some_and(|frontier| begin_original.sequence < frontier)
                || fields.arguments.input_authorization != fields.authorization.reference
                || serde_json::to_value(&fields.begin_body).map_err(|_| invalid())?
                    != Value::Object(begin_original.body.clone())
            {
                return Err(invalid());
            }
            authenticate_request_body_data(&poll, &fields.poll_body)?;
            authenticate_request_body_data(&retire, &fields.retire_body)?;
            authenticate_request_body_data(&observe, &fields.observe_body)?;
            let prior = match checkpoint.as_ref() {
                Some(checkpoint) => checkpoint.producer_checkpoint_data()?,
                None => initial_checkpoint,
            };
            let (kind, start, limit) = match fields.request {
                OperationRequest::ExactRun {
                    start,
                    limit,
                    boundary_policy: ExactBoundaryPolicy::HorizonPark,
                } => (BeginKind::ExactRun, start, limit),
                OperationRequest::BoundarySettle { start, limit } => {
                    (BeginKind::BoundarySettle, start, limit)
                }
                _ => return Err(RuntimeError::UnsupportedFacet),
            };
            let completed = PacketRestoredProducerHistoricalCompletedData {
                launch,
                held,
                checkpoint: prior.0,
                checkpoint_producer: prior.1,
                restored: &fields.completed_record,
                producer: &fields.completed_producer,
                measurement: &fields.completed_measurement,
                begin: &begin,
                poll: &poll,
                operation: PacketRestoredProducerOperationData {
                    operation: &fields.operation,
                    kind,
                    start,
                    limit,
                },
                arguments: &fields.arguments,
            };
            authenticate_restored_producer_historical_completed_data(&completed)
                .map_err(|_| invalid())?;
            authenticate_restored_producer_historical_retired_data(
                &PacketRestoredProducerHistoricalRetiredData {
                    completed: &completed,
                    consumption: &fields.consumption.reference,
                    canonical_consumption: &fields.consumption.bytes,
                    durable_root: &fields.durable_root,
                    retire: &retire,
                    observe: &observe,
                    restored: &fields.checkpoint_record,
                    producer: &fields.checkpoint_producer,
                    measurement: &fields.checkpoint_measurement,
                },
            )
            .map_err(|_| invalid())?;
            let mapped = PacketCompleteSemanticSource::original_restored_producer_historical_mapped_outcome_data(
                OriginalRestoredProducerHistoricalAdmissionData {
                    operation: &fields.operation, route: &fields.route,
                    request: &fields.request, world_binding: &world.world_binding_hash,
                    activation_owners: &world.owners,
                },
                OriginalRestoredProducerHistoricalInstallationData {
                    descriptor: installation.descriptor, owner: installation.owner,
                    incarnation: installation.incarnation, generation: installation.generation,
                    world_binding: installation.world_binding,
                    program: installation.program,
                },
                &fields.completed_record, &fields.completed_producer,
                &fields.completed_measurement,
            )?;
            let mapped_checkpoint = PacketCompleteSemanticSource::original_restored_producer_historical_checkpoint_scheduling_data(
                &world.world_binding_hash, &world.owners,
                OriginalRestoredProducerHistoricalInstallationData {
                    descriptor: installation.descriptor, owner: installation.owner,
                    incarnation: installation.incarnation, generation: installation.generation,
                    world_binding: installation.world_binding,
                    program: installation.program,
                },
                &fields.checkpoint_record, &fields.checkpoint_producer,
                &fields.checkpoint_measurement,
            )?;
            if mapped != fields.outcome || mapped_checkpoint != fields.scheduling {
                return Err(invalid());
            }
            let report = PacketRestoredProducerOperationReportData {
                operation: &fields.operation,
                begin_original,
                begin_terminal,
                poll_original,
                poll_terminal,
                measurement: &fields.completed_measurement,
                restored: &fields.completed_record,
                producer: &fields.completed_producer,
                input_authorization: &fields.authorization.reference,
            };
            if serde_json::to_value(report).map_err(|_| invalid())?
                != *field(fields.original, "report_value")?
            {
                return Err(invalid());
            }
            authenticate_signature_data(
                &fields,
                [&begin, &poll, &retire, &observe],
                controller,
                native,
                maximum_signature_transcript,
            )?;
            previous_slot = Some(fields.slot);
            previous_signature = fields.signature;
            previous_frontier = Some(observe.completed_frontier_data());
            checkpoint = Some(OriginalSourceRestoredProducerCheckpoint17 {
                record: fields.checkpoint_record,
                underlying: PacketNative5UnderlyingRecord::Producer(Box::new(
                    fields.checkpoint_producer,
                )),
                measurement: fields.checkpoint_measurement,
                scheduling: fields.scheduling,
                frontier: observe.completed_frontier_data(),
            });
        }
        if node_attempts.as_ref().is_some_and(|rows| rows.len() != 0) {
            return Err(invalid());
        }
        Ok(Self {
            attempts,
            checkpoint,
        })
    }

    /// Validates the exact unused Producer ledger for a Reactive first checkpoint.
    ///
    /// # Errors
    /// Refuses any failed, nonempty or differently shaped historical owner. This
    /// cannot invent a Producer checkpoint for a Reactive model.
    pub(crate) fn validate_empty_reactive_data(history: &'a Value) -> Result<Self, RuntimeError> {
        let root = object(history, &["schema", "failed", "attempts"])?;
        if field(root, "schema")?.as_str()
            != Some("source-private.source-restored-producer-state/17")
            || field(root, "failed")?.as_bool() != Some(false)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let attempts = field(root, "attempts")?
            .as_array()
            .filter(|attempts| attempts.is_empty())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        Ok(Self {
            attempts,
            checkpoint: None,
        })
    }

    /// Moves the already verified final checkpoint after all Node joins complete.
    ///
    /// An empty Producer history yields None. No checkpoint is reconstructed from
    /// a summary timestamp, parsed again, cloned or substituted for first Observe.
    pub(crate) fn into_checkpoint_data(self) -> Option<OriginalSourceRestoredProducerCheckpoint17> {
        self.checkpoint
    }

    /// Compares the actual retained Node row without recreating its moved results.
    pub(crate) fn authenticate_node_attempt_data(
        &self,
        index: usize,
        node: &Value,
    ) -> Result<(), RuntimeError> {
        let source = object(
            self.attempts.get(index).ok_or_else(invalid)?,
            &super::producer_fields::ATTEMPT_FIELDS,
        )?;
        let node = object(
            node,
            &[
                "admission",
                "slot",
                "stage",
                "retained",
                "returned",
                "scheduling",
                "scheduling_return",
            ],
        )?;
        if field(node, "slot")? != field(source, "slot")?
            || field(node, "stage")?.as_str() != Some("verified")
            || field(node, "admission")? != field(source, "admission")?
            || field(node, "retained")? != field(source, "outcome")?
            || field(node, "scheduling")? != field(source, "scheduling")?
            || !field(node, "returned")?.is_null()
            || !field(node, "scheduling_return")?.is_null()
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn attempts_data(&self) -> &[Value] {
        self.attempts
    }
}

fn authenticate_signature_data(
    fields: &ProducerAttemptFields17<'_>,
    lifecycle: [&ValidatedHistoricalRestoredSuffixPair; 4],
    controller: &ValidatedControllerSettledHistory17,
    native: &SealedHistoricalRestoredSettledNative17,
    maximum_transcript: usize,
) -> Result<(), RuntimeError> {
    let mut verifier = native
        .restored_producer_history_verifier_data(fields.slot, &fields.previous, maximum_transcript)
        .map_err(|_| invalid())?;
    for owner in lifecycle {
        let (original, terminal, _) = owner.completed_pair_data().map_err(|_| invalid())?;
        serde_json::to_writer(&mut verifier, &(original, terminal)).map_err(|_| invalid())?;
    }
    let uploads = field(fields.original, "uploads")?
        .as_array()
        .ok_or_else(invalid)?;
    let bodies = field(fields.original, "upload_bodies")?
        .as_array()
        .ok_or_else(invalid)?;
    let ids = field(fields.original, "request_ids")?
        .as_array()
        .ok_or_else(invalid)?;
    if uploads.len() != bodies.len() || uploads.len() != ids.len() {
        return Err(invalid());
    }
    for ((owner, body), id) in uploads.iter().zip(bodies).zip(ids) {
        let owner = pair(owner, controller)?;
        let (original, terminal, _) = owner.completed_pair_data().map_err(|_| invalid())?;
        let body = object(body, &["kind", "value"])?;
        let kind = match original.method {
            crucible_node_provider::envelope::Method::BlobBegin => "blob_begin",
            crucible_node_provider::envelope::Method::BlobChunk => "blob_chunk",
            crucible_node_provider::envelope::Method::BlobFinish => "blob_finish",
            _ => return Err(invalid()),
        };
        if field(body, "kind")?.as_str() != Some(kind)
            || field(body, "value")?.as_object() != Some(&original.body)
            || read::<crucible_node_contract::Id>(id)?
                != *original.request_id.0.as_ref().ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        // Strict method decoding is distinct from serializing the exact original.
        decode_request(original.method, &original.body).map_err(|_| invalid())?;
        serde_json::to_writer(&mut verifier, &(original, terminal)).map_err(|_| invalid())?;
    }
    serde_json::to_writer(&mut verifier, field(fields.original, "record_values")?)
        .map_err(|_| invalid())?;
    serde_json::to_writer(&mut verifier, &Some(&fields.outcome)).map_err(|_| invalid())?;
    serde_json::to_writer(&mut verifier, &Some(&fields.report_reference)).map_err(|_| invalid())?;
    serde_json::to_writer(&mut verifier, &Some(&fields.durable_root)).map_err(|_| invalid())?;
    serde_json::to_writer(&mut verifier, &Some(&fields.scheduling)).map_err(|_| invalid())?;
    verifier
        .verify_data(&fields.signature)
        .map_err(|_| invalid())
}

fn authenticate_world_data(
    admission: &Value,
    world: &SavedRuntimeActivation,
) -> Result<(), RuntimeError> {
    let wrapper = object(admission, &["kind", "value"])?;
    let admission = field(wrapper, "value")?.as_object().ok_or_else(invalid)?;
    let activation = object(
        field(admission, "activation")?,
        &["record", "nodes", "preparation"],
    )?;
    let record = object(
        field(activation, "record")?,
        &[
            "generation",
            "activation_id",
            "world_binding_hash",
            "owners",
            "boundary",
        ],
    )?;
    if read::<U64>(field(record, "generation")?)? != world.generation
        || read::<crucible_node_contract::Id>(field(record, "activation_id")?)?
            != world.activation_id
        || read::<crucible_node_contract::HashRef>(field(record, "world_binding_hash")?)?
            != world.world_binding_hash
        || read::<Vec<crate::node_contract::OwnerIdentity>>(field(record, "owners")?)?
            != world.owners
        || read::<crucible_node_contract::Position>(field(record, "boundary")?)? != world.boundary
    {
        return Err(invalid());
    }
    Ok(())
}

fn authenticate_limits_data(fields: &ProducerAttemptFields17<'_>) -> Result<(), RuntimeError> {
    let row = object(
        field(fields.original, "row")?,
        &[
            "provider",
            "maximum_restored_record_bytes",
            "maximum_underlying_record_bytes",
            "retained",
            "transient",
            "scratch",
            "maximum",
            "runtime_work",
            "complete_scratch",
        ],
    )?;
    let provider = authenticate_provider_facts_data(field(row, "provider")?)?;
    let originals: usize = read(field(provider, "originals")?)?;
    let uploads = field(fields.original, "uploads")?
        .as_array()
        .ok_or_else(invalid)?;
    if uploads
        .len()
        .checked_add(4)
        .is_none_or(|count| count > originals)
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let restored: usize = read(field(row, "maximum_restored_record_bytes")?)?;
    let underlying: usize = read(field(row, "maximum_underlying_record_bytes")?)?;
    if restored != 65_536 || underlying != 65_536 {
        return Err(invalid());
    }
    let banks = array(field(fields.original, "record_canonical")?, 4)?;
    for (bank, maximum) in banks
        .iter()
        .zip([restored, underlying, restored, underlying])
    {
        if bank.as_array().ok_or_else(invalid)?.len() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
    }
    // These remain historical demand facts. They are never reconstructed into
    // a live Provider row or used to replenish an existing native reservation.
    for name in [
        "retained",
        "transient",
        "scratch",
        "maximum",
        "complete_scratch",
    ] {
        read::<usize>(field(row, name)?)?;
    }
    read::<(usize, usize, usize)>(field(row, "runtime_work")?)?;
    let report_limit: usize = read(field(provider, "maximum_report")?)?;
    if field(fields.original, "report_bytes")?
        .as_array()
        .ok_or_else(invalid)?
        .len()
        > report_limit
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

fn authenticate_provider_facts_data(
    value: &Value,
) -> Result<&serde_json::Map<String, Value>, RuntimeError> {
    use crucible_node_provider::reference_packet::service::native_startup::{
        PacketNativeStartupAllocationRow, PacketRestoredSuffixReservationData,
    };
    let provider = object(
        value,
        &[
            "schema",
            "startup",
            "population",
            "identity",
            "ingress",
            "action",
            "host_retained",
            "host_transient",
            "source_retained",
            "source_transient",
            "maximum_report",
            "originals",
            "scratch",
            "requested",
        ],
    )?;
    if field(provider, "schema")?.as_str()
        != Some("source-private.restored-producer-lifecycle-storage/1")
    {
        return Err(invalid());
    }
    read::<[u8; 32]>(field(provider, "identity")?)?;
    for name in ["ingress", "action"] {
        read::<PacketNativeStartupAllocationRow>(field(provider, name)?)?
            .requested_peak_data()
            .map_err(|_| invalid())?;
    }
    for name in [
        "host_retained",
        "host_transient",
        "source_retained",
        "source_transient",
        "maximum_report",
        "originals",
        "scratch",
        "requested",
    ] {
        read::<usize>(field(provider, name)?)?;
    }
    let population = object(
        field(provider, "population")?,
        &[
            "pending_before",
            "pending_after",
            "completed",
            "newborn",
            "payload_bytes",
            "event_id_bytes",
            "operation_id_bytes",
        ],
    )?;
    for name in [
        "pending_before",
        "pending_after",
        "completed",
        "newborn",
        "payload_bytes",
        "event_id_bytes",
        "operation_id_bytes",
    ] {
        read::<usize>(field(population, name)?)?;
    }
    let startup = object(
        field(provider, "startup")?,
        &[
            "schema",
            "model",
            "launch_digest",
            "launch_bytes",
            "frame_bytes",
            "originals",
            "reservation",
            "retained",
            "transient",
            "scratch",
            "requested",
        ],
    )?;
    if field(startup, "schema")?.as_str()
        != Some("source-private.restored-suffix-startup-storage/1")
    {
        return Err(invalid());
    }
    read::<[u8; 32]>(field(startup, "launch_digest")?)?;
    read::<PacketRestoredSuffixReservationData>(field(startup, "reservation")?)?
        .requested_bytes_data()
        .map_err(|_| invalid())?;
    for name in [
        "launch_bytes",
        "frame_bytes",
        "originals",
        "retained",
        "transient",
        "scratch",
        "requested",
    ] {
        read::<usize>(field(startup, name)?)?;
    }
    let model = object(
        field(startup, "model")?,
        &[
            "snapshot_bytes",
            "journal_bytes",
            "control_bytes",
            "model_vector_backing_bytes",
            "anchor_bytes",
            "capture_comparison_bytes",
            "declared_scanner_bytes",
            "total_bytes",
        ],
    )?;
    for name in [
        "snapshot_bytes",
        "journal_bytes",
        "control_bytes",
        "model_vector_backing_bytes",
        "anchor_bytes",
        "capture_comparison_bytes",
        "declared_scanner_bytes",
        "total_bytes",
    ] {
        read::<usize>(field(model, name)?)?;
    }
    Ok(provider)
}

fn authenticate_request_body_data(
    pair: &ValidatedHistoricalRestoredSuffixPair,
    body: &impl serde::Serialize,
) -> Result<(), RuntimeError> {
    let (original, _, _) = pair.completed_pair_data().map_err(|_| invalid())?;
    if serde_json::to_value(body)
        .map_err(|_| invalid())?
        .as_object()
        != Some(&original.body)
    {
        return Err(invalid());
    }
    Ok(())
}

fn pair(
    history: &Value,
    controller: &ValidatedControllerSettledHistory17,
) -> Result<ValidatedHistoricalRestoredSuffixPair, RuntimeError> {
    ValidatedHistoricalRestoredSuffixPair::validate_data(history, controller).map_err(|_| invalid())
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}

impl OriginalSourceRestoredProducerCheckpoint17 {
    /// Counts actual retained result backing without reconstructing a live owner.
    ///
    /// # Errors
    /// Refuses defining metadata overflow or the independently admitted ceiling.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::{node_adapters::cnp::PacketCompleteSemanticSource, node_contract::NodeRuntime};
        use crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data;
        let native = restoration_activation_retained_native_evidence_data(
            &self.record,
            Some(&self.underlying),
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let terms = [
            std::mem::size_of::<Self>(),
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &native, maximum,
            )?,
            NodeRuntime::capture_reference_storage(&self.measurement)?,
            NodeRuntime::capture_scheduling_observation_storage_data(&self.scheduling, maximum)?,
        ];
        terms.into_iter().try_fold(0usize, |total, term| {
            total
                .checked_add(term)
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }
}

#[cfg(test)]
mod root_reader_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_reactive_history_cannot_manufacture_a_producer_checkpoint() {
        let history = json!({"schema":"source-private.source-restored-producer-state/17",
            "failed":false,"attempts":[]});
        let checked =
            OriginalSourceRestoredProducerHistory17Read::validate_empty_reactive_data(&history)
                .unwrap();
        assert!(checked.into_checkpoint_data().is_none());
        let mut changed = history.clone();
        changed["attempts"] = json!([{}]);
        assert!(
            OriginalSourceRestoredProducerHistory17Read::validate_empty_reactive_data(&changed)
                .is_err()
        );
        changed = history;
        changed["failed"] = json!(true);
        assert!(
            OriginalSourceRestoredProducerHistory17Read::validate_empty_reactive_data(&changed)
                .is_err()
        );
    }
}
