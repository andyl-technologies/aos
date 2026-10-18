//! Preserves completed Source once outcomes without reconstructing live owners.
//!
//! The enclosing signed Source record retains the actual SDK/native originals.
//! These closed scalar records preserve the phase/occupancy decisions consumed
//! by later admission. They neither recreate old SDK operations nor reproduce
//! verifier allocation geometry. Incomplete operations have no completed loan.

use super::*;
use crucible_node_contract::Position;
use serde::{Deserialize, Serialize};

#[path = "settled17_once/decode_geometry.rs"]
mod decode_geometry;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssociationOnce17 {
    attempted: bool,
    ready: bool,
    failed: bool,
    signing_attempted: bool,
    sealed: bool,
    publication_attempted: bool,
    completed_mechanism: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreOnce17 {
    pub(super) prepared: bool,
    pub(super) ready: bool,
    pub(super) signing_started: bool,
    pub(super) sealed: bool,
    pub(super) publishing_started: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransferPhaseOnce17 {
    pub(super) started: bool,
    pub(super) sealed: bool,
    pub(super) publishing_started: bool,
    pub(super) verified: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransferOnce17 {
    pub(super) mapping_attempted: bool,
    pub(super) mapping_complete: bool,
    pub(super) prepare: TransferPhaseOnce17,
    pub(super) commit: TransferPhaseOnce17,
    pub(super) inputs_started: bool,
    pub(super) inputs_verified: bool,
    pub(super) failed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationOnce17 {
    pub(super) reserved: bool,
    pub(super) started: [bool; 2],
    pub(super) verified: [bool; 2],
    pub(super) failed: bool,
    pub(super) uploads_next: usize,
    pub(super) upload_in_flight: bool,
    pub(super) upload_failed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FirstObservationOnce17 {
    pub(super) reserved: bool,
    pub(super) verified: bool,
    pub(super) binding: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SuffixOnce17 {
    pub(super) stage: VerifiedSuffixStage17,
    pub(super) restoration_proof: [u8; 32],
    pub(super) native_binding: [u8; 32],
    pub(super) observation_binding: [u8; 32],
    pub(super) reached: Position,
    pub(super) signature: [u8; 32],
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum VerifiedSuffixStage17 {
    Verified,
}

/// Borrows the defining outer header while owning only fixed phase facts.
///
/// No historical fact supplies a live guard. All phase facts are fixed inline
/// values; their original owning execution state stays retained by the Source.
#[derive(Serialize)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceOnce17View<Outer> {
    association: AssociationOnce17,
    restore: RestoreOnce17,
    transfer: TransferOnce17,
    activation: ActivationOnce17,
    first_observation: FirstObservationOnce17,
    suffix: SuffixOnce17,
    outer: Outer,
}

impl OriginalAckPeerAssociation {
    /// Lends literal completed phase decisions from the same original Source.
    ///
    /// The caller independently holds SourceRead, supervisor and Capture claim
    /// across serialization and rechecks them after the completed output.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_completed_once17_data<
        Outer: Serialize,
    >(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        key: &[u8; 32],
        outer: Outer,
    ) -> Result<SourceOnce17View<Outer>, RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        self.emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let association = AssociationOnce17 {
            attempted: self.attempted,
            ready: self.ready,
            failed: self.failed,
            signing_attempted: self.signing_attempted,
            sealed: self.sealed,
            publication_attempted: self.publication_attempted,
            completed_mechanism: self.completed_mechanism.get(),
        };
        association.authenticate_completed_data()?;
        let restore = self
            .restore
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled17_once_data()?;
        restore.authenticate_dormant_data()?;
        let transfer = self
            .restore_transfer_banks
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled17_once_data()?;
        transfer.authenticate_completed_data()?;
        let activation = self
            .restoration_activation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled17_once_data(source, controller)?;
        activation.authenticate_completed_data()?;
        let first_observation = self
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled17_once_data(source, controller)?;
        first_observation.authenticate_completed_data()?;
        let seed = self
            .restored_suffix
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let suffix = seed
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .settled17_once_data(source, controller, key)?;
        Ok(SourceOnce17View {
            association,
            restore,
            transfer,
            activation,
            first_observation,
            suffix,
            outer,
        })
    }
}

impl AssociationOnce17 {
    fn authenticate_completed_data(&self) -> Result<(), RuntimeError> {
        if !self.attempted
            || !self.ready
            || self.failed
            || !self.signing_attempted
            || !self.sealed
            || !self.publication_attempted
            || !self.completed_mechanism
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl RestoreOnce17 {
    fn authenticate_dormant_data(&self) -> Result<(), RuntimeError> {
        // The transfer dialect retains the original empty restore reservation.
        // A legacy request already entering execution is not this safe point.
        if self.prepared
            || self.ready
            || self.signing_started
            || self.sealed
            || self.publishing_started
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }
}

impl TransferPhaseOnce17 {
    fn authenticate_completed_data(&self) -> Result<(), RuntimeError> {
        if !self.started || !self.sealed || !self.publishing_started || !self.verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl TransferOnce17 {
    fn authenticate_completed_data(&self) -> Result<(), RuntimeError> {
        if !self.mapping_attempted
            || !self.mapping_complete
            || !self.inputs_started
            || !self.inputs_verified
            || self.failed
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.prepare.authenticate_completed_data()?;
        self.commit.authenticate_completed_data()
    }
}

impl ActivationOnce17 {
    fn authenticate_completed_data(&self) -> Result<(), RuntimeError> {
        if !self.reserved
            || self.started != [true; 2]
            || self.verified != [true; 2]
            || self.failed
            || self.uploads_next != 2
            || self.upload_in_flight
            || self.upload_failed
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl FirstObservationOnce17 {
    fn authenticate_completed_data(&self) -> Result<(), RuntimeError> {
        if !self.reserved || !self.verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

/// Retains checked once outcomes as DATA below the exact signed Source body.
///
/// No public constructor, deserializer, clone or live-owner conversion exists.
pub(crate) struct OriginalSourceRestoredOnce17Read {
    suffix: SuffixOnce17,
}

impl OriginalSourceRestoredOnce17Read {
    /// Checks closed once phases against actual completed SDK/native ancestry.
    ///
    /// # Errors
    /// Refuses unknown phase fields, an active/failed cut, incomplete SDK state,
    /// substituted first binding or suffix checkpoint, or a broken seed MAC.
    pub(crate) fn validate_data(
        value: &serde_json::Value,
        controller: &crucible_node_provider::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        native: &crucible_node_provider::protocol_snapshot::restored_settled17::SealedHistoricalRestoredSettledNative17,
        first: &producer_progress::capture::OriginalSourceRestoredFirstObservationHistory17Read,
        maximum_transcript: usize,
    ) -> Result<Self, RuntimeError> {
        use std::io::Write;
        let fields = object(
            value,
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
        let association: AssociationOnce17 = read(field(fields, "association")?)?;
        association.authenticate_completed_data()?;
        let restore: RestoreOnce17 = read(field(fields, "restore")?)?;
        restore.authenticate_dormant_data()?;
        let transfer: TransferOnce17 = read(field(fields, "transfer")?)?;
        transfer.authenticate_completed_data()?;
        let activation: ActivationOnce17 = read(field(fields, "activation")?)?;
        activation.authenticate_completed_data()?;
        let observation: FirstObservationOnce17 = read(field(fields, "first_observation")?)?;
        observation.authenticate_completed_data()?;
        if observation.binding != *first.binding_data() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let suffix = read_suffix_data(field(fields, "suffix")?)?;
        if suffix.stage != VerifiedSuffixStage17::Verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        let (record, underlying, _) = first.checkpoint_data();
        let expected = restoration_continuation::historical_checkpoint17_data(
            reference_identity_data(&first.restoration_scope_data().scope_proof),
            record,
            underlying,
            first.scheduling_data(),
        )?;
        if suffix.restoration_proof != expected.restoration_proof
            || suffix.native_binding != expected.native_binding
            || suffix.observation_binding != expected.observation_binding
            || suffix.reached != expected.reached
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let state = controller
            .parts_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        for name in ["ack_admit", "restore_prepare", "restore_commit"] {
            let assigned = state
                .get(name)
                .and_then(serde_json::Value::as_array)
                .ok_or(RuntimeError::InvalidReceipt)?;
            if assigned.get(5).and_then(serde_json::Value::as_str) != Some("complete") {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        let phases = state
            .get("activation")
            .and_then(serde_json::Value::as_array)
            .filter(|v| v.len() == 2)
            .ok_or(RuntimeError::InvalidReceipt)?;
        for phase in phases {
            if phase
                .as_array()
                .and_then(|v| v.get(8))
                .and_then(serde_json::Value::as_str)
                != Some("complete")
            {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        let uploads = state
            .get("uploads")
            .and_then(serde_json::Value::as_array)
            .filter(|rows| rows.len() == 2)
            .ok_or(RuntimeError::InvalidReceipt)?;
        for (ordinal, upload) in uploads.iter().enumerate() {
            let row = upload.as_array().ok_or(RuntimeError::InvalidReceipt)?;
            if row.get(6).and_then(serde_json::Value::as_str) != Some("complete") {
                return Err(RuntimeError::OutstandingObligations);
            }
            let upload_request: crucible_node_provider::reference_packet::service::complete_restore::activation::upload::PacketRestorationActivationUploadRequest = read(row.get(1).ok_or(RuntimeError::InvalidReceipt)?)?;
            upload_request
                .validate_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let transfer: Id = read(row.get(2).ok_or(RuntimeError::InvalidReceipt)?)?;
            if upload_request.role.ordinal_data() != ordinal
                || &upload_request.scope != first.restoration_scope_data()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            let frames = row
                .get(4)
                .and_then(serde_json::Value::as_array)
                .filter(|frames| !frames.is_empty())
                .ok_or(RuntimeError::InvalidReceipt)?;
            if u64::try_from(frames.len()).map_err(|_| RuntimeError::ResourceLimit)?
                != upload_request.maximum_requests.get()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            for frame in frames {
                if frame.get("attempted").and_then(serde_json::Value::as_bool) != Some(true)
                    || frame.get("complete").and_then(serde_json::Value::as_bool) != Some(true)
                {
                    return Err(RuntimeError::OutstandingObligations);
                }
                let original: crucible_node_provider::envelope::Envelope =
                    read(frame.get("original").ok_or(RuntimeError::InvalidReceipt)?)?;
                let received = frame
                    .get("received")
                    .and_then(serde_json::Value::as_array)
                    .filter(|received| received.len() == 2)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                let terminal: crucible_node_provider::envelope::Envelope = read(&received[0])?;
                controller
                    .authenticate_historical_controller_pair17_data(&original, &terminal)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let request =
                    crucible_node_provider::bodies::decode_request(original.method, &original.body)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                let response =
                    crucible_node_provider::bodies::decode_response(&request, &terminal.body)
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                use crucible_node_provider::{
                    bodies::{MethodResult, OperationState, ResponseShape},
                    envelope::Method,
                };
                let offset = frame
                    .get("offset")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                let length = frame
                    .get("length")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                let method: Method =
                    read(frame.get("method").ok_or(RuntimeError::InvalidReceipt)?)?;
                if original.method != method {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let matched = match &response.result {
                    Some(MethodResult::BlobBegin(progress)) if method == Method::BlobBegin => {
                        progress.transfer_id == transfer
                            && progress.next_offset.get() == 0
                            && progress.maximum_chunk_bytes >= upload_request.chunk_bytes
                    }
                    Some(MethodResult::BlobChunk(progress)) if method == Method::BlobChunk => {
                        progress.transfer_id == transfer
                            && progress.next_offset.get()
                                == offset
                                    .checked_add(length)
                                    .ok_or(RuntimeError::ResourceLimit)?
                    }
                    Some(MethodResult::BlobFinish(progress)) if method == Method::BlobFinish => {
                        progress.transfer_id == transfer
                            && &progress.content == upload_request.content_ref_data()
                    }
                    _ => false,
                };
                if !matched
                    || !terminal.extensions.is_empty()
                    || !matches!(&response.shape, ResponseShape::Completed { operation_state: OperationState::Completed, extensions, .. } if extensions.is_empty())
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let typed = received[1]
                    .as_array()
                    .filter(|typed| typed.len() == 2)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                if typed[0].as_str() != Some("response") {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let expected =
                    crucible_node_provider::retained_metadata::historical_response_body_data(
                        &response,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if serde_json::to_value(expected).map_err(|_| RuntimeError::InvalidReceipt)?
                    != typed[1]
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
        }
        let mut verifier = native
            .restored_suffix_seed_history_verifier_data(maximum_transcript)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        for bytes in [
            &suffix.restoration_proof[..],
            &suffix.native_binding[..],
            &suffix.observation_binding[..],
            &suffix.reached.time_ps.get().to_le_bytes(),
            &suffix.reached.microstep.get().to_le_bytes(),
            &(suffix.reached.phase as u16).to_le_bytes(),
        ] {
            verifier
                .write_all(bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        verifier
            .verify_data(&suffix.signature)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(Self { suffix })
    }

    pub(crate) fn initial_reached_data(&self) -> Position {
        self.suffix.reached
    }

    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let _ = maximum;
        Ok(0)
    }
}

fn reference_identity_data(reference: &ContentRef) -> [u8; 32] {
    let mut state =
        blake3::Hasher::new_derive_key("core.original-restoration-held-reference-correspondence/1");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        state.update(&(text.len() as u64).to_le_bytes());
        state.update(text.as_bytes());
    }
    state.update(&reference.length.get().to_le_bytes());
    *state.finalize().as_bytes()
}

fn object<'a>(
    value: &'a serde_json::Value,
    names: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, RuntimeError> {
    let fields = value.as_object().ok_or(RuntimeError::InvalidReceipt)?;
    if fields.len() != names.len() || names.iter().any(|name| !fields.contains_key(*name)) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(fields)
}

fn field<'a>(
    fields: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<&'a serde_json::Value, RuntimeError> {
    fields.get(name).ok_or(RuntimeError::InvalidReceipt)
}

fn read<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Result<T, RuntimeError> {
    T::deserialize(value).map_err(|_| RuntimeError::InvalidReceipt)
}

fn read_suffix_data(value: &serde_json::Value) -> Result<SuffixOnce17, RuntimeError> {
    if value.get("stage").and_then(serde_json::Value::as_str) != Some("verified") {
        return Err(RuntimeError::InvalidReceipt);
    }
    let suffix: SuffixOnce17 = read(value)?;
    // Value's enum deserializer also accepts external unit maps. Historical
    // evidence has exactly the defining writer's string/Position vocabulary.
    if serde_json::to_value(&suffix).map_err(|_| RuntimeError::InvalidReceipt)? != *value {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{Phase, Tick, U64};

    fn suffix() -> serde_json::Value {
        serde_json::to_value(SuffixOnce17 {
            stage: VerifiedSuffixStage17::Verified,
            restoration_proof: [1; 32],
            native_binding: [2; 32],
            observation_binding: [3; 32],
            reached: Position::new(Tick::new(4), U64::new(5), Phase::Reaction),
            signature: [6; 32],
        })
        .unwrap()
    }

    #[test]
    fn completed_suffix_has_one_closed_writer_vocabulary() {
        let original = suffix();
        assert!(read_suffix_data(&original).is_ok());

        let mut changed = original.clone();
        changed["stage"] = serde_json::json!({"verified": null});
        assert!(read_suffix_data(&changed).is_err());

        let mut changed = original.clone();
        changed["stage"] = serde_json::json!("signed");
        assert!(read_suffix_data(&changed).is_err());

        let mut changed = original.clone();
        changed["unexpected"] = serde_json::Value::Null;
        assert!(read_suffix_data(&changed).is_err());

        let mut changed = original;
        changed.as_object_mut().unwrap().remove("signature");
        assert!(read_suffix_data(&changed).is_err());
    }

    #[test]
    fn incomplete_transfer_and_world_uploads_are_not_completed_safe_points() {
        let mut transfer = TransferOnce17 {
            mapping_attempted: true,
            mapping_complete: true,
            prepare: TransferPhaseOnce17 {
                started: true,
                sealed: true,
                publishing_started: true,
                verified: true,
            },
            commit: TransferPhaseOnce17 {
                started: true,
                sealed: true,
                publishing_started: true,
                verified: true,
            },
            inputs_started: true,
            inputs_verified: true,
            failed: false,
        };
        assert!(transfer.authenticate_completed_data().is_ok());
        transfer.commit.verified = false;
        assert!(transfer.authenticate_completed_data().is_err());

        let mut activation = ActivationOnce17 {
            reserved: true,
            started: [true; 2],
            verified: [true; 2],
            failed: false,
            uploads_next: 2,
            upload_in_flight: false,
            upload_failed: false,
        };
        assert!(activation.authenticate_completed_data().is_ok());
        activation.upload_in_flight = true;
        assert!(activation.authenticate_completed_data().is_err());
    }
}
