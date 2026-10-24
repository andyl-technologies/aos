//! Joins genuine SDK pairs to retained native signed-lineage fields.

use super::*;
use crate::protocol_snapshot::{
    current_controller17::ValidatedHistoricalRestorationAssociation17,
    restored_settled17::historical_auth::{
        HistoricalAck17, HistoricalAckBindings17, HistoricalCommit17, HistoricalCompletedPair17,
        HistoricalPrepare17, HistoricalRestoration17,
    },
};
use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest;

impl NativeCurrentGraph17Data {
    /// Quotes private historical work using only already-retained shapes.
    ///
    /// No SDK pair reconstruction or historical MAC/serialization check runs
    /// here. The Controller's actual once tuples and this native graph's actual
    /// stage envelopes bound all later baseline body decoder allocations.
    ///
    /// # Errors
    /// Refuses incomplete immutable phases, shapes, checked overflow or budget.
    pub(crate) fn source_history17_authentication_geometry_data(
        &self,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        capture: &crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSettledCapture17,
        maximum: usize,
    ) -> Result<crate::protocol_snapshot::restored_settled17::historical_auth::construction::RestoredSettledSourceHistory17AuthGeometryData, ProviderError>{
        use crate::protocol_snapshot::restored_settled17::historical_auth::construction::{
            HistoricalAuth17Shapes, normalized_ack_window_data, source_history17_geometry_data,
            world_manifest_window_data,
        };
        self.validate_data()?;
        let boot = self.lineage.boot_data();
        let commit = self.lineage.commit_data();
        let bindings = HistoricalAckBindings17 {
            birth_association: boot
                .normalized_0
                .value_data()?
                .as_ref()
                .ok_or_else(invalid)?,
            kernel_binding: boot
                .normalized_1
                .value_data()?
                .as_ref()
                .ok_or_else(invalid)?,
            policy_binding: boot
                .normalized_2
                .value_data()?
                .as_ref()
                .ok_or_else(invalid)?,
            host_registration: boot.host_registration.value_data()?,
            native_registration: boot
                .normalized_3
                .value_data()?
                .as_ref()
                .ok_or_else(invalid)?,
            authority: &self.authority.data,
            controller_pid: *commit.controller_pid.value_data()?,
            controller_uid: *commit.controller_uid.value_data()?,
            controller_executable: commit.controller_executable.value_data()?,
            hello_request_literal: self.hello.request_data(),
            hello_response_literal: self.hello.response_data(),
        };
        let normalized = normalized_ack_window_data(&bindings, maximum)?;
        let mut shapes = HistoricalAuth17Shapes::default();
        shapes.include_controller_data(controller, maximum)?;
        let stages = self.restoration_stages17_data()?;
        for envelope in [
            stages.arm.original.as_ref(),
            stages.arm.terminal.as_ref(),
            stages.world.original.as_ref(),
            stages.world.terminal.as_ref(),
            stages.first_observation.original.as_ref(),
            stages.first_observation.terminal.as_ref(),
        ] {
            shapes.include_envelope_data(envelope.ok_or_else(invalid)?, maximum)?;
        }
        for (original, terminal, _) in [
            capture.capture_pair_data(),
            capture.confirmation_pair_data(),
        ] {
            shapes.include_envelope_data(original, maximum)?;
            shapes.include_envelope_data(terminal, maximum)?;
        }
        let manifest = world_manifest_window_data(
            stages.world.manifest.as_ref().ok_or_else(invalid)?,
            maximum,
        )?;
        // This is the exact defining ProgramHistory view used by the selected
        // model codec, not the separate content dictionary or original journal.
        let roots = self.raw_root_spans_data()?;
        let model =
            crate::connection::native17_borrowed_bytes::field(roots.control_data(), "program")?;
        let selector =
            crate::connection::native17_borrowed_bytes::field(roots.control_data(), "selection")?;
        source_history17_geometry_data(
            shapes,
            normalized,
            manifest,
            model.len(),
            selector.len(),
            maximum,
        )
    }

    /// Borrows the actual typed request retained by this graph's Prepare slot.
    ///
    /// No request is decoded from a current Source header or reconstructed from
    /// Commit fields. Source proofs and archive ancestry remain separate joins.
    ///
    /// # Errors
    /// Refuses an incomplete graph, unfinished typed slot or absent request.
    pub(crate) fn restoration_prepare_request_data(
        &self,
    ) -> Result<&PacketCompleteRestorePrepareRequest, ProviderError> {
        self.validate_data()?;
        Ok(&self
            .lineage
            .prepare_data()
            .request
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)?
            .0)
    }

    /// Returns the normalization limit from this exact archived reserve carrier.
    ///
    /// The same complete source-order walk retained this scalar from the Boot's
    /// selected17 carrier. A current launch or format ceiling cannot replace it.
    ///
    /// # Errors
    /// Refuses an incomplete graph or invalid retained carrier contract.
    pub(crate) fn archived_normalization_maximum_data(&self) -> Result<U64, ProviderError> {
        self.validate_data()?;
        self.lineage.reserve_carrier.validate_data()?;
        Ok(self.lineage.reserve_carrier.normalization_maximum)
    }

    /// Borrows required native lineage after exact association with real SDK pairs.
    ///
    /// The association owns the independently funded parsed SDK pair records.
    /// Each original also equals this native cache, and every terminal belongs
    /// to the actual complete native send history and current Control cache.
    /// This loan supplies neither ancestry nor a native token or allocation.
    ///
    /// # Errors
    /// Refuses missing signed fields, changed SDK/native originals or terminals,
    /// incomplete native send history, or absent required Hello/mapping evidence.
    pub(crate) fn historical_restoration17_data<'a>(
        &'a self,
        association: &'a ValidatedHistoricalRestorationAssociation17,
    ) -> Result<HistoricalRestoration17<'a>, ProviderError> {
        self.validate_data()?;
        let boot = self.lineage.boot_data();
        let prepare = self.lineage.prepare_data();
        let commit = self.lineage.commit_data();
        let (ack_original, ack_terminal) = association.ack_pair_data();
        let (prepare_original, prepare_terminal) = association.prepare_pair_data();
        let (commit_original, commit_terminal) = association.commit_pair_data();
        if boot.ack_original.value_data()?.as_ref() != Some(ack_original)
            || prepare.original.value_data()?.as_ref() != Some(prepare_original)
            || commit.original.value_data()?.as_ref() != Some(commit_original)
        {
            return Err(invalid());
        }
        for (original, terminal) in [
            (ack_original, ack_terminal),
            (prepare_original, prepare_terminal),
            (commit_original, commit_terminal),
        ] {
            original.matches_response(terminal)?;
            crate::reference_packet::endpoint::authenticate_native17_retained_terminal_data(
                self, original, terminal,
            )?;
        }
        Ok(HistoricalRestoration17 {
            ack: HistoricalAck17 {
                context: &boot
                    .ack_context
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                proof: &boot.ack_proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: ack_original,
                    terminal: ack_terminal,
                },
                selection: self.control.selection_data(),
                native_pid: U64::new(u64::from(self.creator)),
                bindings: HistoricalAckBindings17 {
                    birth_association: boot
                        .normalized_0
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    kernel_binding: boot
                        .normalized_1
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    policy_binding: boot
                        .normalized_2
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    host_registration: boot.host_registration.value_data()?,
                    native_registration: boot
                        .normalized_3
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    authority: &self.authority.data,
                    controller_pid: *commit.controller_pid.value_data()?,
                    controller_uid: *commit.controller_uid.value_data()?,
                    controller_executable: commit.controller_executable.value_data()?,
                    hello_request_literal: self.hello.request_data(),
                    hello_response_literal: self.hello.response_data(),
                },
            },
            prepare: HistoricalPrepare17 {
                request: &prepare
                    .request
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                context: &prepare
                    .context
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                proof: &prepare.proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: prepare_original,
                    terminal: prepare_terminal,
                },
            },
            commit: HistoricalCommit17 {
                request: &commit.request.value_data()?.as_ref().ok_or_else(invalid)?.0,
                context: &commit.context.value_data()?.as_ref().ok_or_else(invalid)?.0,
                proof: &commit.proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: commit_original,
                    terminal: commit_terminal,
                },
                held: &commit.hold.value_data()?.as_ref().ok_or_else(invalid)?.0,
            },
            canonical_mapping: self.normalization.bytes_data(),
            control: &self.control,
        })
    }
}
