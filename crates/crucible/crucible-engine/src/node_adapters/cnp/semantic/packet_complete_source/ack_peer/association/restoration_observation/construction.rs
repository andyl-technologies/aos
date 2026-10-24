//! Counts independent Source signing, evidence and scheduling before Prepare.

use super::*;

impl PacketCompleteSemanticSource {
    /// Quotes the complete independent once-observation Source graph.
    ///
    /// This borrowed visitor creates no future request, scope proof, World,
    /// native model or claim. Source generation and both node copies receive
    /// distinct requested extents under the same original installed policy.
    ///
    /// # Errors
    /// Refuses another Source/Controller/target, absent registered mechanism,
    /// used observation, malformed originals or checked construction exhaustion.
    pub(crate) fn original_restoration_observation_source_construction_data(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningConstructionInputs<'_>,
        maximum: usize,
    ) -> Result<OriginalSourceRestorationObservationConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_restoration_observation_declaration_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let fixed =
            Self::original_restoration_observation_source_construction_counter_scratch_data();
        if fixed > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        if !std::ptr::eq(self, inputs.activation.transfer.source.as_ref()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let transfer = inputs.activation.transfer;
        let controller = transfer.controller;
        inputs
            .activation_source
            .authenticate_original(self, controller)?;
        transfer.ticket.authenticate_source(transfer.archive)?;
        if inputs
            .request_id
            .as_str()
            .strip_prefix("cnp-restoration-observe-")
            != Some(transfer.activation.activation_id.as_str())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let target = controller
            .original_installed_restoration_activation_target_binding_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let installation = self.installation();
        if target.owner_binding != &installation.owner
            || target.node != &installation.binding.compatibility.node_id
            || target.owner != &installation.owner.owner.id
            || target.admission != &installation.admission
            || target.transaction != &installation.transaction
            || target.gate != &installation.gate
            || target.world != &installation.world_binding_hash
            || target.world != &transfer.activation.world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        if original.restoration_observation.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transfer
            .query
            .authenticate_original_source_context_data(controller, emitter, &installation.owner)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let frame = usize::try_from(controller.authority().limits().frame_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let shapes = projection::measure(inputs, &target, maximum)?;
        let scheduling = scheduling::quote(self, inputs, maximum)?;
        let node_scheduling_copies = sum([scheduling, scheduling], maximum)?;
        let retained = sum(
            [
                OriginalSourceRestorationObservationAttempt::minimum_bank_bytes(frame)?,
                shapes.request.backing,
                shapes.artifact.backing,
                shapes.assigned.backing,
                shapes.terminal.backing,
                inputs
                    .observation_data
                    .source_evidence_retained_requested_bytes_data(),
                scheduling,
                node_scheduling_copies,
            ],
            maximum,
        )?;
        // Each old World inspection is a NEW independent validation extent.
        // Its earlier admitted credit remains spent on the earlier graph; it
        // cannot pay for this observation or these additional returned owners.
        let transient = sum(
            [
                shapes.phase_work(maximum)?,
                inputs
                    .observation_data
                    .source_evidence_maximum_simultaneous_transient_bytes_data(),
                inputs.activation_source.requested_peak_bytes_data(),
                inputs.activation_source.requested_peak_bytes_data(),
                scheduling,
                crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::
                    OriginalInitialLifecycleDiagnostics::requested_bytes(),
                original
                    .native
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_fresh_current_storage_data()?,
            ],
            maximum
        )?;
        let scratch = sum(
            [
                fixed,
                inputs
                    .observation_data
                    .source_evidence_counter_scratch_bytes_data(),
            ],
            maximum,
        )?;
        let requested = sum([retained, transient, scratch], maximum)?;
        transfer
            .query
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(OriginalSourceRestorationObservationConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            provider: *inputs.observation_data,
            activation: *inputs.activation_source,
            request_id: *blake3::hash(inputs.request_id.as_str().as_bytes()).as_bytes(),
            retained,
            transient,
            scratch,
            requested,
            maximum,
            frame,
            scheduling,
            node_scheduling_copies,
        })
    }

    /// Names the independently admitted observation counter and read-fence views.
    pub(crate) fn original_restoration_observation_source_construction_counter_scratch_data()
    -> usize {
        let claim = match OriginalInstalledRestorationObservationClaim::counter_scratch_data() {
            Ok(bytes) => bytes,
            Err(_) => return usize::MAX,
        };
        let terms = [
            Self::original_restoration_activation_source_construction_counter_scratch_data(),
            Self::original_restoration_observation_declaration_counter_scratch_data(),
            CnpController::original_installed_restoration_observation_counter_scratch_data(),
            original_installed_restoration_observation_construction_counter_scratch_data(),
            claim,
            restoration_activation_retained_native_evidence_counter_scratch_data(),
            construction_data::counter_scratch_data() + projection::counter_scratch_data(),
            owner::counter_scratch_data() + scheduling::counter_scratch_data(),
            size_of::<OriginalInstalledRestorationObservationSigningConstructionInputs<'static>>(),
            size_of::<OriginalInstalledRestorationObservationSigningInputs<'static>>(),
            size_of::<OriginalSourceRestorationObservationConstructionData>(),
            size_of::<Result<OriginalSourceRestorationObservationConstructionData, RuntimeError>>(),
            size_of::<OriginalSourceRestorationObservationVerifiedPhase<'static>>(),
            size_of::<
                Result<OriginalSourceRestorationObservationVerifiedPhase<'static>, RuntimeError>,
            >(),
            size_of::<PacketRestorationObservationRequest>()
                + size_of::<PacketRestorationObservationContext>(),
            size_of::<PacketRestorationObservationArtifact>()
                + size_of::<PacketRestorationObservationProof>(),
            size_of::<(
                PacketRestorationObservationRequest,
                Id,
                OriginalInstalledRestorationObservationConstructionData,
            )>(),
            size_of::<
                Option<(
                    PacketRestorationObservationRequest,
                    Id,
                    OriginalInstalledRestorationObservationConstructionData,
                )>,
            >(),
            size_of::<
                Result<
                    (
                        PacketRestorationObservationRequest,
                        Id,
                        OriginalInstalledRestorationObservationConstructionData,
                    ),
                    RuntimeError,
                >,
            >(),
            size_of::<Result<PacketRestorationObservationRequest, serde_json::Error>>(),
            size_of::<Result<PacketRestorationObservationArtifact, serde_json::Error>>(),
            size_of::<Result<serde_json::Value, serde_json::Error>>(),
            size_of::<
                Result<PacketRestorationObservationProof, crucible_node_transport::ProviderError>,
            >(),
            size_of::<Result<PacketNativeRestoredRecord, serde_json::Error>>(),
            size_of::<[usize; 8]>() + size_of::<std::array::IntoIter<usize, 8>>(),
            size_of::<[usize; 7]>() + size_of::<std::array::IntoIter<usize, 7>>(),
            size_of::<[usize; 6]>() + size_of::<std::array::IntoIter<usize, 6>>(),
            size_of::<[usize; 3]>() + size_of::<std::array::IntoIter<usize, 3>>(),
            size_of::<[usize; 2]>() + size_of::<std::array::IntoIter<usize, 2>>(),
            evidence::counter_scratch_data(),
            size_of::<[usize; 32]>(),
            size_of::<std::array::IntoIter<usize, 32>>(),
        ];
        terms
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .unwrap_or(usize::MAX)
    }
}

impl projection::SigningShapes {
    fn phase_work(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let create_proof = sum(
            [
                self.request.serialization,
                self.context.serialization,
                self.context.serialization,
                size_of::<PacketRestorationObservationProof>(),
                "source-owned.packet-restoration-observe-proof/1".len(),
                "blake3-256-mac".len(),
                32,
            ],
            maximum,
        )?;
        let saved_pair = sum(
            [
                self.assigned.serialization,
                self.terminal.serialization,
                self.artifact
                    .decode::<PacketRestorationObservationArtifact>(maximum)?,
                self.request
                    .decode::<PacketRestorationObservationRequest>(maximum)?,
                self.context.serialization,
                create_proof,
                32,
            ],
            maximum,
        )?;
        sum(
            [
                self.scope.serialization,
                self.request.serialization,
                self.request
                    .decode::<PacketRestorationObservationRequest>(maximum)?,
                create_proof,
                self.artifact.serialization,
                self.assigned.serialization,
                self.terminal.serialization,
                saved_pair,
            ],
            maximum,
        )
    }
}
