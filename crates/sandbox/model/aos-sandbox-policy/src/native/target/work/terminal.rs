//! Rechecks the same held Policy publication at the original terminal frontiers.
//!
//! Native Authority lends the actual committed prefix and authenticated frame.
//! The Target keeps every reached native readback and model failure resident;
//! returning comparison DATA never supplies a publication or append capability.

use super::{RootPolicyPublicationWorkV1, RootPolicyPublicationErrorV1 as ErrorV1,
    RootPolicyReadbackObservationV1, RootOriginalInputLoanV1, RootCurrentOwnerLoanV1,
    RootCurrentInputVerifierV1, RootInputCurrentPurposeV1};
use crate::native::authority::{RootAuthorityQ04FlightOriginalV1, RootAuthorityCacheTerminalOutcomeV1};
use crate::q04_data::{Q04RootStageRecipeV1, Q04AcknowledgementKindV1, Q04PreholdInputDataV1};
use crate::signed_inputs::PolicyDeploymentInputsV1;
use aos_sandbox_model::{ObjectDigest, ResourceVector, ResourceDimension};

type PublicationData = (u64, ObjectDigest, ObjectDigest);

impl RootPolicyPublicationWorkV1<'_> {
    /// Copies the first strictly observed publication's comparison fields.
    #[must_use]
    pub fn original_publication_data_v1(&self) -> Option<PublicationData> {
        self.readback.as_ref()?.outcome.as_ref().ok()
            .map(|readback| (readback.sequence, readback.transaction, readback.current))
    }

    /// Observes the same native Target prefix without an earlier clock sample.
    ///
    /// The caller places its original Root/Origin bookends around this exact
    /// body. Every returned native result remains resident before those posts.
    ///
    /// # Errors
    /// Retains physical-name, native prefix, exact sequence and schema failures.
    pub fn observe_publication_body_once_v1(&mut self) -> Result<PublicationData, ()> {
        if self.failure_v1().is_some() { self.refuse_entry_v1(); return Err(()); }
        let admission = (|| -> Result<(), ErrorV1> {
            let controls = std::mem::size_of::<RootPolicyReadbackObservationV1>()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<PublicationData, ()>>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<PublicationData, ErrorV1>>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ErrorV1>>().checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), std::collections::TryReserveError>>().checked_mul(3)?))
                .ok_or(ErrorV1::Bounds)?;
            let backing = if self.repeated_readbacks.len() == self.repeated_readbacks.capacity() {
                self.repeated_readbacks.len().checked_add(1)
                    .and_then(|count| count.checked_mul(4))
                    .and_then(|count| count.checked_mul(std::mem::size_of::<RootPolicyReadbackObservationV1>()))
                    .ok_or(ErrorV1::Bounds)?
            } else { 0 };
            let bytes = controls.checked_add(backing).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ErrorV1::Bounds)?;
            self.target.journal.admit_role_observation_v1(ResourceVector::ZERO
                .with(ResourceDimension::MemoryBytes, bytes))?;
            // Reserve before entering native IO. The returned owning readback
            // then moves into resident custody without a later allocation.
            self.repeated_readbacks.try_reserve_exact(1)
                .map_err(crate::q04_data::PolicyQ04DataErrorV1::from)?;
            Ok(())
        })();
        if let Err(error) = admission { let _later = self.cause.set(error); return Err(()); }
        let mut names_failure = None;
        let outcome = self.read_policy_publication_body_v1(&mut names_failure);
        self.repeated_readbacks.push(RootPolicyReadbackObservationV1 { outcome, names_failure });
        match self.repeated_readbacks.last().and_then(|observation| observation.outcome.as_ref().ok()) {
            Some(readback) => Ok((readback.sequence, readback.transaction, readback.current)),
            None => Err(()),
        }
    }

    /// Repeats terminal Claim, ACK, signed-input and actual Cache joins in order.
    ///
    /// # Errors
    /// Retains the original Authority, Claim, source association, signature,
    /// provenance, native Cache or compiler-model failure on this same Work.
    #[allow(clippy::too_many_arguments)]
    pub fn require_terminal_input_current_v1(
        &self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        kind: Q04AcknowledgementKindV1,
        whole_ack_frame: &[u8],
        prehold_packet: &[u8],
        claim_packet: &[u8],
        observed_source_packet: &[u8],
        controller_packet: &[u8], source_packet: &[u8], cache_uid: u32,
        terminal_cache: Option<&RootAuthorityCacheTerminalOutcomeV1>,
    ) -> Result<(), ()> {
        if self.failure_v1().is_some() { self.refuse_entry_v1(); return Err(()); }
        let returned = (|| -> Result<(), ErrorV1> {
            self.admit_current_verifier_controls_v1()?;
            let cut = flight.borrow_q04_terminal_cut_v1(stage, kind, whole_ack_frame,
                controller_packet, source_packet)?;
            let gen1 = cut.gen1_v1();
            let history = cut.history_v1();
            let identity = history.identity();
            let claim = gen1.verify_claim(claim_packet, identity)?;
            let fields = claim.fields();
            if observed_source_packet != fields[11] { return Err(ErrorV1::ChangedCut); }
            let frames = match kind {
                Q04AcknowledgementKindV1::Policy => 9,
                Q04AcknowledgementKindV1::Release => 15,
                Q04AcknowledgementKindV1::Settlement => 20,
                Q04AcknowledgementKindV1::Clearance => 27,
            };
            let prehold = Q04PreholdInputDataV1::decode(prehold_packet)?;
            let metadata = prehold.fields()[0];
            let original_next = u64::from_be_bytes(crate::q04_data::fixed(metadata, 464));
            let original_names = aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)
                .map_err(crate::native::PolicyNativeJournalErrorV1::from)?;
            let acknowledgement = cut.acknowledgement_v1()?;
            let packet = acknowledgement.bytes();
            if acknowledgement.controller_sequence() != original_next.checked_add(frames).ok_or(ErrorV1::Bounds)?
                || packet[280..312] != *history.consumed_gate_data_v1()
                    .ok_or(ErrorV1::ChangedCut)?.digest().as_bytes()
            { return Err(ErrorV1::ChangedCut); }
            let (controller, held) = gen1.original_controller_provenance(fields[9], fields[10],
                fields[8], stage, identity, original_next)?;
            let original = RootOriginalInputLoanV1::new(self.target, gen1,
                &self.cause, &self.postcheck_debt, &self.target_post_failure, &self.secondary_panic)?;
            let inputs = PolicyDeploymentInputsV1 {
                node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
            };
            let (project, deployment_head, _) = gen1.signed_project_sources(fields[7], &inputs,
                original.recheck_cut_v1(identity).map_err(|()| ErrorV1::ChangedCut)?.wall_seconds())?;
            let cache = if terminal_cache.is_some() {
                gen1.original_cache_provenance(fields[12], fields[8], stage, identity, cache_uid)?
            } else {
                gen1.cache_cut(fields[12], fields[8], stage, identity, cache_uid)?
            };
            cut.require_original_lower_recipe_v1(metadata, fields, &acknowledgement,
                controller, held, cache, terminal_cache)?;
            let purpose = match terminal_cache {
                Some(outcome) => RootInputCurrentPurposeV1::TerminalReleased {
                    identity, held, held_packet: fields[10], cache_packet: fields[12], cache,
                    cache_uid, kind, acknowledgement: packet, original_next, original_names,
                    observed: outcome.readback_v1().ok_or(ErrorV1::ChangedCut)?,
                },
                None => RootInputCurrentPurposeV1::TerminalHeld {
                    identity, held, held_packet: fields[10], cache_packet: fields[12], cache,
                    cache_uid, kind, acknowledgement: packet, original_next, original_names,
                },
            };
            let current = RootCurrentInputVerifierV1 {
                original: RootCurrentOwnerLoanV1::Input(original), gen1, stage,
                controller, project: &project, deployment_head, project_input: fields[7],
                deployment_inputs: inputs, controller_packet: fields[9], proposed: fields[8], purpose,
            };
            current.recheck()
        })();
        match returned {
            Ok(()) => Ok(()),
            Err(error) => { let _later = self.cause.set(error); Err(()) }
        }
    }
}
