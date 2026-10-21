//! Repeats the original Q04 signed-purpose joins under the real gen1 borrower.
//!
//! Canonical packet codecs live in Policy/Protocol. These native methods add
//! the actual same-flight nonce, independent pins, current floor and native
//! Cache readback; no signature or DATA model can create this role borrower.

use super::error::RootAuthorityErrorV1;
use super::gen1::RootAuthorityGen1LoanV1;
use super::gen1::RootAuthorityGen1OwnerLoanV1;
use crate::controller_project_readback::VerifiedControllerProjectAdmissionV1;
use crate::q04_data::{
    ClosedPolicyRootBindingV2, PolicyQ04DataErrorV1, Q04AcknowledgementKindV1,
    Q04AcknowledgementV1, Q04ClaimV1, Q04PreholdInputDataV1, Q04RootStageRecipeV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

#[derive(Clone, Copy)]
enum Q04ControllerPacketPositionV1 {
    CurrentHeld,
    OriginalHeld { original_next: u64 },
}

impl<'owner, 'origin, 'startup> RootAuthorityGen1OwnerLoanV1<'owner, 'origin, 'startup> {
    fn q04_verify_prehold_input<'packet>(
        &self,
        packet: &'packet [u8],
        stage: &Q04RootStageRecipeV1,
        gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
    ) -> Result<
        (
            Q04PreholdInputDataV1<'packet>,
            VerifiedControllerProjectAdmissionV1,
        ),
        RootAuthorityErrorV1,
    > {
        use aos_sandbox_protocol::domain_ledger::project_source::{
            HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
        };

        self.recheck()?;
        gen1.recheck()?;
        if !gen1.current.owner.same_owner_v1(self)
            || stage.staged().challenge() != self.nonce_data_v1()?
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        // The distinct whole-row DATA signature is verified before any
        // projection. It cannot replace CTP03's purpose or current gen1.
        let request = Q04PreholdInputDataV1::verify(packet, self.pins.controller()?)?;
        let fields = request.fields();
        let metadata = fields[0];
        let challenge =
            crate::q04_data::staged_closed_policy_signer_challenge_v2(stage.staged(), fields[4])?;
        let controller =
            crate::controller_project_readback::verify_controller_project_admission_readback_v1(
                fields[5],
                self.pins.controller()?,
                crate::controller_project_readback::ControllerProjectAdmissionChallengeV1::new(
                    challenge.nonce(),
                    challenge.cut(),
                )?,
                self.identities[0],
            )?;
        let accepted = self.accepted;
        let names = ProtectedJournalNamesV1::from_bytes(&metadata[176..224]).map_err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
        )?;
        let source_names = ProtectedJournalNamesV1::from_bytes(&metadata[224..272]).map_err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
        )?;
        let sequence = u64::from_be_bytes(aos_sandbox_ledger_replay::data::take(metadata, 464)?);
        let source_sequence =
            u64::from_be_bytes(aos_sandbox_ledger_replay::data::take(metadata, 472)?);
        if !accepted.completed
            || controller.project() != gen1.floor().project()
            || controller.project() != stage.project()
            || controller.journal_sequence() != gen1.controller_sequence
            || sequence != gen1.controller_sequence
            || names != gen1.controller_names
            || source_names != accepted.source_names
            || source_sequence != accepted.source_sequence
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }

        let proposal = ClosedPolicyRootBindingV2::q04_decode(fields[4])?;
        let source = controller.source_commitment();
        let view = proposal.q04_fields(&source);
        let expected_source = create_project_source_commitment_v1(
            *view.operation,
            *view.operation_revision,
            *view.accepted_generation,
            *view.sandbox,
            *view.project,
            HistoricalCreateProjectSourceHeadsV1::from_historical_fields(
                *view.projection_revision,
                controller.publisher_generation(),
                controller.publisher_digest(),
                controller.cache_domain_head(),
                controller.revocation_scope(),
                controller.revocation_generation(),
                controller.revocation_head(),
            ),
        );
        if *view.operation != controller.operation()
            || *view.sandbox != controller.sandbox()
            || *view.project != controller.project()
            || *view.accepted_generation != 1
            || *view.publisher_generation != controller.publisher_generation()
            || *view.publisher_head != controller.publisher_digest()
            || *view.cache_domain_head != controller.cache_domain_head()
            || *view.revocation_head != controller.revocation_head()
            || *view.ancestry != gen1.floor().tree_head()
            || expected_source != controller.source_commitment()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        gen1.recheck()?;
        self.recheck()?;
        Ok((request, controller))
    }

    // Verification lends only the actual independent Root pin. The complete
    // packet remains in its original flight owner's buffer and success is DATA,
    // not a detachable currentness or writer capability.
    fn q04_verify_claim<'packet>(
        &self,
        packet: &'packet [u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Q04ClaimV1<'packet>, RootAuthorityErrorV1> {
        self.recheck()?;
        if identity.nonce() != self.nonce_data_v1()?
            || identity.controller_uid() != self.identities[0]
            || identity.bytes()[84..88] != self.identities[2].to_be_bytes()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        let claim = Q04ClaimV1::verify(packet, self.pins.controller()?, identity)?;
        self.recheck()?;
        Ok(claim)
    }

    // The two real Controller-purpose packets share the Root-created nonce
    // and actual Stage cut. The old current signer is never called under a
    // hold: its prehold packet is retained and joined to the fresh held packet.
    fn q04_verify_controller_cut(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<
        (
            VerifiedControllerProjectAdmissionV1,
            crate::controller_readback::VerifiedControllerHoldReadbackV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.q04_verify_controller_cut_for(
            current_packet,
            held_packet,
            proposed,
            gen1,
            stage,
            identity,
            Q04ControllerPacketPositionV1::CurrentHeld,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn q04_verify_controller_cut_for(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        gen1: &RootAuthorityGen1LoanV1<'_, 'origin, 'startup>,
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        position: Q04ControllerPacketPositionV1,
    ) -> Result<
        (
            VerifiedControllerProjectAdmissionV1,
            crate::controller_readback::VerifiedControllerHoldReadbackV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        gen1.recheck()?;
        if !gen1.current.owner.same_owner_v1(self)
            || gen1.floor().digest() != identity.gen1_floor()
            || stage.staged().challenge() != self.nonce_data_v1()?
            || identity.nonce() != self.nonce_data_v1()?
            || identity.controller_uid() != self.identities[0]
            || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || crate::q04_data::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        // Stage's record cut authenticates its original reservation. The
        // Controller/Cache signer cut additionally binds the complete B664;
        // derive it once through the existing sole challenge recipe.
        let challenge =
            crate::q04_data::staged_closed_policy_signer_challenge_v2(stage.staged(), proposed)?;
        let current =
            crate::controller_project_readback::verify_controller_project_admission_readback_v1(
                current_packet,
                self.pins.controller()?,
                crate::controller_project_readback::ControllerProjectAdmissionChallengeV1::new(
                    challenge.nonce(),
                    challenge.cut(),
                )?,
                self.identities[0],
            )?;
        let held = crate::controller_readback::verify_controller_hold_readback_v1(
            held_packet,
            self.pins.controller()?,
            crate::controller_readback::ControllerHoldReadbackChallengeV1::new(
                challenge.nonce(),
                challenge.cut(),
            )?,
            self.identities[0],
        )?;
        let accepted = self.accepted;
        if !accepted.completed
            || accepted.acceptance.project() != current.project()
            || current.project() != identity.project()
            || current.operation() != identity.operation()
            || current.sandbox() != identity.sandbox()
            || held.operation() != current.operation()
            || held.sandbox() != current.sandbox()
            || held.source() != current.source_commitment()
            || current.journal_sequence() > held.journal_sequence()
            || held.binding() != identity.binding()
            || held.epoch() != identity.epoch()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        match position {
            Q04ControllerPacketPositionV1::CurrentHeld => {
                if held.journal_sequence() != gen1.controller_sequence {
                    return Err(PolicyQ04DataErrorV1::ChangedCut.into());
                }
            }
            Q04ControllerPacketPositionV1::OriginalHeld { original_next } => {
                // The independently signed original sequence selects only
                // the closed legacy 3/9-member or provenance 10-member family.
                // Controller separately proves native whole membership; this
                // Root join observes signed DATA, never payment or consumption.
                let frames = held
                    .journal_sequence()
                    .checked_sub(original_next)
                    .ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
                let resource = accepted.acceptance.resource_envelope().is_some();
                if !matches!((resource, frames), (false, 5) | (true, 11 | 12)) {
                    return Err(PolicyQ04DataErrorV1::ChangedCut.into());
                }
                if current.journal_sequence() != original_next
                    || held.journal_sequence()
                        != original_next
                            .checked_add(frames)
                            .ok_or(PolicyQ04DataErrorV1::Bounds)?
                    || held.journal_sequence() >= gen1.controller_sequence
                {
                    return Err(PolicyQ04DataErrorV1::ChangedCut.into());
                }
            }
        }
        gen1.recheck()?;
        self.recheck()?;
        Ok((current, held))
    }

    // This uses the actual Root-retained Cache pin and the unchanged fixed
    // read-only replay engine. It does not invent a spent V8 challenge or a
    // physical writer lease; the original Q04 caller retains those writers.
    fn q04_verify_cache_cut(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
        RootAuthorityErrorV1,
    > {
        use crate::journal_keys::CACHE_PIN_KEY;

        self.recheck()?;
        if identity.nonce() != self.nonce_data_v1()?
            || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || crate::q04_data::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        let credential = self
            .journal
            .get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
        let before = aos_sandbox_cache::replay_fixed_root_read_only_cache_policy_hold_v1()?;
        let observed =
            self.q04_verify_original_cache_packet(packet, proposed, stage, identity, cache_uid)?;
        if observed.hold() != before.hold || observed.quota_digest() != before.replay.quota_digest {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }

        self.recheck()?;
        let after = aos_sandbox_cache::replay_fixed_root_read_only_cache_policy_hold_v1()?;
        if before != after
            || self
                .journal
                .get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
                != Some(credential)
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.recheck()?;
        Ok(observed)
    }

    // This authenticates only the original Cache packet. Terminal consumers
    // separately replay its actual fixed four-journal Q04 released/clear cut;
    // the old held bytes can never stand in for a current Cache observation.
    fn q04_verify_original_cache_packet(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
        RootAuthorityErrorV1,
    > {
        use crate::journal_keys::CACHE_PIN_KEY;

        self.recheck()?;
        if cache_uid == 0
            || identity.controller_uid() != self.identities[0]
            || identity.nonce() != self.nonce_data_v1()?
            || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || crate::q04_data::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        let pin = self
            .journal
            .get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
        let signer =
            aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1::decode(
                pin,
            )?;
        let challenge =
            crate::q04_data::staged_closed_policy_signer_challenge_v2(stage.staged(), proposed)?;
        // The signed physical root belongs to the actual Controller. The
        // separate Cache-view UID still governs named journal/idmap checks.
        let observed =
            aos_sandbox_protocol::cache_owner_readback::verify_closed_cache_owner_readback_v2(
                packet,
                &signer,
                aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackChallengeV1::new(
                    challenge.nonce(),
                    challenge.cut(),
                )?,
                self.identities[0],
            )?;
        if !observed.hold().is_held()
            || observed.hold().project() != identity.project()
            || observed.hold().binding() != identity.binding()
            || observed.hold().epoch() != identity.epoch()
            || observed.quota_digest() != identity.cache_quota()
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.recheck()?;
        Ok(observed)
    }

    pub(super) fn q04_signed_project_sources(
        &self,
        project_input: &[u8],
        deployment_inputs: &crate::signed_inputs::PolicyDeploymentInputsV1<'_>,
        now_unix_seconds: i64,
    ) -> Result<
        (
            crate::signed_inputs::VerifiedSignedProjectPolicySourceV2,
            crate::signed_inputs::PolicyDeploymentHeadV1,
            crate::signed_inputs::PolicyDeploymentSourcesV1,
        ),
        RootAuthorityErrorV1,
    > {
        use aos_sandbox_ledger_replay::replay::root_genesis_pins::{
            PolicySignerPinsDataErrorV1, decode_policy_signer_pins_v1,
        };

        self.recheck()?;
        let journal = &self.journal;
        crate::verify_held_root_signed_sources_data_v1! {
            journal: journal,
            project_input: project_input,
            deployment_inputs: deployment_inputs,
            now: now_unix_seconds,
            outputs: (project, deployment, decoded),
            changed_cut: PolicyQ04DataErrorV1::ChangedCut,
            changed_projection: [.into()],
            decode_pins: pins => {
                decode_policy_signer_pins_v1(pins).map_err(|cause| match cause {
                    PolicySignerPinsDataErrorV1::InvalidHead => {
                        crate::signed_inputs::SignedPolicyInputDataErrorV1::InvalidHead
                    }
                    PolicySignerPinsDataErrorV1::StaleHead => {
                        crate::signed_inputs::SignedPolicyInputDataErrorV1::StaleHead
                    }
                })?
            },
            signed_projection: [],
            before_deployment: {
                let deployment_bytes = crate::signed_inputs::deployment_sources_decoding_bytes_v1()
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
                journal.admit_role_observation_v1(aos_sandbox_model::ResourceVector::ZERO.with(
                    aos_sandbox_model::ResourceDimension::MemoryBytes,
                    deployment_bytes,
                ))?;
            },
            before_project: project_packet => {
                let project_bytes = crate::signed_inputs::project_source_verification_receiving_bytes_v2(
                    project_packet.len(),
                    project_input.len(),
                )
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
                journal.admit_role_observation_v1(aos_sandbox_model::ResourceVector::ZERO.with(
                    aos_sandbox_model::ResourceDimension::MemoryBytes,
                    project_bytes,
                ))?;
            },
        }
        self.recheck()?;
        Ok((project, deployment, decoded))
    }
}

impl RootAuthorityGen1LoanV1<'_, '_, '_> {
    // The actual Root pin verifies this distinct Q04 packet. Its sequence is
    // compared to a fresh completed gen1 observation under the same original
    // nonce; an old held signature is never treated as current after a write.
    /// Verifies the actual Controller ACK against this current completed floor.
    ///
    /// # Errors
    /// Refuses a changed original nonce, UID, sequence, physical names or floor,
    /// or preserves the original canonical signature or currentness failure.
    pub fn acknowledgement<'packet>(
        &self,
        kind: Q04AcknowledgementKindV1,
        packet: &'packet [u8],
        identity: &Q04CutIdentityV1,
        original_controller_names: ProtectedJournalNamesV1,
    ) -> Result<Q04AcknowledgementV1<'packet>, RootAuthorityErrorV1> {
        self.recheck()?;
        self.current.owner.recheck()?;
        let packet = Q04AcknowledgementV1::verify(
            kind,
            packet,
            self.current.owner.pins.controller()?,
            identity,
        )?;
        if identity.nonce() != self.current.owner.nonce_data_v1()?
            || identity.controller_uid() != self.current.owner.identities[0]
            || identity.bytes()[84..88] != self.current.owner.identities[2].to_be_bytes()
            || self.floor().digest() != identity.gen1_floor()
            || self.floor().project() != identity.project()
            || packet.controller_sequence() != self.controller_sequence
            || self.controller_names != original_controller_names
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.recheck()?;
        self.current.owner.recheck()?;
        Ok(packet)
    }

    // Signature provenance and original named/sequence equality are separate
    // from any held proof. This read-only prehold purpose never issues a Stage
    // or permits publication; the original Root flight retains all packets.
    /// Verifies the original nonissuing prehold input under this genuine floor.
    ///
    /// # Errors
    /// Refuses substituted metadata, source coordinates, proposed binding or
    /// project provenance, retaining the actual canonical or native cause.
    pub fn prehold_input<'packet>(
        &self,
        packet: &'packet [u8],
        stage: &Q04RootStageRecipeV1,
    ) -> Result<
        (
            Q04PreholdInputDataV1<'packet>,
            VerifiedControllerProjectAdmissionV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        let checked = self
            .current
            .owner
            .q04_verify_prehold_input(packet, stage, self)?;
        self.recheck()?;
        Ok(checked)
    }

    /// Verifies a complete Claim under this actual independent Controller pin.
    ///
    /// # Errors
    /// Refuses a different original nonce or UID, malformed Claim or signature,
    /// or changed native floor custody.
    pub fn verify_claim<'packet>(
        &self,
        packet: &'packet [u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Q04ClaimV1<'packet>, RootAuthorityErrorV1> {
        self.recheck()?;
        let claim = self.current.owner.q04_verify_claim(packet, identity)?;
        self.recheck()?;
        Ok(claim)
    }

    /// Rejoins the current Controller pair to this same completed floor.
    ///
    /// # Errors
    /// Refuses changed original names, sequences, holds, project or binding,
    /// or preserves the canonical signature and native currentness cause.
    pub fn controller_cut(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<
        (
            VerifiedControllerProjectAdmissionV1,
            crate::controller_readback::VerifiedControllerHoldReadbackV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.current.owner.q04_verify_controller_cut(
            current_packet,
            held_packet,
            proposed,
            self,
            stage,
            identity,
        )
    }

    // This retains only signature provenance from the original prehold/C1
    // packets. The distinct current ACK above must establish the later live
    // Controller cut; this projection cannot replace that actual observation.
    /// Checks the retained original Controller pair beside its fresh later ACK.
    ///
    /// # Errors
    /// Refuses a foreign signed family or original sequence association, a
    /// different hold/binding, malformed signature or changed native custody.
    pub fn original_controller_provenance(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        original_next: u64,
    ) -> Result<
        (
            VerifiedControllerProjectAdmissionV1,
            crate::controller_readback::VerifiedControllerHoldReadbackV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.current.owner.q04_verify_controller_cut_for(
            current_packet,
            held_packet,
            proposed,
            self,
            stage,
            identity,
            Q04ControllerPacketPositionV1::OriginalHeld { original_next },
        )
    }

    /// Verifies the actual retained signed project and deployment input pair.
    ///
    /// # Errors
    /// Refuses changed retained inputs, signer generations or deployment
    /// association, or preserves the original signature/decoding failure.
    pub fn signed_project_sources(
        &self,
        project_input: &[u8],
        deployment_inputs: &crate::signed_inputs::PolicyDeploymentInputsV1<'_>,
        now_unix_seconds: i64,
    ) -> Result<
        (
            crate::signed_inputs::VerifiedSignedProjectPolicySourceV2,
            crate::signed_inputs::PolicyDeploymentHeadV1,
            crate::signed_inputs::PolicyDeploymentSourcesV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        let sources = self.current.owner.q04_signed_project_sources(
            project_input,
            deployment_inputs,
            now_unix_seconds,
        )?;
        self.recheck()?;
        Ok(sources)
    }

    /// Rejoins the signed Cache hold to the actual four-journal readonly cut.
    ///
    /// # Errors
    /// Preserves a failed real Cache replay, canonical signature or native
    /// currentness check and refuses mismatched holds, quota or saved pin.
    pub fn cache_cut(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        let cache = self
            .current
            .owner
            .q04_verify_cache_cut(packet, proposed, stage, identity, cache_uid)?;
        self.recheck()?;
        Ok(cache)
    }

    /// Verifies the retained original Cache signature under the actual Root pin.
    ///
    /// # Errors
    /// Refuses a foreign UID, nonce, proposal, hold, epoch or quota, or
    /// preserves the original canonical signature/currentness failure.
    pub fn original_cache_provenance(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &Q04RootStageRecipeV1,
        identity: &Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2,
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        let observed = self
            .current
            .owner
            .q04_verify_original_cache_packet(packet, proposed, stage, identity, cache_uid)?;
        self.recheck()?;
        Ok(observed)
    }
}
