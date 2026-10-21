//! Derives a nonissuing Stage from the actual held Authority and original gen1.
//!
//! The public Stage is canonical DATA. Only this native producer derives its
//! current signer/row identity, complete binding chain, saved prior and original
//! nonce, and enters the same semantic preflight before returning that DATA.

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_ledger_replay::replay::root_genesis_pins::encode_policy_signer_pins_v1;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::journal_keys::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_HEAD_KEY_V2, PROJECT_INPUT_KEY, PROJECT_INPUT_KEY_V2,
    SIGNER_PINS_KEY,
};
use crate::q04_data::{
    ClosedPolicyRootCasBaseV2, PolicyQ04DataErrorV1, Q04RootStageRecipeV1,
    RootPolicyBindingIdentityV2, STAGE_KEY,
};
use crate::signed_inputs::{PolicyDeploymentInputsV1, verify_signed_project_policy_source_v2};
use aos_sandbox_protocol::policy_data::binding_v2::{
    BINDING_V2_KEY_PREFIX, HOLD_KEY, MAXIMUM_POLICY_BINDINGS, current_hold_v1,
    current_root_binding_chain_v2, root_binding_chain_receiving_bytes_v2,
    root_policy_issuer_owner_v2,
};

use super::error::RootAuthorityErrorV1;
use super::q04::RootAuthorityQ04FlightOriginalV1;

impl RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    /// Derives the actual original flight's nonissuing Stage preview.
    ///
    /// # Errors
    /// Refuses a changed completed gen1 association, current signer or signed
    /// row mismatch, legacy project row, unresolved binding hold, reused nonce,
    /// exhausted generation or actual semantic preflight failure.
    // This keeps the existing privileged driver arguments. None installs a
    // native owner, nonce, public verifier or completed floor from DATA.
    #[allow(clippy::too_many_arguments)]
    pub fn q04_preview_stage(
        &mut self,
        source_packet: &[u8],
        expected_deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &VerifyingKey,
        project_packet: &[u8],
        project_input: &[u8],
        project_signer_generation: u64,
        project_key: &VerifyingKey,
        controller_gid: u32,
        now_unix_seconds: i64,
    ) -> Result<Q04RootStageRecipeV1, RootAuthorityErrorV1> {
        let project = {
            let current = self.current_anchored_floor_v1(source_packet)?;
            current.recheck()?;
            current.floor().project()
        };
        let invalid =
            || RootAuthorityErrorV1::Q04Data(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
        let identities = self.identities.ok_or_else(invalid)?;
        if identities[0] == 0 || controller_gid == 0 || controller_gid != identities[1] {
            return Err(invalid());
        }
        let project_bytes = crate::signed_inputs::project_source_verification_receiving_bytes_v2(
            project_packet.len(),
            project_input.len(),
        )
        .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        let controls = std::mem::size_of::<Q04RootStageRecipeV1>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes
                    .checked_add(std::mem::size_of::<RootPolicyBindingIdentityV2>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(project_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        self.authority.journal.admit_role_observation_v1(
            aos_sandbox_model::ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, controls),
        )?;
        let verified = verify_signed_project_policy_source_v2(
            project_packet,
            project_input,
            project_key,
            now_unix_seconds,
        )
        .map_err(|_| invalid())?;
        let head = verified.head();
        if head.deployment_signer_generation() != deployment_signer_generation
            || head.project_signer_generation() != project_signer_generation
        {
            return Err(invalid());
        }
        let pins = encode_policy_signer_pins_v1(
            deployment_signer_generation,
            deployment_key,
            project_signer_generation,
            project_key,
        )
        .map_err(|_| invalid())?;
        let namespace = RecordNamespace::DesiredState;
        let journal = &self.authority.journal;
        if journal.get(namespace, SIGNER_PINS_KEY) != Some(pins.as_slice())
            || journal.get(namespace, HEAD_KEY) != Some(expected_deployment_packet)
            || head.prerequisite_claims()[1].as_bytes()
                != Sha256::digest(expected_deployment_packet).as_slice()
        {
            return Err(invalid());
        }
        if journal.get(namespace, PROJECT_HEAD_KEY_V2) != Some(project_packet)
            || journal.get(namespace, PROJECT_INPUT_KEY_V2) != Some(project_input)
            || journal.get(namespace, PROJECT_HEAD_KEY).is_some()
            || journal.get(namespace, PROJECT_INPUT_KEY).is_some()
        {
            return Err(invalid());
        }
        let issuer_owner = root_policy_issuer_owner_v2(identities[0], controller_gid);
        let identity = RootPolicyBindingIdentityV2 {
            deployment_head: ObjectDigest::from_bytes(
                Sha256::digest(expected_deployment_packet).into(),
            ),
            project: head.project(),
            publisher_generation: head.publisher_generation(),
            publisher_head: head.publisher_digest(),
            project_policy_head: head.packet_digest(),
            project_policy_input: head.input_digest(),
            prerequisite_claims: head.prerequisite_claims(),
            deployment_signer_generation,
            project_signer_generation,
            issuer_owner,
        };
        let raw_binding_count = journal
            .records(namespace)
            .filter(|(key, _)| key.starts_with(BINDING_V2_KEY_PREFIX))
            .count();
        let chain_bytes = root_binding_chain_receiving_bytes_v2(raw_binding_count)
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(crate::native::PolicyNativeJournalErrorV1::geometry)?;
        journal.admit_role_observation_v1(aos_sandbox_model::ResourceVector::ZERO.with(
            aos_sandbox_model::ResourceDimension::MemoryBytes,
            chain_bytes,
        ))?;
        let (predecessor, next_generation, count) =
            current_root_binding_chain_v2(journal.records(namespace)).map_err(|_| invalid())?;
        if count >= MAXIMUM_POLICY_BINDINGS
            || current_hold_v1(
                journal.get(namespace, HOLD_KEY),
                predecessor,
                next_generation,
                count,
            )
            .map_err(|_| invalid())?
            .is_some_and(|hold| hold.held)
        {
            return Err(invalid());
        }
        // The original current_base performs the complete chain fold again.
        let (predecessor, next_generation, _) =
            current_root_binding_chain_v2(journal.records(namespace)).map_err(|_| invalid())?;
        let base = ClosedPolicyRootCasBaseV2 {
            issuer_owner: identity.issuer_owner,
            predecessor,
            next_generation,
            deployment_signer_generation: identity.deployment_signer_generation,
            project_signer_generation: identity.project_signer_generation,
        };
        let nonce = self.nonce_data_v1()?;
        let recipe = Q04RootStageRecipeV1::from_untrusted_fields_v1(
            identity.project,
            base,
            journal.get(namespace, STAGE_KEY),
            nonce,
            identity.stage_cut(base),
        )?;
        journal.preflight_q04_stage_v1(recipe.transaction())?;
        if recipe.project() != project || recipe.staged().challenge() != nonce {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.current_anchored_floor_v1(source_packet)?.recheck()?;
        Ok(recipe)
    }

    /// Encodes Preview DATA under this same held Authority and original cutoff.
    ///
    /// # Errors
    /// Refuses changed source/pin rows, a foreign Stage, expired signed input,
    /// original deadline overflow or changed complete native before-state.
    pub fn q04_encode_preview(
        &self,
        output: &mut Vec<u8>,
        stage: &Q04RootStageRecipeV1,
        inputs: &PolicyDeploymentInputsV1<'_>,
        project_input: &[u8],
        original_clock: aos_sandbox_model::RawPairedClockSample,
        now_unix_seconds: i64,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.authority.recheck()?;
        let (project, _, _) = self.gen1_owner_loan_v1()?.q04_signed_project_sources(
            project_input,
            inputs,
            now_unix_seconds,
        )?;
        let nonce = self.nonce_data_v1()?;
        let namespace = RecordNamespace::DesiredState;
        let journal = &self.authority.journal;
        if project.head().project() != stage.project()
            || stage.staged().challenge() != nonce
            || journal.get(namespace, PROJECT_INPUT_KEY_V2) != Some(project_input)
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        let (sequence, names, before_rows) = journal.q04_before_rows_v1()?;
        let deadline = original_clock
            .boottime_nanoseconds()
            .checked_add(65_000_000_000)
            .ok_or(PolicyQ04DataErrorV1::Bounds)?;
        let mut metadata = [0; 120];
        metadata[..16].copy_from_slice(&original_clock.host_boot_id());
        metadata[16..24].copy_from_slice(&original_clock.boottime_nanoseconds().to_be_bytes());
        metadata[24..32].copy_from_slice(&deadline.to_be_bytes());
        metadata[32..40].copy_from_slice(&sequence.to_be_bytes());
        metadata[40..88].copy_from_slice(&names.to_bytes());
        metadata[88..120].copy_from_slice(before_rows.as_bytes());
        let staged = stage.preview_fields();
        let deployment_packet = journal
            .get(namespace, HEAD_KEY)
            .ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
        let project_packet = journal
            .get(namespace, PROJECT_HEAD_KEY_V2)
            .ok_or(PolicyQ04DataErrorV1::ChangedCut)?;
        crate::q04_data::encode_q04_preview_body_v1(
            output,
            [
                &metadata,
                &staged,
                deployment_packet,
                inputs.node,
                inputs.site,
                inputs.backend,
                inputs.catalogs,
                project_packet,
                project_input,
            ],
            nonce,
        )?;
        self.authority.recheck()?;
        if journal.q04_before_rows_v1()? != (sequence, names, before_rows) {
            return Err(PolicyQ04DataErrorV1::ChangedCut.into());
        }
        Ok(())
    }
}
