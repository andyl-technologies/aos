//! Replays the original signer-pin and deployment-head admission bodies.

use super::super::RootStartupJournalOriginalV1;
use super::binding::ensure_root_binding_unheld_v1;
use super::{
    RootStartupCredentialErrorV1 as ErrorV1, RootStartupCredentialWriterV1, StartupSignerPinsV1,
};
use crate::journal_keys::{HEAD_KEY, SIGNER_PINS_KEY};
use crate::signed_inputs::{
    PolicyDeploymentHeadV1, RootPolicyStartupDeploymentV1,
    verify_historical_policy_deployment_packet_v1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

const SIGNER_PINS_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-signer-pins-transaction.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-head-transaction.v1\0";

impl RootStartupCredentialWriterV1<'_> {
    /// Admits both exact verifier pins through this same fixed startup writer.
    ///
    /// # Errors
    /// Preserves malformed generations, held or changed state, and native refusals.
    pub fn admit_signer_pins(
        &mut self,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        self.journal.journal_mut_v1()?;
        self.journal.admit_signer_pins_after_entry_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            self.original.as_ref(),
        )?;
        self.journal.signer_pins = Some(StartupSignerPinsV1 {
            deployment_generation,
            deployment_key: *deployment_key,
            project_generation,
            project_key: *project_key,
        });
        Ok(())
    }

    /// Admits the exact packet whose source model this token already verified.
    ///
    /// # Errors
    /// Preserves signer association, hold, head succession, append and readback errors.
    pub fn admit_deployment_head(
        &mut self,
        deployment: RootPolicyStartupDeploymentV1<'_>,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        let pins = self.admitted_signer_pins_v1()?;
        if deployment.key != &pins.deployment_key
            || deployment.signer_generation != pins.deployment_generation
        {
            return Err(ErrorV1::StaleHead);
        }
        self.journal.journal_mut_v1()?;
        let packet = deployment.packet;
        let verified = deployment.head;
        let verifying_key = deployment.key;

        self.journal.admit_deployment_head_after_entry_v1(
            packet,
            verified,
            verifying_key,
            self.original.as_ref(),
        )
    }
}

pub(super) fn encode_signer_pins_v1(
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<Vec<u8>, ErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::encode_policy_signer_pins_v1(
        deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(|error| match error {
        aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::InvalidHead => ErrorV1::InvalidHead,
        aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::StaleHead => ErrorV1::StaleHead,
    })
}

fn read_u64_v1(bytes: &[u8], offset: usize) -> Result<u64, ErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::read_u64(bytes, offset)
        .map_err(|error| match error {
            aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::InvalidHead => ErrorV1::InvalidHead,
            aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::StaleHead => ErrorV1::StaleHead,
        })
}

impl RootStartupJournalOriginalV1 {
    pub(in crate::native::startup) fn admit_signer_pins_after_entry_v1(
        &mut self,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
        original: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), ErrorV1> {
        let encoded = encode_signer_pins_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        )?;

        let mut authority = self.credential_authority_after_entry_v1(original)?;
        ensure_root_binding_unheld_v1(&authority).map_err(|_| ErrorV1::StaleHead)?;
        match authority.get(SIGNER_PINS_KEY)? {
            Some(current) if current == encoded.as_slice() => return Ok(()),
            Some(_) => return Err(ErrorV1::StaleHead),
            None => {}
        }
        if !authority.is_materialized_empty()? {
            return Err(ErrorV1::StaleHead);
        }

        let digest = Sha256::new()
            .chain_update(SIGNER_PINS_TRANSACTION_DOMAIN)
            .chain_update(&encoded)
            .finalize();
        let transaction_id: [u8; 16] = digest[..16].try_into().map_err(|_| ErrorV1::InvalidHead)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                SIGNER_PINS_KEY.to_vec(),
                encoded.clone(),
            )],
        )?;
        authority.commit(&transaction)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(encoded.as_slice()) {
            return Err(ErrorV1::StaleHead);
        }
        Ok(())
    }

    pub(in crate::native::startup) fn admit_deployment_head_after_entry_v1(
        &mut self,
        packet: &[u8],
        verified: PolicyDeploymentHeadV1,
        verifying_key: &VerifyingKey,
        original: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        let mut authority = self.credential_authority_after_entry_v1(original)?;
        ensure_root_binding_unheld_v1(&authority).map_err(|_| ErrorV1::StaleHead)?;

        let existing = authority.get(HEAD_KEY)?;
        if existing == Some(packet) {
            return Ok(verified);
        }
        let predecessor_generation = existing
            .map(|current| {
                verify_historical_policy_deployment_packet_v1(current, verifying_key)
                    .map_err(ErrorV1::from)?;
                read_u64_v1(current, 8)
            })
            .transpose()?
            .unwrap_or(0);
        if predecessor_generation.checked_add(1) != Some(verified.generation()) {
            return Err(ErrorV1::StaleHead);
        }

        let transaction_digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(packet)
            .finalize();
        let transaction_id: [u8; 16] = transaction_digest[..16]
            .try_into()
            .map_err(|_| ErrorV1::InvalidHead)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                HEAD_KEY.to_vec(),
                packet.to_vec(),
            )],
        )?;
        authority.commit(&transaction)?;
        if authority.get(HEAD_KEY)? != Some(packet) {
            return Err(ErrorV1::StaleHead);
        }
        Ok(verified)
    }
}
