//! Opens real ordinary files for tests of the sole credential admission bodies.
//!
//! This fixture has no selected lender, completed role, or journal adopter.
//! Its mutation methods invoke the same private admissions as production.

use std::path::Path;

use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalTransaction};
use ed25519_dalek::VerifyingKey;

use super::super::{
    RootStartupJournalErrorV1, RootStartupJournalOriginalV1, StartupJournalStorageV1,
};
use super::RootStartupCredentialErrorV1 as ErrorV1;
use crate::signed_inputs::{PolicyDeploymentHeadV1, PolicyDeploymentInputsV1};

/// Retains actual fixture acquisition while exercising native fixed admissions.
///
/// Available only with test fixtures, this owner neither accepts an opened
/// journal nor exposes selected receiving or a completed Authority role.
pub struct RootStartupFixedAdmissionFixtureV1 {
    owner: RootStartupJournalOriginalV1,
}

impl RootStartupFixedAdmissionFixtureV1 {
    /// Opens and fully replays the actual named ordinary fixture files once.
    ///
    /// # Errors
    /// Preserves the whole reached opening and its native or semantic failure.
    pub fn open_v1(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<Self, ErrorV1> {
        let mut owner = RootStartupJournalOriginalV1::new_fixed_admission_v1();
        let StartupJournalStorageV1::Ordinary(ordinary) = &mut owner.storage else {
            return Err(RootStartupJournalErrorV1::Closed.into());
        };
        ordinary.open_entered = true;
        ordinary
            .opening
            .open_fixture_startup_authority_once_v1(directory, name, limits, uid);
        if ordinary.opening.failure_v1().is_some() {
            return Err(ErrorV1::Opening {
                returned: RootStartupJournalErrorV1::Closed,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        Ok(Self { owner })
    }

    /// Admits signer pins using the same native semantic body as startup.
    ///
    /// # Errors
    /// Preserves signer, held binding, materialization, commit and readback refusals.
    pub fn admit_signer_pins_v1(
        &mut self,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        self.owner.admit_signer_pins_after_entry_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits the optional Cache pin using the production semantic body.
    ///
    /// # Errors
    /// Preserves signer separation, rotation, native commit and readback refusals.
    pub fn admit_cache_pin_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        self.owner.admit_cache_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits the optional Controller pin using the production semantic body.
    ///
    /// # Errors
    /// Preserves signer separation, rotation, native commit and readback refusals.
    pub fn admit_controller_pin_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        self.owner.admit_controller_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits the optional Source pin using the production semantic body.
    ///
    /// # Errors
    /// Preserves signer separation, rotation, native commit and readback refusals.
    pub fn admit_source_pin_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        self.owner.admit_source_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits an already verified head at the original fixture CAS frontier.
    ///
    /// # Errors
    /// Preserves held binding, succession, native commit and readback refusals.
    pub fn admit_verified_head_v1(
        &mut self,
        packet: &[u8],
        head: PolicyDeploymentHeadV1,
        key: &VerifyingKey,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        self.owner
            .admit_deployment_head_after_entry_v1(packet, head, key, None)
    }

    /// Verifies a profile against the same real held fixture pins and head.
    ///
    /// # Errors
    /// Preserves missing or substituted pins/head and profile verification errors.
    pub fn verify_profile_v2(
        &mut self,
        packet: &[u8],
        inputs: &PolicyDeploymentInputsV1<'_>,
        profile: &crate::signed_inputs::PolicyDeploymentInputProfileV2,
        now: i64,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        use crate::journal_keys::HEAD_KEY;
        let (key, generation) = self.deployment_role_data_v1()?;
        if generation != profile.signer_generation() {
            return Err(ErrorV1::StaleHead);
        }
        let authority = self.owner.credential_authority_after_entry_v1(None)?;
        if authority.get(HEAD_KEY)? != Some(packet) {
            return Err(ErrorV1::StaleHead);
        }
        crate::signed_inputs::verify_policy_deployment_profile_data_v2(
            packet, inputs, profile, &key, now,
        )
        .map_err(ErrorV1::from)
    }

    /// Reads the actual fixture deployment signer and generation as comparison data.
    ///
    /// # Errors
    /// Preserves native read failures and rejects absent or malformed role pins.
    pub fn deployment_role_data_v1(&mut self) -> Result<(VerifyingKey, u64), ErrorV1> {
        let authority = self.owner.credential_authority_after_entry_v1(None)?;
        let pins = authority
            .get(crate::journal_keys::SIGNER_PINS_KEY)?
            .ok_or(ErrorV1::StaleHead)?;
        let (generation, key, _, _) =
            aos_sandbox_ledger_replay::replay::root_genesis_pins::decode_policy_signer_pins_v1(
                pins,
            )
            .map_err(|_| ErrorV1::InvalidHead)?;
        Ok((key, generation))
    }

    /// Rechecks the same real fixture directory, owner, journal and lock names.
    ///
    /// # Errors
    /// Preserves health, fixture traversal, identity and names failures.
    pub fn validate_held_names_v1(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
    ) -> Result<(), ErrorV1> {
        use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
        let journal = match &self.owner.storage {
            StartupJournalStorageV1::Ordinary(ordinary) => ordinary.opening.journal_v1(),
            StartupJournalStorageV1::Selected(_) => None,
        }
        .ok_or(RootStartupJournalErrorV1::Closed)?;
        journal.require_healthy_native()?;
        let view = journal.read_view();
        if view.protected_name() != Some(name) || view.protected_uid() != Some(uid) {
            return Err(crate::native::PolicyNativeJournalErrorV1::boundary().into());
        }
        let _current = view
            .require_directory_at_uid_for_test::<Mechanical>(directory, uid)
            .map_err(crate::native::PolicyNativeJournalErrorV1::from)?;
        view.require_names::<Mechanical>()
            .map_err(crate::native::PolicyNativeJournalErrorV1::from)?;
        Ok(())
    }

    /// Copies the actual held fixture NEXT as nonauthorizing DATA.
    #[must_use]
    pub fn snapshot_sequence_v1(&self) -> Option<u64> {
        match &self.owner.storage {
            StartupJournalStorageV1::Ordinary(ordinary) => ordinary
                .opening
                .journal_v1()
                .map(|journal| journal.next_sequence()),
            StartupJournalStorageV1::Selected(_) => None,
        }
    }

    /// Seeds generic fixture rows through the actual ordinary mutation engine.
    ///
    /// # Errors
    /// Preserves protected-family refusal and native, semantic or append failure.
    pub fn seed_v1(&mut self, transaction: &JournalTransaction) -> Result<CommitResult, ErrorV1> {
        self.owner
            .journal_after_entry_mut_v1()
            .ok_or(RootStartupJournalErrorV1::Closed)?
            .commit(transaction)
            .map_err(ErrorV1::from)
    }
}
