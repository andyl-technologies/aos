//! Keeps the real startup writer and optional original Root funding borrowed together.
//!
//! Selected credential admission never locks Root again. Each commit reborrows
//! the same continuously held original through the common Native append path.

use aos_sandbox_policy::signed_inputs::PolicyDeploymentHeadV1;

use ed25519_dalek::VerifyingKey;

use super::super::cache_readback_pin::admit_cache_readback_pin_in_journal_v1_with_root_receiving;
use super::super::controller_hold_pin::admit_controller_hold_pin_in_journal_v1_with_root_receiving;
use super::super::deployment_head::{
    admit_deployment_head_in_journal_with_root_receiving,
    admit_policy_signer_pins_in_journal_v1_with_root_receiving,
};
use super::super::source_hold_pin::admit_source_hold_pin_in_journal_v1_with_root_receiving;
use super::super::{
    CacheReadbackPinErrorV1, ControllerHoldPinErrorV1, PolicyDeploymentHeadErrorV1,
    SourceHoldPinErrorV1,
};
use super::{RootPolicyStartupDeploymentV1, RootPolicyStartupJournalV1, StartupSignerPinsV1};
use aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1;

/// Reborrows one actual credential writer and its existing optional Root original.
///
/// Only the retained startup owner constructs this adapter. It exposes fixed
/// credential admissions, never the journal, funding guard or a general writer.
pub struct RootStartupCredentialWriterV1<'borrow> {
    journal: &'borrow mut RootPolicyStartupJournalV1,
    original: Option<RootJournalFinancialBorrowV1<'borrow>>,
}

impl<'borrow> RootStartupCredentialWriterV1<'borrow> {
    pub(super) fn new(
        journal: &'borrow mut RootPolicyStartupJournalV1,
        original: Option<RootJournalFinancialBorrowV1<'borrow>>,
    ) -> Self {
        Self { journal, original }
    }

    /// Admits the deployment/project signer pins through this held writer.
    ///
    /// # Errors
    ///
    /// Preserves existing pin, hold, replay, and durable-admission refusals.
    pub fn admit_signer_pins(
        &mut self,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), PolicyDeploymentHeadErrorV1> {
        admit_policy_signer_pins_in_journal_v1_with_root_receiving(
            self.journal.journal_mut()?,
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

    /// Admits the exact already-verified deployment without decoding it again.
    ///
    /// # Errors
    ///
    /// Rejects a token whose signer differs from this owner's admitted pins;
    /// preserves protected hold, head generation, append, and readback refusals.
    pub fn admit_deployment_head(
        &mut self,
        deployment: RootPolicyStartupDeploymentV1<'_>,
    ) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
        let pins = self.journal.admitted_signer_pins()?;
        // Credential generations identify verifier keys; they are separate
        // from the signed deployment head's monotone generation.
        if deployment.key != &pins.deployment_key
            || deployment.signer_generation != pins.deployment_generation
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }

        admit_deployment_head_in_journal_with_root_receiving(
            self.journal.journal_mut()?,
            deployment.packet,
            deployment.head,
            deployment.key,
            self.original.as_ref(),
        )
    }

    /// Admits the optional Cache pin through this same held writer.
    ///
    /// # Errors
    ///
    /// Preserves existing optional-pin, role separation, and journal refusals.
    pub fn admit_cache_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), CacheReadbackPinErrorV1> {
        let pins = self.journal.admitted_signer_pins()?;
        admit_cache_readback_pin_in_journal_v1_with_root_receiving(
            self.journal.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
            self.original.as_ref(),
        )
    }

    /// Admits the optional Controller pin through this same held writer.
    ///
    /// # Errors
    ///
    /// Preserves existing optional-pin, role separation, and journal refusals.
    pub fn admit_controller_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), ControllerHoldPinErrorV1> {
        let pins = self.journal.admitted_signer_pins()?;
        admit_controller_hold_pin_in_journal_v1_with_root_receiving(
            self.journal.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
            self.original.as_ref(),
        )
    }

    /// Admits the optional Source pin through this same held writer.
    ///
    /// # Errors
    ///
    /// Preserves existing optional-pin, role separation, and journal refusals.
    pub fn admit_source_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), SourceHoldPinErrorV1> {
        let pins = self.journal.admitted_signer_pins()?;
        admit_source_hold_pin_in_journal_v1_with_root_receiving(
            self.journal.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
            self.original.as_ref(),
        )
    }
}
