//! Reuses one protected authority writer across normal Root startup admission.
//!
//! The daemon retains this owner from the unresolved-hold observation through
//! credential admission and an independent named-writer post. It releases the
//! writer before fixed recovery helpers or request handling can reopen it.
//! Journal-owned opening/replay partials remain resident until that boundary;
//! transitive validator temporaries and complete credential receiving do not.
//! This owner establishes no startup origin, parent payment, physical fit,
//! receiving loan, activation authority, or refund on disposal.

use std::{error::Error, fmt, path::Path};

use ed25519_dalek::VerifyingKey;

use crate::journal::{Journal, JournalError, ProtectedWriterOpenOriginalsV1};

use super::binding_v2::read_inert_closed_policy_binding_hold_in_journal_v1;
use super::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
use super::controller_hold_pin::admit_controller_hold_pin_in_journal_v1;
use super::deployment_head::{
    admit_deployment_head_in_journal, admit_policy_signer_pins_in_journal_v1,
};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::source_hold_pin::admit_source_hold_pin_in_journal_v1;
use super::{
    CacheReadbackPinErrorV1, ClosedPolicyRootCasObservationV2, ControllerHoldPinErrorV1,
    PolicyCompilerJournalErrorV1, PolicyDeploymentHeadErrorV1, PolicyDeploymentHeadV1,
    PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1, SourceHoldPinErrorV1,
    decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
};

/// Retains a verified packet and the typed sources decoded from its exact inputs.
///
/// Private fields prevent combining a verified head with unrelated sources.
/// This is deployment provenance only; protected admission remains separate.
pub struct RootPolicyStartupDeploymentV1<'input> {
    packet: &'input [u8],
    key: &'input VerifyingKey,
    signer_generation: u64,
    head: PolicyDeploymentHeadV1,
    _sources: PolicyDeploymentSourcesV1,
}

impl<'input> RootPolicyStartupDeploymentV1<'input> {
    /// Verifies and decodes one exact signed deployment without opening a journal.
    ///
    /// # Errors
    ///
    /// Rejects zero signer generations and preserves signature, validity,
    /// canonical-input, and typed-source errors.
    pub fn verify(
        packet: &'input [u8],
        inputs: &PolicyDeploymentInputsV1<'_>,
        key: &'input VerifyingKey,
        signer_generation: u64,
        now_unix_seconds: i64,
    ) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if signer_generation == 0 {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let head = verify_policy_deployment_head_v1(packet, inputs, key, now_unix_seconds)?;
        let sources = decode_policy_deployment_sources_v1(inputs, head)?;

        Ok(Self {
            packet,
            key,
            signer_generation,
            head,
            _sources: sources,
        })
    }

    /// Returns the head whose exact sources were verified and decoded.
    #[must_use]
    pub const fn head(&self) -> PolicyDeploymentHeadV1 {
        self.head
    }

    /// Transfers the already-decoded sources while ending packet/key borrows.
    ///
    /// Legacy startup keeps these sources until its original credential scope
    /// ends. This transfer performs no verification, decode, or admission.
    #[must_use]
    pub fn into_sources(self) -> PolicyDeploymentSourcesV1 {
        self._sources
    }
}

/// Retains one fixed Root authority writer and its reached opening originals.
///
/// The caller must explicitly finish the named-writer post before release,
/// including when credentials or admission fail. Drop releases custody only.
pub struct RootPolicyStartupJournalV1 {
    opening: ProtectedWriterOpenOriginalsV1,
    signer_pins: Option<StartupSignerPinsV1>,
    names_post: Option<Result<(), JournalError>>,
    finished: bool,
}

#[derive(Clone, Copy)]
struct StartupSignerPinsV1 {
    deployment_generation: u64,
    deployment_key: VerifyingKey,
    project_generation: u64,
    project_key: VerifyingKey,
}

impl RootPolicyStartupJournalV1 {
    /// Prearms vacant custody without opening storage or issuing authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opening: ProtectedWriterOpenOriginalsV1::new(),
            signer_pins: None,
            names_post: None,
            finished: false,
        }
    }

    /// Enters the fixed writable opening once, retaining native/replay failures.
    pub fn open_once(&mut self) {
        self.opening.open_once(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
        );
    }

    /// Reads unresolved custody from this same writer before credential admission.
    ///
    /// # Errors
    ///
    /// Rejects failed opening, malformed or legacy history, or ended borrowing.
    pub fn read_binding_hold(
        &mut self,
    ) -> Result<Option<ClosedPolicyRootCasObservationV2>, PolicyCompilerJournalErrorV1> {
        read_inert_closed_policy_binding_hold_in_journal_v1(self.journal_mut()?)
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
        admit_policy_signer_pins_in_journal_v1(
            self.journal_mut()?,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        )?;
        self.signer_pins = Some(StartupSignerPinsV1 {
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
        let pins = self.admitted_signer_pins()?;
        // Credential generations identify verifier keys; they are separate
        // from the signed deployment head's monotone generation.
        if deployment.key != &pins.deployment_key
            || deployment.signer_generation != pins.deployment_generation
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }

        admit_deployment_head_in_journal(
            self.journal_mut()?,
            deployment.packet,
            deployment.head,
            deployment.key,
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
        let pins = self.admitted_signer_pins()?;
        admit_cache_readback_pin_in_journal_v1(
            self.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
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
        let pins = self.admitted_signer_pins()?;
        admit_controller_hold_pin_in_journal_v1(
            self.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
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
        let pins = self.admitted_signer_pins()?;
        admit_source_hold_pin_in_journal_v1(
            self.journal_mut()?,
            credential,
            pins.deployment_generation,
            &pins.deployment_key,
            pins.project_generation,
            &pins.project_key,
        )
    }

    /// Retains one independent fixed-name post before ending startup borrowing.
    ///
    /// # Errors
    ///
    /// Rejects repetition, incomplete or poisoned opening, or replaced names.
    /// A negative post cannot authorize continued startup admission.
    pub fn finish_names_once(&mut self) -> Result<(), JournalError> {
        if self.finished {
            return Err(JournalError::ProtectedBoundary);
        }
        self.finished = true;
        self.names_post = Some(self.opening.check_named_currentness(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
        ));
        if matches!(self.names_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Borrows the original opening or independent-post cause until release.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening.failure().or_else(|| {
            self.names_post
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))
        })
    }

    /// Moves posted custody into an owning diagnostic until error disposal.
    ///
    /// The caller must attempt the independent post first. This preserves its
    /// original cause without reopening storage or extending a receiving loan.
    /// Disposing the error releases custody, and establishes no refund or Drained.
    pub fn into_failure(self) -> impl Error {
        StartupJournalFailureV1 { owner: self }
    }

    // Copy only the already-admitted public pins before mutably borrowing the
    // writer. Each existing owner helper still rechecks the protected record.
    fn admitted_signer_pins(&self) -> Result<StartupSignerPinsV1, JournalError> {
        self.signer_pins.ok_or(JournalError::ProtectedBoundary)
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, JournalError> {
        if self.finished {
            return Err(JournalError::ProtectedBoundary);
        }
        let journal = self
            .opening
            .journal_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        journal.validate_held_root_owned_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
        )?;
        Ok(journal)
    }
}

struct StartupJournalFailureV1 {
    owner: RootPolicyStartupJournalV1,
}

impl fmt::Debug for StartupJournalFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupJournalFailureV1")
            .field("cause", &self.owner.failure())
            .finish()
    }
}

impl fmt::Display for StartupJournalFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.owner.failure() {
            Some(cause) => fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Root startup journal has no completed failure observation"),
        }
    }
}

impl Error for StartupJournalFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure()
    }
}
