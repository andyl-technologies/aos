//! Reuses one protected authority writer across normal Root startup admission.
//!
//! The daemon retains this owner from the unresolved-hold observation through
//! credential admission and an independent named-writer post. It releases the
//! writer before fixed recovery helpers or request handling can reopen it.
//! Journal-owned opening/replay partials remain resident until that boundary;
//! transitive validator temporaries and complete credential receiving do not.
//! This owner establishes no startup origin, parent payment, physical fit,
//! receiving loan, activation authority, or refund on disposal.

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
};

mod credential_geometry;
mod credential_writer;

pub use credential_writer::RootStartupCredentialWriterV1;

use std::{error::Error, fmt, path::Path};

use ed25519_dalek::VerifyingKey;

use crate::journal::{Journal, JournalError, ProtectedWriterOpenOriginalsV1};

use super::binding_v2::read_inert_closed_policy_binding_hold_in_journal_v1;
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::{
    CacheReadbackPinErrorV1, ClosedPolicyRootCasObservationV2, ControllerHoldPinErrorV1,
    PolicyCompilerJournalErrorV1, PolicyDeploymentHeadErrorV1, SourceHoldPinErrorV1,
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
        let head = verify_policy_deployment_head_v1(packet, inputs, key, now_unix_seconds)
            .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
        let sources = decode_policy_deployment_sources_v1(inputs, head)
            .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;

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
    #[cfg(target_os = "linux")]
    selected: Option<crate::journal::root_construction::RootJournalConstructionOriginalV1>,
    #[cfg(target_os = "linux")]
    selected_final_post: Option<aos_sandbox_broker::receiving::RootWriterPostOriginalV1>,
    signer_pins: Option<StartupSignerPinsV1>,
    receiving_names_before: Option<Result<(), JournalError>>,
    receiving_names_after: Option<Result<(), JournalError>>,
    names_post: Option<Result<(), JournalError>>,
    names_original: crate::journal::ProtectedJournalCurrentnessOriginalsV1,
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
    pub(crate) fn credential_writer_v1<'borrow>(
        &'borrow mut self,
        original: Option<aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'borrow>>,
    ) -> RootStartupCredentialWriterV1<'borrow> {
        RootStartupCredentialWriterV1::new(self, original)
    }

    /// Prearms vacant custody without opening storage or issuing authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opening: ProtectedWriterOpenOriginalsV1::new(),
            #[cfg(target_os = "linux")]
            selected: None,
            #[cfg(target_os = "linux")]
            selected_final_post: None,
            signer_pins: None,
            receiving_names_before: None,
            receiving_names_after: None,
            names_post: None,
            names_original: crate::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            finished: false,
        }
    }

    /// Enters the fixed writable opening once, retaining native/replay failures.
    pub fn open_once(&mut self) {
        self.opening.open_captured_once(
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
        self.credential_writer_v1(None).admit_signer_pins(deployment_generation, deployment_key, project_generation, project_key)
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
        self.credential_writer_v1(None).admit_deployment_head(deployment)
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
        self.credential_writer_v1(None).admit_cache_pin(credential)
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
        self.credential_writer_v1(None).admit_controller_pin(credential)
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
        self.credential_writer_v1(None).admit_source_pin(credential)
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
        #[cfg(target_os = "linux")]
        if let Some(selected) = self.selected.as_mut() {
            // The final credential post was armed before its first mutation.
            // Native poison/refusal cannot suppress this independent obligation.
            self.names_post = Some(match (selected.opened_mut(), self.selected_final_post.as_mut()) {
                (Some(journal), Some(post)) => journal.finish_root_names_post_once_v1(post),
                _ => { selected.finish_names_once();
                    if selected.failure().is_none() { Ok(()) } else { Err(JournalError::ProtectedBoundary) } },
            });
            return if matches!(self.names_post, Some(Ok(()))) { Ok(()) }
                else { Err(JournalError::ProtectedBoundary) };
        }
        self.names_post = Some(self.opening.check_named_currentness_retaining(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
            0,
            &mut self.names_original,
        ));
        if matches!(self.names_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    // Only the actual Root receiving cohort selects this staged form. The
    // fixed production names and limits cannot be supplied by another role.
    pub(crate) fn fixed_receiving_preparation_demand() -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let invalid = || JournalError::JournalTooLarge;
        let header = u64::try_from(std::mem::size_of::<
            crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        >()).map_err(|_| invalid())?;
        // The lower selected constructor cannot price this separate upper
        // field. Its native backing is entered only by ordinary startup.
        crate::journal::root_construction::RootJournalConstructionOriginalV1::fixed_demand_v1(
            crate::journal::root_construction::RootJournalPurposeV1::StartupAuthority,
        )?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))
            .map_err(|_| invalid())
    }

    pub(crate) fn prepare_receiving_once(
        &mut self,
        initial: &mut aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1,
    ) {
        if self.finished || self.selected.is_some() { initial.latch_root_refusal_v1(); return; }
        let mut selected = crate::journal::root_construction::RootJournalConstructionOriginalV1::new();
        selected.prepare_once(initial,
            crate::journal::root_construction::RootJournalPurposeV1::StartupAuthority);
        self.selected = Some(selected);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn receiving_extent(&self) -> Option<&crate::journal::ProtectedJournalPreopenReplayExtentV1> {
        self.selected.as_ref()?.extent()
    }

    pub(crate) fn receiving_index_demand_v1(&self) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        self.selected.as_ref().ok_or(JournalError::ProtectedBoundary)?.index_demand_v1()
    }

    pub(crate) fn replay_receiving_once(&mut self) {
        if self.finished { return; }
        if let Some(selected) = self.selected.as_mut() {
            selected.replay_once();
            selected.finish_names_once();
        }
    }

    pub(crate) fn finish_receiving_names_after_once(&mut self) {
        if let Some(selected) = self.selected.as_mut() { selected.finish_names_once(); }
    }

    pub(crate) fn receiving_replay_ready(&self) -> bool {
        self.selected.as_ref().is_some_and(|selected| selected.ready())
    }

    /// Borrows the original opening or independent-post cause until release.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(target_os = "linux")]
        if let Some(selected) = &self.selected {
            return selected.concrete_failure_v1()
                .or_else(|| self.selected_final_post.as_ref().and_then(|post| post.concrete_failure_v1()))
                .or_else(|| self.names_post.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                .or_else(|| selected.failure())
                .or_else(|| self.selected_final_post.as_ref().and_then(|post| post.failure()));
        }
        self.opening.failure().or_else(|| {
            self.receiving_names_before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.receiving_names_after.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
        }).or_else(|| self.names_original.failure()).or_else(|| {
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
        #[cfg(target_os = "linux")]
        if let Some(selected) = self.selected.as_mut() {
            selected.take_opened_once();
            let journal = selected.opened_mut().ok_or(JournalError::ProtectedBoundary)?;
            if self.selected_final_post.is_none() {
                self.selected_final_post = Some(journal.arm_root_names_post_once_v1()?);
            }
            journal.validate_held_root_owned_at(Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL)?;
            return Ok(journal);
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
