//! Original Root custody for the exclusive Git-only enrollment flight.
//!
//! The closed comparison below reuses the canonical checkpoint, signed packet,
//! traffic admission and coverage-body engines. Its result is historical DATA:
//! the actual Root owner must independently retain its startup, fixed role
//! credentials, current deployment, original writer and nonrenewing cutoff.
//!
//! ```text
//! AOSGUPF1: original checkpoint | Prepare request/outcome | Read request/outcome
//! only the first two exchanges of the same fresh authenticated session
//! ```

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use buffa::Message as _;
use aos_sandbox_broker_session_protocol::manifest::{
    BROKER_SESSION_MANIFEST_BYTES, BrokerSessionManifestAudienceV1,
    BrokerSessionManifestErrorV1, BrokerSessionManifestV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProjectionError, BrokerSessionProtocolV1, BrokerSessionSequenceError,
    BrokerSessionTrafficStateV1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageBrokerProofV1, GitCoverageBrokerRoleV1,
    GitCoverageCatalogV1, GitCoverageDataErrorV1, GitCoverageEnrollmentV1,
    GitCoverageFenceV1, GitCoverageJournalProfileV1,
    GitCoverageOutcomeFieldsV1, GitCoverageOutcomeV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodErrorV1, AuthenticatedBrokerMethodOutcomeAdmissionV1,
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestAdmissionV1,
    AuthenticatedBrokerMethodResultV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    authenticated_semantic_bindings_from_envelope_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalCheckpointErrorV1, HistoricalSessionCheckpointV1,
};
use aos_sandbox_protocol::git_project_coverage::{
    GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1, compare_git_project_coverage_response_v1,
};
use aos_sandbox_protocol::{PeerPolicy, ProtocolValidationError};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageRootCoordinatesV1, GitCoverageRootSubmissionV1,
};
use aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::normal_root::{
    NormalRootStartupErrorV1, OriginalNormalRootPeerV1,
    OriginalControllerPolicyPeerV1, ProductionControllerNormalRootProfileV1,
    ProductionNormalRootStartupV1,
};
use crate::journal::{
    CommitResult, GitCoverageNativeHistoryErrorV1, Journal, JournalError,
    JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
};
use super::consumer_read_flight::{
    ConsumerReadFlightErrorV1, Deadline, RetainedCarrier, TransportFault,
};

/// Identifies the complete fixed thirty-two-byte exclusive-cohort bootstrap.
pub const GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1: &[u8; 8] = b"AOSGUER1";
const ROOT_CHALLENGE_MAGIC: &[u8; 8] = b"AOSGUENQ";
const ROOT_OBSERVATION_BYTES: usize = 1200;
const ROOT_OBSERVATION_ENTRY_BYTES: usize = 552;
const ROOT_OBSERVATION_DOMAIN: &[u8] =
    b"aos.sandbox.git-upload.root-coverage-observation.v2\0";
const ROOT_CAS_DONE_MAGIC: &[u8; 8] = b"AOSGUCAS";
const ROOT_CAS_END_MAGIC: &[u8; 8] = b"AOSGUEND";

#[derive(Debug, thiserror::Error)]
enum RootFlightFailureV1 {
    #[error(transparent)]
    Transport(#[from] TransportFault),
    #[error(transparent)]
    Carrier(#[from] ConsumerReadFlightErrorV1),
    #[error(transparent)]
    Startup(#[from] NormalRootStartupErrorV1),
    #[error(transparent)]
    Policy(#[from] super::PolicyCompilerJournalErrorV1),
    #[error(transparent)]
    Data(#[from] GitCoverageDataErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Deployment(#[from] super::PolicyDeploymentHeadErrorV1),
    #[error(transparent)]
    Native(Box<GitCoverageNativeHistoryErrorV1>),
    #[error(transparent)]
    CacheSource(#[from] crate::cache_residency::CacheReplayControllerBootstrapErrorV1),
    #[error(transparent)]
    CacheTarget(#[from] crate::cache_residency::CacheResidencyProtectedJournalErrorV1),
    #[error(transparent)]
    Account(#[from] crate::publisher_policy::GitUploadBootstrapErrorV1),
    #[error(transparent)]
    Comparison(#[from] EnrollmentComparisonErrorV1),
    #[error("original Git coverage Root flight differs or cannot resume")]
    Refused,
}

// These are copies of observations from an actual loan, never a replacement
// writer or currentness permit. The original Journal remains in its slot.
struct RootNativeObservationV1 {
    prefix: [u8; 32],
    origin: [u8; 32],
    last_commit: Option<([u8; 16], u64)>,
}

/// Copies a closed observation from a real original native-prefix loan.
///
/// The profile prevents CacheBootstrap facts from substituting for global
/// Source facts. This owns DATA only; its original writer stays with its owner.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GitCoverageNativeCutDataV1 {
    profile: GitCoverageJournalProfileV1,
    provision_origin: [u8; 32],
    prefix: [u8; 32],
    transactions: usize,
    records: usize,
    last_commit: Option<([u8; 16], u64)>,
}

impl GitCoverageNativeCutDataV1 {
    pub(crate) fn from_original_loan(
        profile: GitCoverageJournalProfileV1,
        loan: &crate::journal::GitCoverageNativePrefixLoanV1<'_>,
    ) -> Self {
        let (transactions, records) = loan.counts();
        Self {
            profile,
            provision_origin: loan.provision_origin_digest(),
            prefix: loan.prefix_digest(),
            transactions,
            records,
            last_commit: loan.last_commit(),
        }
    }
}

enum OriginalSourceCutReadV1<'captured> {
    Capture,
    Compare(Option<&'captured GitCoverageNativeCutDataV1>),
}

// Keeps comparison inside the SAME native loan, then ends it before callers
// park owned DATA/error and run their independent final named-writer bookend.
fn read_original_source_cut(
    original: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
    original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    read: OriginalSourceCutReadV1<'_>,
) -> Result<GitCoverageNativeCutDataV1, RootFlightFailureV1> {
    original.require_fixed_named_writer_v1()?;
    let inputs = original_inputs.ready().ok_or(RootFlightFailureV1::Refused)?;
    let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
    let mut native = original.journal().source_git_coverage_native_prefix_v1(&catalog)
        .map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?;
    native.recheck()?;
    let actual = GitCoverageNativeCutDataV1::from_original_loan(
        GitCoverageJournalProfileV1::Source, &native,
    );
    if let OriginalSourceCutReadV1::Compare(expected) = read {
        if expected != Some(&actual) {
            return Err(RootFlightFailureV1::Refused);
        }
    }
    Ok(actual)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountPhaseV1 {
    Fresh,
    Capturing,
    Captured,
    Committing,
    Committed,
    LocallyCompleted,
    ExistingLocallyCompleted,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountDispositionV1 {
    Enrollment,
    Existing,
}

/// Retains one covered account attempt under an external original profile loan.
///
/// Native loans remain local to short fixed-owner methods. This capsule owns
/// only their returned DATA/errors and its ONE original Root flight, never a
/// reference into the executor, initializer or parent worker. An empty capsule
/// is not checked account authority or an allocation permission.
#[doc(hidden)]
pub struct GitCoverageAccountAttemptV1<'profile> {
    root: GitCoverageRootClientV1<'profile>,
    source_cut: Option<Result<GitCoverageNativeCutDataV1, RootFlightFailureV1>>,
    controller_cut: Option<Result<GitCoverageNativeCutDataV1, GitCoverageNativeHistoryErrorV1>>,
    cache_bootstrap_cut: Option<Result<GitCoverageNativeCutDataV1, crate::cache_residency::CacheReplayControllerBootstrapErrorV1>>,
    cache_cuts: Option<Result<Vec<GitCoverageNativeCutDataV1>, crate::cache_residency::CacheResidencyProtectedJournalErrorV1>>,
    controller_transaction: Option<Result<JournalTransaction, JournalError>>,
    controller_preflight: Option<Result<(), JournalError>>,
    controller_commit: Option<Result<CommitResult, JournalError>>,
    controller_readback: Option<Result<GitCoverageNativeCutDataV1, GitCoverageNativeHistoryErrorV1>>,
    metadata: Option<Result<Vec<u8>, GitCoverageDataErrorV1>>,
    remote_readbacks: [Option<Result<GitCoverageOutcomeFieldsV1, EnrollmentComparisonErrorV1>>; 2],
    owner_rows: Option<Result<Vec<[u8; 140]>, RootFlightFailureV1>>,
    account_append: Option<Result<crate::publisher_policy::GitUploadEnrolledAccountAppendV1, crate::publisher_policy::GitUploadBootstrapErrorV1>>,
    account_readback: Option<Result<GitCoverageNativeCutDataV1, GitCoverageNativeHistoryErrorV1>>,
    first_failure: Option<RootFlightFailureV1>,
    postcheck: Option<RootFlightFailureV1>,
    phase: AccountPhaseV1,
    disposition: AccountDispositionV1,
    existing_prepare_nonce: Option<[u8; 16]>,
}

impl<'profile> GitCoverageAccountAttemptV1<'profile> {
    /// Parks the genuine external profile loan before any flight or owner work.
    #[must_use]
    pub fn new(profile: &'profile ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            root: GitCoverageRootClientV1::new(profile),
            source_cut: None,
            controller_cut: None,
            cache_bootstrap_cut: None,
            cache_cuts: None,
            controller_transaction: None,
            controller_preflight: None,
            controller_commit: None,
            controller_readback: None,
            metadata: None,
            remote_readbacks: [None, None],
            owner_rows: None,
            account_append: None,
            account_readback: None,
            first_failure: None,
            postcheck: None,
            phase: AccountPhaseV1::Fresh,
            disposition: AccountDispositionV1::Enrollment,
            existing_prepare_nonce: None,
        }
    }

    /// Selects read-only replay while the SAME flight is still wholly fresh.
    ///
    /// # Errors
    /// Refuses every entered or partially captured owner. This sets no Ready,
    /// completion, currentness, generation or account permission.
    #[doc(hidden)]
    pub fn select_existing_replay_before_root_v1(&mut self) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Fresh || self.root.phase != RootClientPhaseV1::Fresh
            || self.source_cut.is_some() || self.controller_cut.is_some()
        {
            return Err(());
        }
        self.disposition = AccountDispositionV1::Existing;
        Ok(())
    }

    /// Ends only the local existing-pair flight after genuine Root readback.
    ///
    /// # Errors
    /// Refuses incomplete/failed replay and retains original endpoint debt.
    /// The existing account is never retagged as a new successful append.
    #[doc(hidden)]
    pub fn finish_existing_root_once(&mut self) -> Result<(), ()> {
        if self.disposition != AccountDispositionV1::Existing
            || self.phase != AccountPhaseV1::Captured
            || self.root.phase != RootClientPhaseV1::Observed
            || self.failure().is_some() || self.postcheck.is_some()
        {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        if self.root.finish_after_cas_once().is_err() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.phase = AccountPhaseV1::ExistingLocallyCompleted;
        Ok(())
    }

    /// Starts the SAME original Root challenge flight before local capture.
    ///
    /// # Errors
    /// Borrows actual resident Root failure; a failed flight cannot reconnect.
    pub fn begin_root_once(&mut self) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        self.root.begin_once()
    }

    /// Checks and returns the original Root nonce/boot/cut as correlation DATA.
    ///
    /// # Errors
    /// Refuses changed, failed, late or incomplete original Root custody.
    pub fn root_challenge(&mut self)
        -> Result<([u8; 16], [u8; 16], u64), GitCoverageRootFlightErrorV1<'_>>
    {
        self.root.challenge()
    }

    /// Completes only this client's local flight after its actual successor CAS.
    ///
    /// The original Root owner performs its own final checks after client EOF.
    /// Success here is neither their release proof nor funding or Drain.
    ///
    /// # Errors
    /// Refuses any noncommitted/failed attempt and retains actual transport,
    /// peer, cutoff and shutdown causes without retrying or renewing the cut.
    pub fn finish_local_root_once(&mut self) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Committed || self.failure().is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        if self.root.finish_after_cas_once().is_err() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.phase = AccountPhaseV1::LocallyCompleted;
        Ok(())
    }

    /// Compares the actual successor under the caller's same protected store.
    ///
    /// The original append remains resident here. This separately named
    /// readback never weakens the existing exact-gen1 bootstrap wrapper.
    ///
    /// # Errors
    /// Rejects an incomplete/failed attempt or any changed original source,
    /// credential, capacity, account predecessor or complete native replay.
    pub fn compare_enrolled_current_v1(
        &self,
        store: &crate::publisher_policy::PublisherPolicyStore<'_>,
        bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        capacity: &aos_sandbox_core::GitUploadCapacityV1,
        credentials: &crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), crate::publisher_policy::GitUploadBootstrapErrorV1> {
        if !matches!(self.phase, AccountPhaseV1::Committed | AccountPhaseV1::LocallyCompleted
            | AccountPhaseV1::ExistingLocallyCompleted)
            || self.failure().is_some()
        {
            return Err(crate::publisher_policy::GitUploadBootstrapErrorV1::Conflict);
        }
        if self.disposition == AccountDispositionV1::Existing {
            return store.current_git_upload_stored_enrolled_account_v1(
                bootstrap, source, capacity, credentials, now,
            );
        }
        let append = self.account_append.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(crate::publisher_policy::GitUploadBootstrapErrorV1::Conflict)?;
        store.current_git_upload_enrolled_account(
            append, bootstrap, source, capacity, credentials, now,
        )
    }

    /// Sends exact proofs while retaining their genuine typed outcomes outside.
    ///
    /// The containing Security owner independently checks its latest original
    /// Sessions before and after this flight. These comparisons are DATA only.
    ///
    /// # Errors
    /// Retains mismatched original packets or closed pair semantics and refuses
    /// submission until all local observations were captured by their owners.
    pub fn submit_root_once(
        &mut self,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_proofs: [&[u8]; 2],
        original_outcomes: [&AuthenticatedBrokerMethodOutcomeV1; 4],
    ) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Captured || self.remote_readbacks.iter().any(Option::is_some) {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        let returned = (|| {
            let inputs = original_inputs.ready().ok_or(RootFlightFailureV1::Refused)?;
            let enrollment = GitCoverageEnrollmentV1::decode(inputs.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
            for index in 0..2 {
                let role = if index == 0 { GitCoverageBrokerRoleV1::Mount } else { GitCoverageBrokerRoleV1::Storage };
                let root_nonce = self.root.root_nonce.ok_or(RootFlightFailureV1::Refused)?;
                self.remote_readbacks[index] = Some((|| {
                    let proof = GitCoverageBrokerProofV1::decode(original_proofs[index])?;
                    compare_borrowed_coverage_pair(
                        &proof, role,
                        original_outcomes[index * 2], original_outcomes[index * 2 + 1],
                        &enrollment, &catalog, root_nonce, self.existing_prepare_nonce,
                    )
                })());
                if !matches!(self.remote_readbacks[index].as_ref(), Some(Ok(_))) {
                    return Err(RootFlightFailureV1::Refused);
                }
            }
            let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(RootFlightFailureV1::Refused)?;
            self.root.submit_once(enrollment.node_epoch().0, [
                inputs.enrollment(), inputs.catalog(), original_proofs[0], original_proofs[1], metadata,
            ]).map_err(|_| RootFlightFailureV1::Refused)
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    /// Parks the actual Root observation without extracting its flight owner.
    ///
    /// # Errors
    /// The actual Root error remains in the SAME flight; failure is terminal.
    pub fn observe_root_once(&mut self) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Captured || self.root.observe_root_once().is_err() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    /// Captures global Source DATA from the executor's SAME original writer.
    ///
    /// # Errors
    /// Returns a marker only; the actual native/input error and separate final
    /// name debt remain owned here. CacheBootstrap cannot supply this cut.
    pub fn capture_original_source_cut_v1(
        &mut self,
        original: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    ) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Fresh || self.source_cut.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.phase = AccountPhaseV1::Capturing;
        self.source_cut = Some(read_original_source_cut(
            original, original_inputs, OriginalSourceCutReadV1::Capture,
        ));
        if let Err(cause) = original.require_fixed_named_writer_v1() {
            self.postcheck.get_or_insert(cause.into());
        }
        if !matches!(self.source_cut.as_ref(), Some(Ok(_))) || self.postcheck.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn compare_original_source_cut(
        &mut self,
        original: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    ) -> Result<(), ()> {
        let returned = read_original_source_cut(
            original, original_inputs,
            OriginalSourceCutReadV1::Compare(
                self.source_cut.as_ref().and_then(|result| result.as_ref().ok()),
            ),
        ).map(|_| ());
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = original.require_fixed_named_writer_v1() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn compare_completed_original_source_cut(
        &mut self,
        original: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    ) -> Result<(), ()> {
        if !matches!(self.phase, AccountPhaseV1::LocallyCompleted | AccountPhaseV1::ExistingLocallyCompleted) {
            self.first_failure.get_or_insert(RootFlightFailureV1::Refused);
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.compare_original_source_cut(original, original_inputs)
    }

    pub(crate) fn capture_cache_bootstrap_cut(
        &mut self,
        source: &mut crate::cache_residency::CacheReplayControllerBootstrapOwnerV1,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Capturing || self.cache_bootstrap_cut.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.cache_bootstrap_cut = Some(source.capture_git_coverage_native_cut_v1(catalog));
        if !matches!(self.cache_bootstrap_cut.as_ref(), Some(Ok(_))) {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    // Only the initializer with the private clock loan calls this. Each DATA
    // row came from its SAME retained writer; an error is moved exactly once.
    pub(crate) fn park_original_cache_cuts(
        &mut self,
        returned: Result<Vec<GitCoverageNativeCutDataV1>, crate::cache_residency::CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(), ()> {
        if self.phase != AccountPhaseV1::Capturing || self.cache_cuts.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.cache_cuts = Some(returned);
        if !matches!(self.cache_cuts.as_ref(), Some(Ok(_))) {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn compare_cache_bootstrap_cut(
        &mut self,
        source: &mut crate::cache_residency::CacheReplayControllerBootstrapOwnerV1,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<(), ()> {
        let returned = source.capture_git_coverage_native_cut_v1(catalog);
        match returned {
            Ok(actual) if self.cache_bootstrap_cut.as_ref()
                .and_then(|result| result.as_ref().ok()) == Some(&actual) => Ok(()),
            Ok(_) => {
                self.first_failure.get_or_insert(RootFlightFailureV1::Refused);
                self.phase = AccountPhaseV1::Failed;
                Err(())
            }
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                self.phase = AccountPhaseV1::Failed;
                Err(())
            }
        }
    }

    pub(crate) fn compare_original_cache_cuts(
        &mut self,
        returned: Result<Vec<GitCoverageNativeCutDataV1>, crate::cache_residency::CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(), ()> {
        match returned {
            Ok(actual) if self.cache_cuts.as_ref()
                .and_then(|result| result.as_ref().ok()) == Some(&actual) => Ok(()),
            Ok(_) => {
                self.first_failure.get_or_insert(RootFlightFailureV1::Refused);
                self.phase = AccountPhaseV1::Failed;
                Err(())
            }
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                self.phase = AccountPhaseV1::Failed;
                Err(())
            }
        }
    }

    // This call is owned by the initializer while its private clock guard is
    // live. `now` is sampled there, not accepted by either public forwarder.
    pub(crate) fn capture_controller_account_cut(
        &mut self,
        journal: &mut Journal,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), ()> {
        let returned = self.capture_controller_account_cut_inner(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, now,
        );
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = journal.validate_held_protected_names() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.failure().is_some() || self.postcheck.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.phase = AccountPhaseV1::Captured;
        Ok(())
    }

    fn capture_controller_account_cut_inner(
        &mut self,
        journal: &mut Journal,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), RootFlightFailureV1> {
        if self.phase != AccountPhaseV1::Capturing
            || !matches!(self.source_cut.as_ref(), Some(Ok(_)))
            || !matches!(self.cache_bootstrap_cut.as_ref(), Some(Ok(_)))
            || self.controller_cut.is_some()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        self.root.check_original()?;
        let data = original_inputs.ready().ok_or(RootFlightFailureV1::Refused)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
        catalog.compare_enrollment(&enrollment)?;
        let (_, issued, expires) = enrollment.generation_interval();
        let unsigned_now = u64::try_from(now).map_err(|_| RootFlightFailureV1::Refused)?;
        if unsigned_now < issued || unsigned_now >= expires {
            return Err(RootFlightFailureV1::Refused);
        }

        // The same protected store compares the real completed gen1 triple,
        // signed full source, capacity and credential backing before the pair.
        if self.disposition == AccountDispositionV1::Existing {
            self.existing_prepare_nonce = Some(
                journal.existing_controller_coverage_birth_nonce_v1(&catalog)
                    .map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?,
            );
        }
        let store = crate::publisher_policy::PublisherPolicyStore::load(
            journal, crate::publisher_policy::PublisherPolicyLimits::default(),
        ).map_err(crate::publisher_policy::GitUploadBootstrapErrorV1::from)?;
        if self.disposition == AccountDispositionV1::Existing {
            store.current_git_upload_stored_enrolled_account_v1(
                original_bootstrap, original_source, original_capacity,
                original_bootstrap_credentials, now,
            )?;
        } else {
            store.current_git_upload_bootstrap(
                original_bootstrap, original_source, original_capacity,
                original_bootstrap_credentials, now,
            )?;
        }
        drop(store);

        self.controller_cut = Some(observe_controller_native_cut(journal, &catalog));
        let Some(Ok(before)) = self.controller_cut.as_ref() else {
            return Err(RootFlightFailureV1::Refused);
        };
        let nonce = self.root.root_nonce.ok_or(RootFlightFailureV1::Refused)?;
        if self.disposition == AccountDispositionV1::Existing {
            let source = self.source_cut.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(RootFlightFailureV1::Refused)?;
            let bootstrap = self.cache_bootstrap_cut.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(RootFlightFailureV1::Refused)?;
            let deadline = self.root.deadline.ok_or(RootFlightFailureV1::Refused)?;
            self.metadata = Some(encode_local_cut_metadata(
                nonce, deadline.cutoff(), [before, source, bootstrap],
            ));
            if !matches!(self.metadata.as_ref(), Some(Ok(_))) {
                return Err(RootFlightFailureV1::Refused);
            }
            return Ok(());
        }
        let birth_fields = enrollment.fixed_owner_birth_recipe_v1(
            &catalog, GitCoverageJournalProfileV1::Controller, nonce,
        )?;
        if before.prefix != birth_fields.predecessor_prefix
            || before.provision_origin != birth_fields.provision_origin
            || journal.get(RecordNamespace::DesiredState, b"z-git-birth-v1").is_some()
            || journal.get(RecordNamespace::DesiredState, b"z-git-fence-v1").is_some()
            || journal.snapshot_sequence().checked_add(3) != Some(birth_fields.commit_sequence)
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let birth_bytes = birth_fields.encode()?;
        let birth = GitCoverageBirthV1::decode(&birth_bytes)?;
        let fence_bytes = birth_fields.to_fence_fields(
            enrollment.generation_interval().0, birth.digest(), nonce,
        ).encode()?;
        self.controller_transaction = Some(JournalTransaction::new(
            birth_fields.transaction,
            vec![
                JournalRecord::put(RecordNamespace::DesiredState, b"z-git-birth-v1".to_vec(), birth_bytes.to_vec()),
                JournalRecord::put(RecordNamespace::DesiredState, b"z-git-fence-v1".to_vec(), fence_bytes.to_vec()),
            ],
        ));
        let transaction = self.controller_transaction.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        self.controller_preflight = Some(journal.preflight_transactions(std::slice::from_ref(transaction)));
        if !matches!(self.controller_preflight.as_ref(), Some(Ok(()))) {
            return Err(RootFlightFailureV1::Refused);
        }
        journal.validate_held_protected_names()?;
        self.controller_commit = Some(journal.commit(transaction));
        let committed = self.controller_commit.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        if committed.commit_sequence != birth_fields.commit_sequence {
            return Err(RootFlightFailureV1::Refused);
        }

        self.controller_readback = Some(observe_controller_native_cut(journal, &catalog));
        let Some(Ok(after)) = self.controller_readback.as_ref() else {
            return Err(RootFlightFailureV1::Refused);
        };
        if after.last_commit != Some((birth_fields.transaction, committed.commit_sequence))
            || journal.get(RecordNamespace::DesiredState, b"z-git-birth-v1") != Some(birth_bytes.as_slice())
            || journal.get(RecordNamespace::DesiredState, b"z-git-fence-v1") != Some(fence_bytes.as_slice())
        {
            return Err(RootFlightFailureV1::Refused);
        }

        let source = self.source_cut.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(RootFlightFailureV1::Refused)?;
        let bootstrap = self.cache_bootstrap_cut.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(RootFlightFailureV1::Refused)?;
        let deadline = self.root.deadline.ok_or(RootFlightFailureV1::Refused)?;
        self.metadata = Some(encode_local_cut_metadata(
            nonce, deadline.cutoff(), [after, source, bootstrap],
        ));
        if !matches!(self.metadata.as_ref(), Some(Ok(_))) {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    // Called only inside the initializer's SAME private clock guard. The
    // upper owner independently bookends its latest authenticated Sessions.
    pub(crate) fn commit_controller_account(
        &mut self,
        journal: &mut Journal,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), ()> {
        let returned = self.commit_controller_account_inner(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, now,
        );
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = journal.validate_held_protected_names() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = self.root.check_original() {
            self.postcheck.get_or_insert(cause);
        }
        if self.failure().is_some() || self.postcheck.is_some() {
            self.phase = AccountPhaseV1::Failed;
            return Err(());
        }
        self.phase = AccountPhaseV1::Committed;
        Ok(())
    }

    fn commit_controller_account_inner(
        &mut self,
        journal: &mut Journal,
        original_inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), RootFlightFailureV1> {
        if self.phase != AccountPhaseV1::Captured
            || self.root.phase != RootClientPhaseV1::Observed
            || !matches!(self.root.observation.as_ref(), Some(Ok(_)))
            || self.account_append.is_some() || self.owner_rows.is_some()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        // Unwind leaves Committing. No public or private method resumes it.
        self.phase = AccountPhaseV1::Committing;
        self.root.check_original()?;
        let inputs = original_inputs.ready().ok_or(RootFlightFailureV1::Refused)?;
        let enrollment = GitCoverageEnrollmentV1::decode(inputs.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
        catalog.compare_enrollment(&enrollment)?;
        let before = self.controller_readback.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
            .ok_or(RootFlightFailureV1::Refused)?;
        let current = observe_controller_native_cut(journal, &catalog)
            .map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?;
        if current != before {
            return Err(RootFlightFailureV1::Refused);
        }

        self.owner_rows = Some(self.original_owner_rows(&catalog));
        let rows = self.owner_rows.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(RootFlightFailureV1::Refused)?;
        let mut store = crate::publisher_policy::PublisherPolicyStore::load(
            journal, crate::publisher_policy::PublisherPolicyLimits::default(),
        ).map_err(crate::publisher_policy::GitUploadBootstrapErrorV1::from)?;
        self.account_append = Some(store.prepare_git_upload_enrolled_account(
            original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, &enrollment, rows, now,
        ));
        let Some(Ok(append)) = self.account_append.as_mut() else {
            return Err(RootFlightFailureV1::Refused);
        };
        // The prepared result is already resident before either independent
        // original-peer bookend or the subsequent physical append crossing.
        self.root.check_original()?;
        store.commit_git_upload_enrolled_account(
            append, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, now,
        ).map_err(|_| RootFlightFailureV1::Refused)?;
        store.current_git_upload_enrolled_account(
            append, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, now,
        )?;
        let coordinates = append.committed_coordinates().ok_or(RootFlightFailureV1::Refused)?;
        drop(store);

        self.account_readback = Some(observe_controller_native_cut(journal, &catalog));
        let Some(Ok(after)) = &self.account_readback else {
            return Err(RootFlightFailureV1::Refused);
        };
        if after.last_commit != Some(coordinates)
            || before.last_commit.and_then(|(_, sequence)| sequence.checked_add(5))
                != Some(coordinates.1)
            || before.transactions.checked_add(1) != Some(after.transactions)
            || before.records.checked_add(3) != Some(after.records)
            || before.provision_origin != after.provision_origin
        {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    // All local rows follow real native loans. Remote rows follow the SAME
    // authenticated Prepare/Read and Root observations; the live services
    // prove complete subordinate prefixes and physical emptiness before
    // signing. A catalog by itself cannot call or establish this method.
    fn original_owner_rows(
        &self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<Vec<[u8; 140]>, RootFlightFailureV1> {
        let controller = self.controller_readback.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let source = self.source_cut.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let bootstrap = self.cache_bootstrap_cut.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let cache = self.cache_cuts.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let root = self.root.observation.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let mount = self.remote_readbacks[0].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let storage = self.remote_readbacks[1].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        if catalog.members().count() > 16 {
            return Err(RootFlightFailureV1::Refused);
        }
        let mut rows = Vec::with_capacity(catalog.members().count());
        for member in catalog.members() {
            let profile = member.profile();
            let original = member.bytes();
            let native = if GitCoverageJournalProfileV1::Controller.is_native_writer_member_v1(profile) {
                Some(controller)
            } else if profile == GitCoverageJournalProfileV1::Source {
                Some(source)
            } else if profile == GitCoverageJournalProfileV1::CacheBootstrap {
                Some(bootstrap)
            } else {
                cache.iter().find(|cut| cut.profile == profile)
            };
            let (prefix, sequence, disposition) = if let Some(cut) = native {
                if cut.provision_origin.as_slice() != member.provision_origin() {
                    return Err(RootFlightFailureV1::Refused);
                }
                match cut.last_commit {
                    Some((_, sequence)) => (cut.prefix, sequence, 0),
                    None if cut.transactions == 0 && cut.records == 0 => (cut.prefix, 0, 1),
                    _ => return Err(RootFlightFailureV1::Refused),
                }
            } else {
                match profile {
                    GitCoverageJournalProfileV1::RootAuthority
                    | GitCoverageJournalProfileV1::RootPolicyState => {
                        let entry = root.entry(profile)?;
                        (entry.0, entry.1, 0)
                    }
                    GitCoverageJournalProfileV1::Mount => (mount.native_prefix, mount.commit_sequence, 0),
                    GitCoverageJournalProfileV1::StorageCatalog => (storage.native_prefix, storage.commit_sequence, 0),
                    GitCoverageJournalProfileV1::CachePhysical if member.infrastructure_count() == 0 => (
                        original[104..136].try_into().map_err(|_| RootFlightFailureV1::Refused)?, 0, 2,
                    ),
                    GitCoverageJournalProfileV1::StorageNative
                    | GitCoverageJournalProfileV1::StorageWorkspace
                    | GitCoverageJournalProfileV1::StorageOutput => {
                        // Only after the real remote complete-history audit:
                        // its last declared PUT is immediately before COMMIT.
                        // An empty declaration is valid only under that audit.
                        let sequence = catalog.infrastructure().filter(|row| row.attribution() == member.digest())
                            .map(|row| row.put_sequence()).max();
                        let prefix = original[104..136].try_into().map_err(|_| RootFlightFailureV1::Refused)?;
                        match sequence {
                            Some(sequence) => (prefix, sequence.checked_add(1)
                                .ok_or(RootFlightFailureV1::Refused)?, 0),
                            None if member.infrastructure_count() == 0 => (prefix, 0, 1),
                            _ => return Err(RootFlightFailureV1::Refused),
                        }
                    }
                    _ => return Err(RootFlightFailureV1::Refused),
                }
            };
            let mut row = [0; 140];
            row[0] = profile.owner() as u8;
            row[1] = disposition;
            row[4..36].copy_from_slice(&original[8..40]);
            row[36..68].copy_from_slice(member.provision_origin());
            row[68..76].copy_from_slice(&sequence.to_be_bytes());
            row[76..108].copy_from_slice(&prefix);
            row[108..140].copy_from_slice(&member.digest());
            rows.push(row);
        }
        rows.sort_by(|left, right| {
            (left[0], &left[4..36], &left[108..140])
                .cmp(&(right[0], &right[4..36], &right[108..140]))
        });
        Ok(rows)
    }

    /// Borrows the resident typed cause without extracting an original owner.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.source_cut {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.cache_bootstrap_cut {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.cache_cuts {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.controller_cut {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.controller_transaction {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.controller_preflight {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.controller_commit {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.controller_readback {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.metadata {
            return Some(cause);
        }
        for result in &self.remote_readbacks {
            if let Some(Err(cause)) = result {
                return Some(cause);
            }
        }
        if let Some(Err(cause)) = &self.owner_rows {
            return Some(cause);
        }
        match &self.account_append {
            Some(Err(cause)) => return Some(cause),
            Some(Ok(append)) if append.failure().is_some() => return append.failure(),
            _ => {}
        }
        if let Some(Err(cause)) = &self.account_readback {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.root.observation {
            return Some(cause);
        }
        if let Some(cause) = self.root.error().cause {
            return Some(cause);
        }
        self.first_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    /// Borrows later original-owner debt separately from the first failure.
    #[must_use]
    pub fn postcheck_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.postcheck.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

fn fixed_coverage_fence_for_original_pair(
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
    profile: GitCoverageJournalProfileV1,
    prepare_nonce: [u8; 16],
) -> Result<([u8; 268], u64), GitCoverageDataErrorV1> {
    let birth_fields = enrollment.fixed_owner_birth_recipe_v1(catalog, profile, prepare_nonce)?;
    let birth_bytes = birth_fields.encode()?;
    let birth = GitCoverageBirthV1::decode(&birth_bytes)?;
    let fence = birth_fields.to_fence_fields(
        enrollment.generation_interval().0, birth.digest(), prepare_nonce,
    ).encode()?;
    Ok((fence, birth_fields.commit_sequence))
}

fn compare_borrowed_coverage_pair(
    proof: &GitCoverageBrokerProofV1<'_>,
    role: GitCoverageBrokerRoleV1,
    prepare: &AuthenticatedBrokerMethodOutcomeV1,
    read: &AuthenticatedBrokerMethodOutcomeV1,
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
    root_nonce: [u8; 16],
    existing_prepare_nonce: Option<[u8; 16]>,
) -> ComparisonResult<GitCoverageOutcomeFieldsV1> {
    let parts = proof.parts();
    let (prepare_method, read_method, profile) = match role {
        GitCoverageBrokerRoleV1::Mount => (
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1,
            BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1,
            GitCoverageJournalProfileV1::Mount,
        ),
        GitCoverageBrokerRoleV1::Storage => (
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1,
            BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1,
            GitCoverageJournalProfileV1::StorageCatalog,
        ),
    };
    if proof.role() != role || prepare.method() != prepare_method || read.method() != read_method
        || parts[1] != prepare.request().canonical_packet() || parts[2] != prepare.canonical_packet()
        || parts[3] != read.request().canonical_packet() || parts[4] != read.canonical_packet()
        || prepare.request().client_sequence() != 1 || prepare.broker_sequence() != 1
        || read.request().client_sequence() != 2 || read.broker_sequence() != 2
        || prepare.request().session_binding() != read.request().session_binding()
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let original = prepare.request().git_coverage_request_v1()
        .ok_or(EnrollmentComparisonErrorV1::Refused)?.comparison()?;
    if original.enrollment().map(GitCoverageEnrollmentV1::bytes) != Some(enrollment.bytes()) {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    use aos_sandbox_core::format::git_upload_enrollment::GitCoveragePrepareModeV1;
    let birth_nonce = match (original.prepare_mode(), existing_prepare_nonce) {
        (GitCoveragePrepareModeV1::Original, None) => original.coordinates().nonce,
        (GitCoveragePrepareModeV1::ExistingPair, Some(nonce)) if nonce != [0; 16] => nonce,
        _ => return Err(EnrollmentComparisonErrorV1::Refused),
    };
    if original.coordinates().nonce != root_nonce {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let (fence_bytes, commit_sequence) = fixed_coverage_fence_for_original_pair(
        enrollment, catalog, profile, birth_nonce,
    )?;
    let fence = GitCoverageFenceV1::decode(&fence_bytes)?;
    let prepare_readback = original_coverage_readback_v1(prepare, &fence)?;
    let readback = original_coverage_readback_v1(read, &fence)?;
    if prepare_readback.commit_sequence != commit_sequence
        || readback != (GitCoverageOutcomeFieldsV1 {
            request: aos_sandbox_core::format::git_upload_enrollment::GitCoverageRequestCoordinatesV1 {
                nonce: root_nonce, ..prepare_readback.request
            },
            ..prepare_readback
        })
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    Ok(readback)
}

fn observe_controller_native_cut(
    journal: &Journal,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<GitCoverageNativeCutDataV1, GitCoverageNativeHistoryErrorV1> {
    let loan = journal.controller_git_coverage_native_prefix_v1(catalog)?;
    Ok(GitCoverageNativeCutDataV1::from_original_loan(
        GitCoverageJournalProfileV1::Controller, &loan,
    ))
}

// Fixed local DATA, not another evidence/currentness engine. The complete
// native observations were obtained from real owners before this encoding.
const LOCAL_CUT_ROW_BYTES: usize = 104;
const LOCAL_CUT_BYTES: usize = 32 + 3 * LOCAL_CUT_ROW_BYTES + 32;
const LOCAL_CUT_DOMAIN: &[u8] = b"aos.sandbox.git-upload.local-native-cut.v1\0";
const LOCAL_CUT_PROFILES: [GitCoverageJournalProfileV1; 3] = [
    GitCoverageJournalProfileV1::Controller,
    GitCoverageJournalProfileV1::Source,
    GitCoverageJournalProfileV1::CacheBootstrap,
];

fn encode_local_cut_metadata(
    nonce: [u8; 16],
    cutoff: u64,
    cuts: [&GitCoverageNativeCutDataV1; 3],
) -> Result<Vec<u8>, GitCoverageDataErrorV1> {
    if nonce == [0; 16] || cutoff == 0 {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    let mut bytes = Vec::with_capacity(LOCAL_CUT_BYTES);
    bytes.extend_from_slice(b"AOSGULC1");
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&cutoff.to_be_bytes());
    for (cut, expected_profile) in cuts.into_iter().zip(LOCAL_CUT_PROFILES) {
        validate_local_native_cut(cut, expected_profile)?;
        let transactions = u64::try_from(cut.transactions).map_err(|_| GitCoverageDataErrorV1::Invalid)?;
        let records = u32::try_from(cut.records).map_err(|_| GitCoverageDataErrorV1::Invalid)?;
        let (transaction, sequence, flags) = match cut.last_commit {
            Some((transaction, sequence)) if transaction != [0; 16] && sequence != 0 => (transaction, sequence, 0_u16),
            None if transactions == 0 && records == 0 => ([0; 16], 0, 1_u16),
            _ => return Err(GitCoverageDataErrorV1::Invalid),
        };
        bytes.extend_from_slice(&(cut.profile as u16).to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&cut.provision_origin);
        bytes.extend_from_slice(&cut.prefix);
        bytes.extend_from_slice(&transaction);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&transactions.to_be_bytes());
        bytes.extend_from_slice(&records.to_be_bytes());
    }
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(LOCAL_CUT_DOMAIN)
        .chain_update(&bytes).finalize().into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

// This decoder lends comparison DATA only. The authenticated original
// Controller and its actual fixed-owner methods supply provenance separately.
// The explicit empty disposition is not an absent owner or a fake COMMIT.
fn decode_local_cut_metadata(
    bytes: &[u8],
    nonce: [u8; 16],
    cutoff: u64,
) -> Result<[GitCoverageNativeCutDataV1; 3], GitCoverageDataErrorV1> {
    if bytes.len() != LOCAL_CUT_BYTES || nonce == [0; 16] || cutoff == 0
        || bytes.get(..8) != Some(b"AOSGULC1".as_slice())
        || bytes.get(8..24) != Some(nonce.as_slice())
        || bytes.get(24..32) != Some(cutoff.to_be_bytes().as_slice())
    {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    let checksum_offset = LOCAL_CUT_BYTES - 32;
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(LOCAL_CUT_DOMAIN)
        .chain_update(&bytes[..checksum_offset])
        .finalize().into();
    if bytes[checksum_offset..] != checksum {
        return Err(GitCoverageDataErrorV1::Invalid);
    }

    let read_row = |index: usize| -> Result<GitCoverageNativeCutDataV1, GitCoverageDataErrorV1> {
        let start = 32 + index * LOCAL_CUT_ROW_BYTES;
        let row = &bytes[start..start + LOCAL_CUT_ROW_BYTES];
        let array = |start: usize, length: usize| {
            row.get(start..start + length).ok_or(GitCoverageDataErrorV1::Invalid)
        };
        let profile = LOCAL_CUT_PROFILES[index];
        if row[..2] != (profile as u16).to_be_bytes() {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let flags = u16::from_be_bytes(array(2, 2)?.try_into()
            .map_err(|_| GitCoverageDataErrorV1::Invalid)?);
        let transaction: [u8; 16] = array(68, 16)?.try_into()
            .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
        let sequence = u64::from_be_bytes(array(84, 8)?.try_into()
            .map_err(|_| GitCoverageDataErrorV1::Invalid)?);
        let last_commit = match flags {
            0 => Some((transaction, sequence)),
            1 if transaction == [0; 16] && sequence == 0 => None,
            _ => return Err(GitCoverageDataErrorV1::Invalid),
        };
        let cut = GitCoverageNativeCutDataV1 {
            profile,
            provision_origin: array(4, 32)?.try_into()
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?,
            prefix: array(36, 32)?.try_into()
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?,
            transactions: usize::try_from(u64::from_be_bytes(array(92, 8)?.try_into()
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?))
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?,
            records: usize::try_from(u32::from_be_bytes(array(100, 4)?.try_into()
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?))
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?,
            last_commit,
        };
        validate_local_native_cut(&cut, profile)?;
        Ok(cut)
    };
    Ok([read_row(0)?, read_row(1)?, read_row(2)?])
}

fn validate_local_native_cut(
    cut: &GitCoverageNativeCutDataV1,
    expected_profile: GitCoverageJournalProfileV1,
) -> Result<(), GitCoverageDataErrorV1> {
    if cut.profile != expected_profile || cut.provision_origin == [0; 32]
        || cut.prefix == [0; 32]
    {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    match cut.last_commit {
        Some((transaction, sequence)) if transaction != [0; 16] && sequence != 0
            && cut.transactions != 0 && cut.records != 0 => {
            let transactions = u64::try_from(cut.transactions)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            let records = u64::try_from(cut.records)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            if transactions.checked_mul(2).and_then(|frames| frames.checked_add(records))
                != Some(sequence)
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            Ok(())
        }
        None if expected_profile == GitCoverageJournalProfileV1::Source
            && cut.transactions == 0 && cut.records == 0 => Ok(()),
        _ => Err(GitCoverageDataErrorV1::Invalid),
    }
}

// This closed reply is authenticated by the original fixed Root endpoint,
// not by its checksum. It carries the exact existing birth/fence codecs and
// a separately observed native position; no future prefix is persisted.
struct RootCoverageObservationV1 {
    bytes: [u8; ROOT_OBSERVATION_BYTES],
}

impl RootCoverageObservationV1 {
    fn decode(
        bytes: &[u8],
        root_nonce: [u8; 16],
        cutoff: u64,
        enrollment: &GitCoverageEnrollmentV1<'_>,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<Self, RootFlightFailureV1> {
        if bytes.len() != ROOT_OBSERVATION_BYTES
            || bytes.get(..8) != Some(b"AOSGURO2".as_slice())
            || bytes.get(8..24) != Some(root_nonce.as_slice())
            || bytes.get(24..32) != Some(cutoff.to_be_bytes().as_slice())
            || bytes.get(1136..1168) != Some(catalog.coordinates().2.as_slice())
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(ROOT_OBSERVATION_DOMAIN)
            .chain_update(&bytes[..1168])
            .finalize()
            .into();
        if bytes[1168..] != checksum {
            return Err(RootFlightFailureV1::Refused);
        }
        let authority_nonce = compare_root_observation_entry(
            &bytes[32..584], GitCoverageJournalProfileV1::RootAuthority,
            enrollment, catalog,
        )?;
        let state_nonce = compare_root_observation_entry(
            &bytes[584..1136], GitCoverageJournalProfileV1::RootPolicyState,
            enrollment, catalog,
        )?;
        if authority_nonce != state_nonce {
            return Err(RootFlightFailureV1::Refused);
        }

        let bytes = bytes.try_into().map_err(|_| RootFlightFailureV1::Refused)?;
        Ok(Self { bytes })
    }

    fn entry(
        &self,
        profile: GitCoverageJournalProfileV1,
    ) -> Result<([u8; 32], u64), RootFlightFailureV1> {
        let offset = root_entry_offset(profile)?;
        let entry = &self.bytes[offset..offset + ROOT_OBSERVATION_ENTRY_BYTES];
        Ok((
            entry[512..544].try_into().map_err(|_| RootFlightFailureV1::Refused)?,
            u64::from_be_bytes(entry[544..552].try_into()
                .map_err(|_| RootFlightFailureV1::Refused)?),
        ))
    }
}

fn root_entry_offset(profile: GitCoverageJournalProfileV1) -> Result<usize, RootFlightFailureV1> {
    match profile {
        GitCoverageJournalProfileV1::RootAuthority => Ok(32),
        GitCoverageJournalProfileV1::RootPolicyState => Ok(584),
        _ => Err(RootFlightFailureV1::Refused),
    }
}

// Both entries use the same existing birth/fence engines. The closed profile
// fixes the actual original UUID, origin and NEXT; Root2 cannot stand in for14.
fn compare_root_observation_entry(
    bytes: &[u8],
    profile: GitCoverageJournalProfileV1,
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<[u8; 16], RootFlightFailureV1> {
    root_entry_offset(profile)?;
    if bytes.len() != ROOT_OBSERVATION_ENTRY_BYTES
        || bytes[512..544] == [0; 32]
    {
        return Err(RootFlightFailureV1::Refused);
    }
    let birth = GitCoverageBirthV1::decode(&bytes[..244])?;
    let fence = GitCoverageFenceV1::decode(&bytes[244..512])?;
    fence.compare_birth(&birth)?;
    let nonce = fence.fields().prepare_nonce;
    let expected = enrollment.fixed_owner_birth_recipe_v1(catalog, profile, nonce)?;
    let sequence = u64::from_be_bytes(bytes[544..552].try_into()
        .map_err(|_| RootFlightFailureV1::Refused)?);
    if birth.fields() != expected
        || fence.fields().generation != enrollment.generation_interval().0
        || sequence != expected.commit_sequence
    {
        return Err(RootFlightFailureV1::Refused);
    }
    Ok(nonce)
}

#[derive(Clone, Copy)]
enum RootDenialModeV1 {
    Append,
    Replay,
}

// Selects an existing owning reservoir at the actual crossing. Later
// credential or currentness debt cannot change this first failure source.
#[derive(Clone, Copy)]
enum RootWriterFailureSourceV1 {
    Action,
    Postcheck,
}

const ROOT_WRITER_PROFILES: [GitCoverageJournalProfileV1; 2] = [
    GitCoverageJournalProfileV1::RootAuthority,
    GitCoverageJournalProfileV1::RootPolicyState,
];

fn root_denial_nonce(
    journal: &Journal,
    profile: GitCoverageJournalProfileV1,
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<Option<[u8; 16]>, RootFlightFailureV1> {
    root_entry_offset(profile)?;
    let namespace = RecordNamespace::DesiredState;
    let pair = match (
        journal.get(namespace, b"z-git-birth-v1"),
        journal.get(namespace, b"z-git-fence-v1"),
    ) {
        (None, None) => None,
        (Some(birth), Some(fence)) => Some((birth, fence)),
        _ => return Err(RootFlightFailureV1::Refused),
    };
    let original_rows = if profile == GitCoverageJournalProfileV1::RootAuthority { 2 } else { 0 };
    let expected_rows = original_rows + if pair.is_some() { 2 } else { 0 };
    if journal.all_records().count() != expected_rows
        || journal.all_records().any(|(actual_namespace, key, _)| {
            actual_namespace != namespace
                || !matches!(key, b"z-git-birth-v1" | b"z-git-fence-v1")
                    && !(profile == GitCoverageJournalProfileV1::RootAuthority
                        && (key == super::deployment_head::HEAD_KEY
                            || key == super::deployment_head::SIGNER_PINS_KEY))
        })
    {
        return Err(RootFlightFailureV1::Refused);
    }
    let Some((birth, fence)) = pair else {
        return Ok(None);
    };
    let birth = GitCoverageBirthV1::decode(birth)?;
    let fence = GitCoverageFenceV1::decode(fence)?;
    fence.compare_birth(&birth)?;
    let nonce = fence.fields().prepare_nonce;
    let expected = enrollment.fixed_owner_birth_recipe_v1(catalog, profile, nonce)?;
    if birth.fields() != expected
        || fence.fields().generation != enrollment.generation_interval().0
        || expected.commit_sequence.checked_add(1) != Some(journal.snapshot_sequence())
    {
        return Err(RootFlightFailureV1::Refused);
    }
    Ok(Some(nonce))
}

fn observe_root_native_cut(
    journal: &Journal,
    profile: GitCoverageJournalProfileV1,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<RootNativeObservationV1, RootFlightFailureV1> {
    let loan = match profile {
        GitCoverageJournalProfileV1::RootAuthority => {
            journal.root_authority_git_coverage_native_prefix_v1(catalog)
        }
        GitCoverageJournalProfileV1::RootPolicyState => {
            journal.root_state_git_coverage_native_prefix_v1(catalog)
        }
        _ => return Err(RootFlightFailureV1::Refused),
    }.map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?;

    // The real loan ends locally. Its whole owning Result is parked before
    // either writer receives an independent physical/name postcheck.
    Ok(RootNativeObservationV1 {
        prefix: loan.prefix_digest(),
        origin: loan.provision_origin_digest(),
        last_commit: loan.last_commit(),
    })
}

fn root_denial_transaction(
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
    profile: GitCoverageJournalProfileV1,
    nonce: [u8; 16],
) -> Result<JournalTransaction, RootFlightFailureV1> {
    root_entry_offset(profile)?;
    let fields = enrollment.fixed_owner_birth_recipe_v1(catalog, profile, nonce)?;
    let birth_bytes = fields.encode()?;
    let birth = GitCoverageBirthV1::decode(&birth_bytes)?;
    let fence_bytes = fields.to_fence_fields(
        enrollment.generation_interval().0, birth.digest(), nonce,
    ).encode()?;

    Ok(JournalTransaction::new(fields.transaction, vec![
        JournalRecord::put(RecordNamespace::DesiredState, b"z-git-birth-v1".to_vec(), birth_bytes.to_vec()),
        JournalRecord::put(RecordNamespace::DesiredState, b"z-git-fence-v1".to_vec(), fence_bytes.to_vec()),
    ])?)
}

/// Keeps both fixed Root writers and every returned durability result resident.
///
/// Authority owns current signed deployment pins. Both writers own their
/// distinct permanent denial pair. Root acquires these originals LAST; neither is
/// reopened, transferred into a consuming validator, or loaned to the client.
struct RootCoverageWritersV1 {
    authority: Option<Result<(Journal, RecoveryReport), JournalError>>,
    state: Option<Result<(Journal, RecoveryReport), JournalError>>,
    transactions: [Option<Result<JournalTransaction, RootFlightFailureV1>>; 2],
    preflights: [Option<Result<(), JournalError>>; 2],
    commits: [Option<Result<CommitResult, JournalError>>; 2],
    readbacks: [Option<Result<RootNativeObservationV1, RootFlightFailureV1>>; 2],
    denial_mode: Option<RootDenialModeV1>,
    denial_started: bool,
    next_denial_writer: usize,
    failure_source: Option<RootWriterFailureSourceV1>,
    postcheck: Option<RootFlightFailureV1>,
    attempted: bool,
}

impl RootCoverageWritersV1 {
    fn empty() -> Self {
        Self {
            authority: None,
            state: None,
            transactions: [None, None],
            preflights: [None, None],
            commits: [None, None],
            readbacks: [None, None],
            denial_mode: None,
            denial_started: false,
            next_denial_writer: 0,
            failure_source: None,
            postcheck: None,
            attempted: false,
        }
    }

    fn capture_existing_once(&mut self) -> Result<(), RootFlightFailureV1> {
        if self.attempted || self.authority.is_some() || self.state.is_some() {
            return Err(RootFlightFailureV1::Refused);
        }
        self.attempted = true;

        self.authority = Some(Journal::open_existing_protected_at(
            std::path::Path::new(super::protected_owner::PROTECTED_POLICY_ROOT),
            super::protected_owner::POLICY_AUTHORITY_JOURNAL,
            super::protected_owner::policy_authority_journal_limits(),
        ));
        let authority = Self::original(&self.authority)?;
        authority.validate_held_protected_names()?;

        self.state = Some(Journal::open_existing_protected_at(
            std::path::Path::new(super::protected_owner::PROTECTED_POLICY_ROOT),
            super::protected_owner::POLICY_STATE_JOURNAL,
            super::protected_owner::policy_state_journal_limits(),
        ));
        Self::original(&self.state)?.validate_held_protected_names()?;
        Ok(())
    }

    fn original(
        slot: &Option<Result<(Journal, RecoveryReport), JournalError>>,
    ) -> Result<&Journal, RootFlightFailureV1> {
        match slot {
            Some(Ok((journal, recovery))) if recovery.truncated_bytes == 0 => Ok(journal),
            // The lower opener may already have repaired a tail before it
            // returned. Retain that report/writer and refuse, never undo it.
            _ => Err(RootFlightFailureV1::Refused),
        }
    }

    fn compare_current_deployment(
        &self,
        packet: &[u8],
        inputs: &super::PolicyDeploymentInputsV1<'_>,
        enrollment: &GitCoverageEnrollmentV1<'_>,
        catalog: &GitCoverageCatalogV1<'_>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
        now_unix_seconds: i64,
    ) -> Result<super::PolicyDeploymentHeadV1, RootFlightFailureV1> {
        let authority = Self::original(&self.authority)?;
        authority.validate_held_protected_names()?;
        let namespace = RecordNamespace::DesiredState;
        let protected_pins = super::deployment_head::decode_policy_signer_pins_v1(
            authority.get(namespace, super::deployment_head::SIGNER_PINS_KEY)
                .ok_or(RootFlightFailureV1::Refused)?,
        )?;
        if protected_pins != (
            deployment_generation, *deployment_key, project_generation, *project_key,
        ) || authority.get(namespace, super::deployment_head::HEAD_KEY) != Some(packet) {
            return Err(RootFlightFailureV1::Refused);
        }

        // The installed daemon supplies V1's actual original inputs. Reuse its
        // verifier and typed decoder, not a guessed V2 declaration or a second
        // signature/JSON engine. The concrete prebirth census remains only
        // head+pins and empty state. Each additional local pair is exact and
        // native-validated, never arbitrary catalogued DesiredState. The
        // initial two-writer relation is checked before either append, and
        // the final response requires both. Between ordered commits this read
        // bookend may see this same flight's partial crossing, not a baseline.
        self.compare_original_catalog(catalog)?;
        root_denial_nonce(
            authority, GitCoverageJournalProfileV1::RootAuthority, enrollment, catalog,
        )?;
        root_denial_nonce(
            Self::original(&self.state)?, GitCoverageJournalProfileV1::RootPolicyState,
            enrollment, catalog,
        )?;
        let head = super::verify_policy_deployment_head_v1(
            packet, inputs, deployment_key, now_unix_seconds,
        )?;
        super::decode_policy_deployment_sources_v1(inputs, head)?;
        authority.validate_held_protected_names()?;
        Ok(head)
    }

    fn compare_original_catalog(
        &self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<(), RootFlightFailureV1> {
        let authority = Self::original(&self.authority)?;
        let mut authority_cut = authority.root_authority_git_coverage_native_prefix_v1(catalog)
            .map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?;
        authority_cut.recheck()?;

        let state = Self::original(&self.state)?;
        let mut state_cut = state.root_state_git_coverage_native_prefix_v1(catalog)
            .map_err(|cause| RootFlightFailureV1::Native(Box::new(cause)))?;
        state_cut.recheck()?;
        Ok(())
    }

    fn prepare_denial_once(
        &mut self,
        enrollment: &GitCoverageEnrollmentV1<'_>,
        catalog: &GitCoverageCatalogV1<'_>,
        original_nonce: [u8; 16],
    ) -> Result<(), RootFlightFailureV1> {
        if self.denial_started {
            return Err(RootFlightFailureV1::Refused);
        }
        self.denial_started = true;
        let returned = self.prepare_denial(enrollment, catalog, original_nonce);
        let postcheck = self.compare_original_catalog(catalog);
        if let Err(cause) = postcheck {
            self.postcheck.get_or_insert(cause);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    fn prepare_denial(
        &mut self,
        enrollment: &GitCoverageEnrollmentV1<'_>,
        catalog: &GitCoverageCatalogV1<'_>,
        original_nonce: [u8; 16],
    ) -> Result<(), RootFlightFailureV1> {
        self.compare_original_catalog(catalog)?;
        let authority_nonce = root_denial_nonce(
            Self::original(&self.authority)?, ROOT_WRITER_PROFILES[0], enrollment, catalog,
        )?;
        let state_nonce = root_denial_nonce(
            Self::original(&self.state)?, ROOT_WRITER_PROFILES[1], enrollment, catalog,
        )?;
        // Only both-unfenced or both-complete can start this flight. A previous
        // one-sided append is debt, never permission to complete the other file.
        if authority_nonce != state_nonce {
            return Err(RootFlightFailureV1::Refused);
        }
        let birth_nonce = authority_nonce.unwrap_or(original_nonce);
        for (index, profile) in ROOT_WRITER_PROFILES.into_iter().enumerate() {
            self.transactions[index] = Some(root_denial_transaction(
                enrollment, catalog, profile, birth_nonce,
            ));
        }
        if self.transactions.iter().any(|slot| !matches!(slot, Some(Ok(_)))) {
            return Err(RootFlightFailureV1::Refused);
        }

        if authority_nonce.is_none() {
            // Both actual constructors and all-eight preflight Results are
            // resident before either effect. No scalar size/sequence proof
            // replaces the existing current/prospective materializer checks.
            for (index, slot) in [&self.authority, &self.state].into_iter().enumerate() {
                let journal = Self::original(slot)?;
                let transaction = self.transactions[index].as_ref()
                    .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
                let birth = GitCoverageBirthV1::decode(transaction.records()[0].value()
                    .ok_or(RootFlightFailureV1::Refused)?)?;
                if journal.snapshot_sequence().checked_add(3) != Some(birth.fields().commit_sequence) {
                    return Err(RootFlightFailureV1::Refused);
                }
                self.preflights[index] = Some(journal.preflight_transactions(
                    std::slice::from_ref(transaction),
                ));
            }
            if self.preflights.iter().any(|slot| !matches!(slot, Some(Ok(())))) {
                return Err(RootFlightFailureV1::Refused);
            }
            self.denial_mode = Some(RootDenialModeV1::Append);
        } else {
            // Exact replay observes both original pairs without any preflight
            // append, new nonce, rewritten UUID or physical mutation.
            self.denial_mode = Some(RootDenialModeV1::Replay);
        }
        Ok(())
    }

    fn commit_denial_writer_once(
        &mut self,
        index: usize,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<(), RootFlightFailureV1> {
        if index != self.next_denial_writer || index >= ROOT_WRITER_PROFILES.len()
            || self.denial_mode.is_none() || self.cause().is_some() || self.postcheck.is_some()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        // Advance before the effect. An error, cancellation or unwind cannot
        // retry this writer, heal a partial crossing or recreate its Result.
        self.next_denial_writer += 1;
        let returned = self.commit_denial_writer(index, catalog);
        if returned.is_err() {
            self.failure_source.get_or_insert(RootWriterFailureSourceV1::Action);
        }
        let postchecked = self.compare_original_catalog(catalog);
        if let Err(cause) = postchecked {
            self.postcheck.get_or_insert(cause);
            self.failure_source.get_or_insert(RootWriterFailureSourceV1::Postcheck);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    fn commit_denial_writer(
        &mut self,
        index: usize,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<(), RootFlightFailureV1> {
        let profile = ROOT_WRITER_PROFILES[index];
        let transaction = self.transactions[index].as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(RootFlightFailureV1::Refused)?;
        let birth_bytes = transaction.records()[0].value().ok_or(RootFlightFailureV1::Refused)?;
        let fence_bytes = transaction.records()[1].value().ok_or(RootFlightFailureV1::Refused)?;
        let birth = GitCoverageBirthV1::decode(birth_bytes)?.fields();
        let slot = if index == 0 { &mut self.authority } else { &mut self.state };
        let Some(Ok((journal, _))) = slot else {
            return Err(RootFlightFailureV1::Refused);
        };
        journal.validate_held_protected_names()?;
        if matches!(self.denial_mode, Some(RootDenialModeV1::Append)) {
            self.commits[index] = Some(journal.commit(transaction));
            let Some(Ok(committed)) = &self.commits[index] else {
                return Err(RootFlightFailureV1::Refused);
            };
            if committed.commit_sequence != birth.commit_sequence {
                return Err(RootFlightFailureV1::Refused);
            }
        }

        self.readbacks[index] = Some(observe_root_native_cut(journal, profile, catalog));
        let Some(Ok(observation)) = &self.readbacks[index] else {
            return Err(RootFlightFailureV1::Refused);
        };
        if observation.last_commit != Some((birth.transaction, birth.commit_sequence))
            || observation.origin != birth.provision_origin
            || journal.get(RecordNamespace::DesiredState, b"z-git-birth-v1") != Some(birth_bytes)
            || journal.get(RecordNamespace::DesiredState, b"z-git-fence-v1") != Some(fence_bytes)
        {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.authority {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.state {
            return Some(cause);
        }
        for slot in &self.transactions {
            if let Some(Err(cause)) = slot {
                return Some(cause);
            }
        }
        for slot in &self.preflights {
            if let Some(Err(cause)) = slot {
                return Some(cause);
            }
        }
        for index in 0..2 {
            if let Some(Err(cause)) = &self.commits[index] {
                return Some(cause);
            }
            if let Some(Err(cause)) = &self.readbacks[index] {
                return Some(cause);
            }
        }
        None
    }

    fn observation(
        &self,
        root_nonce: [u8; 16],
        cutoff: u64,
        enrollment: &GitCoverageEnrollmentV1<'_>,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<RootCoverageObservationV1, RootFlightFailureV1> {
        if self.cause().is_some() || self.postcheck.is_some() {
            return Err(RootFlightFailureV1::Refused);
        }
        if self.next_denial_writer != ROOT_WRITER_PROFILES.len() {
            return Err(RootFlightFailureV1::Refused);
        }

        let mut bytes = [0; ROOT_OBSERVATION_BYTES];
        bytes[..8].copy_from_slice(b"AOSGURO2");
        bytes[8..24].copy_from_slice(&root_nonce);
        bytes[24..32].copy_from_slice(&cutoff.to_be_bytes());
        for (index, slot) in [&self.authority, &self.state].into_iter().enumerate() {
            let journal = Self::original(slot)?;
            let Some(Ok(native)) = &self.readbacks[index] else {
                return Err(RootFlightFailureV1::Refused);
            };
            let (_, sequence) = native.last_commit.ok_or(RootFlightFailureV1::Refused)?;
            let namespace = RecordNamespace::DesiredState;
            let birth = journal.get(namespace, b"z-git-birth-v1")
                .ok_or(RootFlightFailureV1::Refused)?;
            let fence = journal.get(namespace, b"z-git-fence-v1")
                .ok_or(RootFlightFailureV1::Refused)?;
            if birth.len() != 244 || fence.len() != 268 {
                return Err(RootFlightFailureV1::Refused);
            }

            let offset = root_entry_offset(ROOT_WRITER_PROFILES[index])?;
            let entry = &mut bytes[offset..offset + ROOT_OBSERVATION_ENTRY_BYTES];
            entry[..244].copy_from_slice(birth);
            entry[244..512].copy_from_slice(fence);
            entry[512..544].copy_from_slice(&native.prefix);
            entry[544..552].copy_from_slice(&sequence.to_be_bytes());
        }
        bytes[1136..1168].copy_from_slice(&catalog.coordinates().2);
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(ROOT_OBSERVATION_DOMAIN)
            .chain_update(&bytes[..1168])
            .finalize()
            .into();
        bytes[1168..].copy_from_slice(&checksum);
        RootCoverageObservationV1::decode(&bytes, root_nonce, cutoff, enrollment, catalog)
    }
}

/// Retains Root's accepted original before any exclusive-cohort checks.
///
/// This selected owner borrows startup from the daemon's outer resident slot.
/// Its ONE carrier owns all input chunks, and its two original fixed writers
/// are acquired LAST and held through the client's successor-CAS bookend.
/// Returned errors and abandonment never release the failed owner locally.
#[doc(hidden)]
pub struct RootGitCoverageEnrollmentOwnerV1<'startup> {
    startup: Option<&'startup ProductionNormalRootStartupV1>,
    carrier: RetainedCarrier,
    bootstrap: [u8; 32],
    deadline: Option<Deadline>,
    peer: Option<OriginalControllerPolicyPeerV1<'startup>>,
    credentials: crate::public_api_session::GitCoverageCredentialCustodyV1,
    profile_read: Option<Result<Vec<u8>, crate::immutable_image::ImmutableImageErrorV1>>,
    profile_comparison: Option<Result<(), NormalRootStartupErrorV1>>,
    proofs: [Option<ComparisonResult<OriginalBrokerCoveragePairV1>>; 2],
    local_cuts: Option<Result<[GitCoverageNativeCutDataV1; 3], GitCoverageDataErrorV1>>,
    writers: RootCoverageWritersV1,
    observation: Option<Result<RootCoverageObservationV1, RootFlightFailureV1>>,
    first_failure: Option<RootFlightFailureV1>,
    postcheck: Option<RootFlightFailureV1>,
    attempted: bool,
    armed: bool,
}

impl<'startup> RootGitCoverageEnrollmentOwnerV1<'startup> {
    /// Parks the accepted stream, original startup loan and complete bootstrap.
    ///
    /// No peer, key, path, caller predicate or currentness result constructs a
    /// positive enrollment owner. The thirty-two-byte bootstrap was read by
    /// the unchanged ordinary daemon recognition engine.
    #[must_use]
    pub fn new(
        startup: Option<&'startup ProductionNormalRootStartupV1>,
        original: std::os::unix::net::UnixStream,
        bootstrap: [u8; 32],
    ) -> Self {
        Self {
            startup,
            carrier: RetainedCarrier::accepted(original),
            bootstrap,
            deadline: None,
            peer: None,
            credentials: crate::public_api_session::GitCoverageCredentialCustodyV1::root(),
            profile_read: None,
            profile_comparison: None,
            proofs: [None, None],
            local_cuts: None,
            writers: RootCoverageWritersV1::empty(),
            observation: None,
            first_failure: None,
            postcheck: None,
            attempted: false,
            armed: true,
        }
    }

    /// Serves one original metadata flight and retains its actual failed cut.
    ///
    /// Inputs are the daemon's existing signed deployment originals and role
    /// pins. Completion is local transport disposal, not account funding,
    /// remote release, a Root floor or Git backend admission.
    ///
    /// # Errors
    /// Borrows the first resident credential, native, codec or transport cause
    /// and independent bookend/shutdown debt. The daemon must exit while this
    /// owner remains resident; an ordinary return cannot discard failed state.
    pub fn serve_once(
        &mut self,
        packet: &[u8],
        inputs: &super::PolicyDeploymentInputsV1<'_>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        let returned = self.serve(
            packet, inputs, deployment_generation, deployment_key,
            project_generation, project_key,
        );
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
            if let Err(cause) = self.check_parked_originals() {
                self.postcheck.get_or_insert(cause);
            }
            self.carrier.end();
            return Err(self.error());
        }
        self.armed = false;
        Ok(())
    }

    fn serve(
        &mut self,
        packet: &[u8],
        inputs: &super::PolicyDeploymentInputsV1<'_>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), RootFlightFailureV1> {
        if self.attempted || !self.armed {
            return Err(RootFlightFailureV1::Refused);
        }
        self.attempted = true;
        let startup = self.startup.ok_or(RootFlightFailureV1::Refused)?;
        startup.recheck()?;
        if self.bootstrap[..8] != *GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1
            || self.bootstrap[8..24] == [0; 16]
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let cutoff = u64::from_be_bytes(self.bootstrap[24..32].try_into()
            .map_err(|_| RootFlightFailureV1::Refused)?);
        self.deadline = Some(Deadline::capture(cutoff)?);
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        self.carrier.adopt(deadline)?;
        self.peer = Some(startup.observe_controller_policy_peer(self.carrier.stream()?)?);
        self.credentials.capture().map_err(|_| RootFlightFailureV1::Refused)?;

        let root_nonce = super::fresh_root_nonce()?;
        if root_nonce == [0; 16] {
            return Err(RootFlightFailureV1::Refused);
        }
        let mut challenge = [0; 32];
        challenge[..8].copy_from_slice(ROOT_CHALLENGE_MAGIC);
        challenge[8..24].copy_from_slice(&root_nonce);
        challenge[24..].copy_from_slice(&cutoff.to_be_bytes());
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        self.carrier.write(&challenge, &mut original_controller_check(peer))?;

        // Bound the original header before collecting its body. The SAME
        // decoder lends the two parked buffers without another carrier copy.
        let header_index = self.carrier.read_exact(80, &mut original_controller_check(peer))?;
        let body_length = GitCoverageRootSubmissionV1::bounded_body_length(
            self.carrier.bytes(header_index)?,
        )?;
        let body_index = self.carrier.read_exact(body_length, &mut original_controller_check(peer))?;
        let submission = GitCoverageRootSubmissionV1::decode_original_parts(
            self.carrier.bytes(header_index)?, self.carrier.bytes(body_index)?,
        )?;
        let coordinates = submission.coordinates();
        if coordinates.root_nonce != root_nonce || coordinates.cutoff != cutoff
            || coordinates.controller_boot != deadline.boot()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let parts = submission.parts();
        let originals = self.credentials.ready().ok_or(RootFlightFailureV1::Refused)?;
        if parts[0] != originals.enrollment() || parts[1] != originals.catalog() {
            return Err(RootFlightFailureV1::Refused);
        }
        let enrollment = GitCoverageEnrollmentV1::decode(parts[0])?;
        let catalog = GitCoverageCatalogV1::decode(parts[1])?;
        catalog.compare_enrollment(&enrollment)?;
        let (project_pin, deployment_pin) = originals.role_pins();
        use aos_sandbox_core::format::policy_signer_credential::{
            PolicyVerifierRoleV1, decode_policy_verifier_credential_v1,
        };
        let actual_project = decode_policy_verifier_credential_v1(
            PolicyVerifierRoleV1::Project, project_pin,
        ).map_err(GitCoverageDataErrorV1::RoleCredential)?;
        let actual_deployment = decode_policy_verifier_credential_v1(
            PolicyVerifierRoleV1::Deployment, deployment_pin,
        ).map_err(GitCoverageDataErrorV1::RoleCredential)?;
        if actual_project != (project_generation, *project_key)
            || actual_deployment != (deployment_generation, *deployment_key)
            || enrollment.role_generations() != (deployment_generation, project_generation)
            || enrollment.node_epoch().0 != coordinates.node
            || catalog.coordinates().2 != enrollment.commitments()[0]
        {
            return Err(RootFlightFailureV1::Refused);
        }
        enrollment.verify_project_signature(project_key)?;

        self.profile_comparison = Some(startup.compare_git_coverage_profile_v1(
            catalog.coordinates().3, &mut self.profile_read,
        ));
        if !matches!(self.profile_comparison.as_ref(), Some(Ok(()))) {
            return Err(RootFlightFailureV1::Refused);
        }
        self.local_cuts = Some(decode_local_cut_metadata(parts[4], root_nonce, cutoff));
        let Some(Ok(local_cuts)) = &self.local_cuts else {
            return Err(RootFlightFailureV1::Refused);
        };
        // Keep the original ordinary local check and its error priority.
        // Only its rejected cold shape can select the new read-only branch;
        // malformed/Original carriers still return that same old cause.
        let existing_pair = match compare_local_cut_catalog(
            local_cuts, &enrollment, &catalog, root_nonce, false,
        ) {
            Ok(()) => false,
            Err(original) => {
                if existing_pair_mode(parts[2]).is_ok_and(|mode| mode)
                    && existing_pair_mode(parts[3]).is_ok_and(|mode| mode)
                {
                    true
                } else {
                    return Err(original);
                }
            }
        };

        let manifests = originals.root_session_manifests().ok_or(RootFlightFailureV1::Refused)?;
        for (index, role) in [GitCoverageBrokerRoleV1::Mount, GitCoverageBrokerRoleV1::Storage]
            .into_iter().enumerate()
        {
            let manifest = manifests[index].try_into().map_err(|_| RootFlightFailureV1::Refused)?;
            self.proofs[index] = Some(compare_original_broker_pair_v1(
                parts[index + 2], role, manifest, &enrollment, &catalog,
                deadline.boot(), root_nonce, cutoff, deadline.current_git_coverage_boottime()?,
            ));
            if !matches!(self.proofs[index].as_ref(), Some(Ok(_))) {
                return Err(RootFlightFailureV1::Refused);
            }
            if !existing_pair && self.proofs[index].as_ref()
                .and_then(|result| result.as_ref().ok())
                .is_none_or(|pair| pair.readback.is_none())
            {
                return Err(RootFlightFailureV1::Refused);
            }
        }

        // Root takes its original writers only after all remote and local
        // originals are parked. No Root callback or second opener is needed.
        self.writers.capture_existing_once()?;
        let head = self.writers.compare_current_deployment(
            packet, inputs, &enrollment, &catalog, deployment_generation, deployment_key,
            project_generation, project_key, coverage_wall_now(deadline)?,
        )?;
        require_enrollment_wall(&enrollment, coverage_wall_now(deadline)?)?;
        if catalog.coordinates().2 != *head.packet_digest().as_bytes() {
            return Err(RootFlightFailureV1::Refused);
        }
        if existing_pair {
            let authority_nonce = root_denial_nonce(
                RootCoverageWritersV1::original(&self.writers.authority)?,
                ROOT_WRITER_PROFILES[0], &enrollment, &catalog,
            )?;
            let state_nonce = root_denial_nonce(
                RootCoverageWritersV1::original(&self.writers.state)?,
                ROOT_WRITER_PROFILES[1], &enrollment, &catalog,
            )?;
            let birth_nonce = match (authority_nonce, state_nonce) {
                (Some(authority), Some(state)) if authority == state => authority,
                _ => return Err(RootFlightFailureV1::Refused),
            };
            compare_local_cut_catalog(local_cuts, &enrollment, &catalog, birth_nonce, true)?;
            for (index, role) in [GitCoverageBrokerRoleV1::Mount, GitCoverageBrokerRoleV1::Storage]
                .into_iter().enumerate()
            {
                let pair = self.proofs[index].as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(RootFlightFailureV1::Refused)?;
                let proof = GitCoverageBrokerProofV1::decode(parts[index + 2])?;
                pair.readback = Some(compare_borrowed_coverage_pair(
                    &proof, role, &pair.prepare, &pair.read, &enrollment, &catalog,
                    root_nonce, Some(birth_nonce),
                )?);
            }
        }
        self.writers.prepare_denial_once(&enrollment, &catalog, root_nonce)?;
        for index in 0..ROOT_WRITER_PROFILES.len() {
            // Both original transactions/preflights precede this first effect.
            // The same live peer, credentials, clock and actual deployment are
            // checked around EACH ordered crossing, never renewed or replaced.
            self.credentials.recheck_root_inputs_v1().map_err(|_| RootFlightFailureV1::Refused)?;
            self.check_current(packet, inputs, deployment_generation, deployment_key,
                project_generation, project_key)?;
            let returned = self.writers.commit_denial_writer_once(index, &catalog);
            let credentials = self.credentials.recheck_root_inputs_v1()
                .map_err(|_| RootFlightFailureV1::Refused);
            let postchecked = self.check_current(
                packet, inputs, deployment_generation, deployment_key,
                project_generation, project_key,
            );
            if let Err(cause) = credentials {
                self.writers.postcheck.get_or_insert(cause);
            }
            if let Err(cause) = postchecked {
                self.writers.postcheck.get_or_insert(cause);
            }
            returned?;
            if self.writers.postcheck.is_some() {
                return Err(RootFlightFailureV1::Refused);
            }
        }
        self.observation = Some(self.writers.observation(root_nonce, cutoff, &enrollment, &catalog));
        if !matches!(self.observation.as_ref(), Some(Ok(_))) {
            return Err(RootFlightFailureV1::Refused);
        }
        self.credentials.recheck_root_inputs_v1().map_err(|_| RootFlightFailureV1::Refused)?;
        self.check_current(packet, inputs, deployment_generation, deployment_key,
            project_generation, project_key)?;

        let Some(Ok(observation)) = &self.observation else {
            return Err(RootFlightFailureV1::Refused);
        };
        self.carrier.write(&observation.bytes, &mut original_controller_check(peer))?;
        let completed_index = self.carrier.read_exact(32, &mut original_controller_check(peer))?;
        let completed = self.carrier.bytes(completed_index)?;
        if completed[..8] != *ROOT_CAS_DONE_MAGIC || completed[8..24] != root_nonce
            || completed[24..] != cutoff.to_be_bytes()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        self.credentials.recheck_root_inputs_v1().map_err(|_| RootFlightFailureV1::Refused)?;
        self.check_current(packet, inputs, deployment_generation, deployment_key,
            project_generation, project_key)?;
        let mut acknowledged = [0; 32];
        acknowledged[..8].copy_from_slice(ROOT_CAS_END_MAGIC);
        acknowledged[8..24].copy_from_slice(&root_nonce);
        acknowledged[24..].copy_from_slice(&cutoff.to_be_bytes());
        self.carrier.write(&acknowledged, &mut original_controller_check(peer))?;
        self.carrier.finish_sending()?;
        self.carrier.require_eof(&mut original_controller_check(peer))?;
        self.credentials.recheck_root_inputs_v1().map_err(|_| RootFlightFailureV1::Refused)?;
        self.check_current(packet, inputs, deployment_generation, deployment_key,
            project_generation, project_key)
    }

    fn check_current(
        &self,
        packet: &[u8],
        inputs: &super::PolicyDeploymentInputsV1<'_>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), RootFlightFailureV1> {
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        self.carrier.checked(&mut original_controller_check(peer))?;
        let originals = self.credentials.ready().ok_or(RootFlightFailureV1::Refused)?;
        let enrollment = GitCoverageEnrollmentV1::decode(originals.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(originals.catalog())?;
        require_enrollment_wall(&enrollment, coverage_wall_now(deadline)?)?;
        self.writers.compare_current_deployment(packet, inputs, &enrollment, &catalog, deployment_generation,
            deployment_key, project_generation, project_key, coverage_wall_now(deadline)?)?;
        self.carrier.checked(&mut original_controller_check(peer))?;
        Ok(())
    }

    // Independent negative bookends still run with the first owning result
    // already resident. No failed credential or native slot is refreshed.
    fn check_parked_originals(&self) -> Result<(), RootFlightFailureV1> {
        if let Some(startup) = self.startup {
            startup.recheck()?;
        }
        if let Some(peer) = &self.peer {
            self.carrier.checked(&mut original_controller_check(peer))?;
        }
        for slot in [&self.writers.authority, &self.writers.state] {
            if let Some(Ok((journal, _))) = slot {
                journal.validate_held_protected_names()?;
            }
        }
        Ok(())
    }

    fn error(&self) -> GitCoverageRootFlightErrorV1<'_> {
        let cause = match self.writers.failure_source {
            Some(RootWriterFailureSourceV1::Action) => self.writers.cause()
                .or_else(|| self.first_failure.as_ref()
                    .map(|cause| cause as &(dyn std::error::Error + 'static))),
            Some(RootWriterFailureSourceV1::Postcheck) => self.writers.postcheck.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            None => self.credentials.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.profile_read.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| self.profile_comparison.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| self.proofs.iter().find_map(|slot| slot.as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static))))
                .or_else(|| self.local_cuts.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| self.writers.cause())
                .or_else(|| self.observation.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| self.first_failure.as_ref()
                    .map(|cause| cause as &(dyn std::error::Error + 'static))),
        };
        GitCoverageRootFlightErrorV1 {
            cause,
            postcheck: self.postcheck.as_ref().or(self.writers.postcheck.as_ref())
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            receive: self.carrier.receive_failure(),
            shutdown: self.carrier.shutdown_failure(),
        }
    }
}

impl Drop for RootGitCoverageEnrollmentOwnerV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

fn original_controller_check<'loan, 'startup: 'loan>(
    peer: &'loan OriginalControllerPolicyPeerV1<'startup>,
) -> impl FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>)
    -> Result<(), TransportFault> + 'loan
{
    move |stream, chunk| {
        peer.recheck_stream(stream).map_err(ConsumerReadFlightErrorV1::from)?;
        if let Some(chunk) = chunk {
            peer.require_chunk(stream, chunk).map_err(ConsumerReadFlightErrorV1::from)?;
        }
        peer.recheck_stream(stream)
            .map_err(ConsumerReadFlightErrorV1::from).map_err(TransportFault::from)
    }
}

// Unix validity is observed separately from the original BOOTTIME flight.
// This claims no new rollback-resistant clock and never renews that cutoff.
fn coverage_wall_now(deadline: Deadline) -> Result<i64, RootFlightFailureV1> {
    deadline.require_current()?;
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|cause| ConsumerReadFlightErrorV1::Io(std::io::Error::other(cause)))?;
    let now = i64::try_from(elapsed.as_secs()).map_err(|_| RootFlightFailureV1::Refused)?;
    deadline.require_current()?;
    Ok(now)
}

fn require_enrollment_wall(
    enrollment: &GitCoverageEnrollmentV1<'_>,
    now: i64,
) -> Result<(), RootFlightFailureV1> {
    let now = u64::try_from(now).map_err(|_| RootFlightFailureV1::Refused)?;
    let (_, issued, expires) = enrollment.generation_interval();
    if now < issued || now >= expires {
        return Err(RootFlightFailureV1::Refused);
    }
    Ok(())
}

fn compare_local_cut_catalog(
    cuts: &[GitCoverageNativeCutDataV1; 3],
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
    nonce: [u8; 16],
    existing_pair: bool,
) -> Result<(), RootFlightFailureV1> {
    for cut in cuts {
        let member = catalog.members().find(|member| member.profile() == cut.profile)
            .ok_or(RootFlightFailureV1::Refused)?;
        if member.bytes()[72..104] != cut.provision_origin {
            return Err(RootFlightFailureV1::Refused);
        }
        if cut.profile == GitCoverageJournalProfileV1::Controller {
            let birth = enrollment.fixed_owner_birth_recipe_v1(catalog, cut.profile, nonce)?;
            if !existing_pair && cut.last_commit != Some((birth.transaction, birth.commit_sequence)) {
                return Err(RootFlightFailureV1::Refused);
            }
            if existing_pair && cut.last_commit.is_none_or(|(_, sequence)| sequence <= birth.commit_sequence) {
                return Err(RootFlightFailureV1::Refused);
            }
        } else if member.bytes()[104..136] != cut.prefix {
            return Err(RootFlightFailureV1::Refused);
        }
    }
    Ok(())
}

/// Borrows a resident failure and distinct original receive/shutdown debt.
///
/// The actual owning cause and original endpoint remain in their flight. This
/// view cannot release that owner, authorize an account, or establish Drain.
#[derive(Debug)]
pub struct GitCoverageRootFlightErrorV1<'flight> {
    cause: Option<&'flight (dyn std::error::Error + 'static)>,
    postcheck: Option<&'flight (dyn std::error::Error + 'static)>,
    receive: Option<&'flight RetainedSeqpacketReceiveErrorV1>,
    shutdown: Option<&'flight std::io::Error>,
}

impl std::fmt::Display for GitCoverageRootFlightErrorV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cause {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("original Git coverage Root flight is unavailable"),
        }
    }
}

impl std::error::Error for GitCoverageRootFlightErrorV1<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
    }
}

impl GitCoverageRootFlightErrorV1<'_> {
    /// Borrows later peer/cut debt without replacing the first owning cause.
    #[must_use]
    pub fn postcheck_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.postcheck
    }

    /// Borrows the actual lower receive failure, if one was returned.
    #[must_use]
    pub fn receive_failure(&self) -> Option<&RetainedSeqpacketReceiveErrorV1> {
        self.receive
    }

    /// Borrows known cleanup debt; its absence is never release evidence.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootClientPhaseV1 {
    Fresh,
    Checking,
    Challenged,
    Submitted,
    Observed,
    LocallyCompleted,
    Failed,
}

#[derive(Clone, Copy)]
enum RootClientFailureSourceV1 {
    Returned,
    Submission,
    Observation,
    Postcheck,
}

/// Retains one original fixed Root flight under a genuine Controller profile.
///
/// The profile loan comes from outside this owner; it is not a self-reference.
/// The first challenge supplies only correlation DATA. The containing selected
/// startup retains all local owners and this flight through the successor CAS.
/// No method constructs a signer, a currentness token, or a public effect handle.
/// Abandonment of a started or failed flight aborts before original fields drop;
/// only a never-started capsule or verified local completion permits disposal.
pub struct GitCoverageRootClientV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    carrier: RetainedCarrier,
    peer: Option<OriginalNormalRootPeerV1<'profile>>,
    deadline: Option<Deadline>,
    bootstrap: Option<[u8; 32]>,
    root_nonce: Option<[u8; 16]>,
    submission: Option<Result<Vec<u8>, GitCoverageDataErrorV1>>,
    observation: Option<Result<RootCoverageObservationV1, RootFlightFailureV1>>,
    first_failure: Option<RootFlightFailureV1>,
    postcheck_failure: Option<RootFlightFailureV1>,
    failure_source: Option<RootClientFailureSourceV1>,
    phase: RootClientPhaseV1,
}

impl<'profile> GitCoverageRootClientV1<'profile> {
    /// Parks the genuine profile loan before entropy, clocks, or endpoint work.
    #[must_use]
    pub fn new(profile: &'profile ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            profile,
            carrier: RetainedCarrier::empty(),
            peer: None,
            deadline: None,
            bootstrap: None,
            root_nonce: None,
            submission: None,
            observation: None,
            first_failure: None,
            postcheck_failure: None,
            failure_source: None,
            phase: RootClientPhaseV1::Fresh,
        }
    }

    /// Starts the original sixty-second flight and receives its sole challenge.
    ///
    /// # Errors
    /// Borrows the first resident profile, clock, entropy, peer, or transport
    /// failure. A failed or previously started flight cannot reconnect or retry.
    pub fn begin_once(&mut self) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        let result = self.begin();
        self.finish_method(result, RootClientPhaseV1::Challenged)
    }

    fn begin(&mut self) -> Result<(), RootFlightFailureV1> {
        self.enter(RootClientPhaseV1::Fresh)?;
        self.profile.recheck()?;
        self.deadline = Some(Deadline::new_git_coverage()?);
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        let client_nonce = super::fresh_root_nonce()?;
        if client_nonce == [0; 16] {
            return Err(RootFlightFailureV1::Refused);
        }
        let mut bootstrap = [0; 32];
        bootstrap[..8].copy_from_slice(GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1);
        bootstrap[8..24].copy_from_slice(&client_nonce);
        bootstrap[24..].copy_from_slice(&deadline.cutoff().to_be_bytes());
        self.bootstrap = Some(bootstrap);

        self.carrier.connect(deadline)?;
        self.peer = Some(self.profile.observe_original_peer(self.carrier.stream()?)?);
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        let mut check = original_root_check(peer);
        self.carrier.write(
            self.bootstrap.as_ref().ok_or(RootFlightFailureV1::Refused)?, &mut check,
        )?;
        let challenge_index = self.carrier.read_exact(32, &mut check)?;
        let challenge = self.carrier.bytes(challenge_index)?;
        if challenge.get(..8) != Some(ROOT_CHALLENGE_MAGIC.as_slice())
            || challenge.get(24..) != Some(deadline.cutoff().to_be_bytes().as_slice())
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let root_nonce: [u8; 16] = challenge.get(8..24)
            .ok_or(RootFlightFailureV1::Refused)?
            .try_into().map_err(|_| RootFlightFailureV1::Refused)?;
        if root_nonce == [0; 16] {
            return Err(RootFlightFailureV1::Refused);
        }
        self.root_nonce = Some(root_nonce);
        self.carrier.checked(&mut check)?;
        Ok(())
    }

    /// Returns correlation DATA only after fresh original-peer and cut checks.
    ///
    /// # Errors
    /// Borrows the resident first cause outside the challenged phase or after
    /// a failed bookend. The returned nonce, boot, and cutoff are not authority.
    pub fn challenge(&mut self) -> Result<([u8; 16], [u8; 16], u64), GitCoverageRootFlightErrorV1<'_>> {
        let result = (|| {
            self.enter(RootClientPhaseV1::Challenged)?;
            self.check_original()?;
            let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
            let nonce = self.root_nonce.ok_or(RootFlightFailureV1::Refused)?;
            Ok((nonce, deadline.boot(), deadline.cutoff()))
        })();
        match result {
            Ok(coordinates) => {
                self.phase = RootClientPhaseV1::Challenged;
                Ok(coordinates)
            }
            Err(cause) => {
                self.fail(cause);
                Err(self.error())
            }
        }
    }

    /// Parks and sends the five exact original sections without reencoding them.
    ///
    /// # Errors
    /// Borrows the first encoding, phase, peer, or I/O failure. The complete
    /// encoding Result stays resident before any independent postcheck.
    pub fn submit_once(
        &mut self,
        node: [u8; 16],
        original_parts: [&[u8]; 5],
    ) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        let result = self.submit(node, original_parts);
        self.finish_method(result, RootClientPhaseV1::Submitted)
    }

    fn submit(&mut self, node: [u8; 16], original_parts: [&[u8]; 5])
        -> Result<(), RootFlightFailureV1>
    {
        self.enter(RootClientPhaseV1::Challenged)?;
        self.check_original()?;
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        self.submission = Some(GitCoverageRootSubmissionV1::encode(
            GitCoverageRootCoordinatesV1 {
                root_nonce: self.root_nonce.ok_or(RootFlightFailureV1::Refused)?,
                cutoff: deadline.cutoff(),
                controller_boot: deadline.boot(),
                node,
            },
            original_parts,
        ));
        if self.submission.as_ref().is_some_and(Result::is_err) {
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Submission);
        }
        // Parked encoding failure remains primary even when the independent
        // original-peer/cut bookend also fails. Never take/reinsert either.
        if let Err(cause) = self.check_original() {
            self.postcheck_failure.get_or_insert(cause);
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Postcheck);
        }
        if self.submission.as_ref().is_some_and(Result::is_err)
            || self.postcheck_failure.is_some()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        let Some(Ok(bytes)) = self.submission.as_ref() else {
            return Err(RootFlightFailureV1::Refused);
        };
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        let mut check = original_root_check(peer);
        self.carrier.write(bytes, &mut check)?;
        self.carrier.checked(&mut check)?;
        Ok(())
    }

    fn check_original(&self) -> Result<(), RootFlightFailureV1> {
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        self.carrier.checked(&mut original_root_check(peer))?;
        Ok(())
    }

    /// Receives bounded Root enrollment DATA on the same original endpoint.
    ///
    /// The returned observation remains owned by this flight. It supplies no
    /// account, currentness token or allocation permission; the actual cohort
    /// still needs all local-owner bookends and its same-writer successor CAS.
    ///
    /// # Errors
    /// Permanently retains the original transport, framing or comparison
    /// failure. It never reconnects or reconstructs a Root writer from DATA.
    pub fn observe_root_once(&mut self) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        let result = self.observe_root();
        self.finish_method(result, RootClientPhaseV1::Observed)
    }

    fn observe_root(&mut self) -> Result<(), RootFlightFailureV1> {
        self.enter(RootClientPhaseV1::Submitted)?;
        self.check_original()?;
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        let index = self.carrier.read_exact(
            ROOT_OBSERVATION_BYTES, &mut original_root_check(peer),
        )?;
        let Some(Ok(submission)) = &self.submission else {
            return Err(RootFlightFailureV1::Refused);
        };
        let original = GitCoverageRootSubmissionV1::decode(submission)?;
        let parts = original.parts();
        let enrollment = GitCoverageEnrollmentV1::decode(parts[0])?;
        let catalog = GitCoverageCatalogV1::decode(parts[1])?;
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        self.observation = Some(RootCoverageObservationV1::decode(
            self.carrier.bytes(index)?,
            self.root_nonce.ok_or(RootFlightFailureV1::Refused)?,
            deadline.cutoff(), &enrollment, &catalog,
        ));
        if self.observation.as_ref().is_some_and(Result::is_err) {
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Observation);
        }

        // A parse failure stays primary while the independent actual peer/cut
        // postcheck still runs. Both owning results remain in this flight.
        if let Err(cause) = self.check_original() {
            self.postcheck_failure.get_or_insert(cause);
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Postcheck);
        }
        if self.observation.as_ref().is_some_and(Result::is_err)
            || self.postcheck_failure.is_some()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        Ok(())
    }

    // Only the actual account attempt's Committed phase can invoke this. The
    // protocol acknowledgement is a same-peer bookend, not a remote receipt
    // for release, funding, Root post-EOF checks or destruction of its owners.
    fn finish_after_cas_once(&mut self) -> Result<(), GitCoverageRootFlightErrorV1<'_>> {
        let returned = self.finish_after_cas();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Returned);
        }
        if let Err(cause) = self.check_original() {
            self.postcheck_failure.get_or_insert(cause);
            self.failure_source.get_or_insert(RootClientFailureSourceV1::Postcheck);
        }
        if self.first_failure.is_some() || self.postcheck_failure.is_some() {
            self.phase = RootClientPhaseV1::Failed;
            self.carrier.end();
            return Err(self.error());
        }
        self.phase = RootClientPhaseV1::LocallyCompleted;
        Ok(())
    }

    fn finish_after_cas(&mut self) -> Result<(), RootFlightFailureV1> {
        self.enter(RootClientPhaseV1::Observed)?;
        self.check_original()?;
        let deadline = self.deadline.ok_or(RootFlightFailureV1::Refused)?;
        let nonce = self.root_nonce.ok_or(RootFlightFailureV1::Refused)?;
        let peer = self.peer.as_ref().ok_or(RootFlightFailureV1::Refused)?;
        let mut completed = [0; 32];
        completed[..8].copy_from_slice(ROOT_CAS_DONE_MAGIC);
        completed[8..24].copy_from_slice(&nonce);
        completed[24..].copy_from_slice(&deadline.cutoff().to_be_bytes());
        self.carrier.write(&completed, &mut original_root_check(peer))?;
        let acknowledged_index = self.carrier.read_exact(32, &mut original_root_check(peer))?;
        let acknowledged = self.carrier.bytes(acknowledged_index)?;
        if acknowledged[..8] != *ROOT_CAS_END_MAGIC || acknowledged[8..24] != nonce
            || acknowledged[24..] != deadline.cutoff().to_be_bytes()
        {
            return Err(RootFlightFailureV1::Refused);
        }
        self.carrier.finish_sending()?;
        self.carrier.require_eof(&mut original_root_check(peer))?;
        self.check_original()
    }

    fn enter(&mut self, expected: RootClientPhaseV1) -> Result<(), RootFlightFailureV1> {
        if self.phase != expected || self.first_failure.is_some() || self.postcheck_failure.is_some() {
            return Err(RootFlightFailureV1::Refused);
        }
        // Cancellation/unwind leaves Checking, which no method can resume.
        self.phase = RootClientPhaseV1::Checking;
        Ok(())
    }

    fn fail(&mut self, cause: RootFlightFailureV1) {
        if self.first_failure.is_none() {
            self.first_failure = Some(cause);
        }
        self.failure_source.get_or_insert(RootClientFailureSourceV1::Returned);
        self.phase = RootClientPhaseV1::Failed;
        self.carrier.end();
    }

    fn finish_method(&mut self, result: Result<(), RootFlightFailureV1>, success: RootClientPhaseV1)
        -> Result<(), GitCoverageRootFlightErrorV1<'_>>
    {
        match result {
            Ok(()) => {
                self.phase = success;
                Ok(())
            }
            Err(cause) => {
                self.fail(cause);
                Err(self.error())
            }
        }
    }

    fn error(&self) -> GitCoverageRootFlightErrorV1<'_> {
        let cause = match self.failure_source {
            Some(RootClientFailureSourceV1::Submission) => self.submission.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(RootClientFailureSourceV1::Observation) => self.observation.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(RootClientFailureSourceV1::Postcheck) => self.postcheck_failure.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(RootClientFailureSourceV1::Returned) => self.first_failure.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            None => None,
        };
        GitCoverageRootFlightErrorV1 {
            cause,
            postcheck: self.postcheck_failure.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            receive: self.carrier.receive_failure(),
            shutdown: self.carrier.shutdown_failure(),
        }
    }
}

impl Drop for GitCoverageRootClientV1<'_> {
    fn drop(&mut self) {
        if !matches!(self.phase, RootClientPhaseV1::Fresh | RootClientPhaseV1::LocallyCompleted) {
            std::process::abort();
        }
    }
}

fn original_root_check<'loan, 'profile: 'loan>(peer: &'loan OriginalNormalRootPeerV1<'profile>)
    -> impl FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), TransportFault> + 'loan
{
    move |stream, chunk| {
        peer.recheck_stream(stream).map_err(ConsumerReadFlightErrorV1::from)?;
        if let Some(chunk) = chunk {
            peer.require_chunk(stream, chunk).map_err(ConsumerReadFlightErrorV1::from)?;
        }
        peer.recheck_stream(stream)
            .map_err(ConsumerReadFlightErrorV1::from).map_err(TransportFault::from)
    }
}

/// Retains the actual codec/admission cause, never an error-string surrogate.
#[derive(Debug, thiserror::Error)]
enum EnrollmentComparisonErrorV1 {
    #[error(transparent)]
    Data(#[from] GitCoverageDataErrorV1),
    #[error(transparent)]
    Manifest(#[from] BrokerSessionManifestErrorV1),
    #[error(transparent)]
    Checkpoint(#[from] HistoricalCheckpointErrorV1),
    #[error(transparent)]
    Projection(#[from] BrokerSessionProjectionError),
    #[error(transparent)]
    Traffic(#[from] BrokerSessionSequenceError),
    #[error(transparent)]
    Method(#[from] AuthenticatedBrokerMethodErrorV1),
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error("original Git coverage enrollment comparison differs")]
    Refused,
}

type ComparisonResult<T> = Result<T, EnrollmentComparisonErrorV1>;

/// Owns both original authenticated results until the Root postchecks finish.
///
/// No constructor is exported, and neither result is a live remote loan.
struct OriginalBrokerCoveragePairV1 {
    checkpoint: HistoricalSessionCheckpointV1,
    prepare: AuthenticatedBrokerMethodOutcomeV1,
    read: AuthenticatedBrokerMethodOutcomeV1,
    readback: Option<GitCoverageOutcomeFieldsV1>,
}

// Every supplied coordinate is comparison DATA borrowed from the containing
// Root flight. This helper creates no peer, signer, Session or currentness.
fn compare_original_broker_pair_v1(
    bytes: &[u8],
    expected_role: GitCoverageBrokerRoleV1,
    original_manifest: &[u8; BROKER_SESSION_MANIFEST_BYTES],
    enrollment: &GitCoverageEnrollmentV1<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
    original_boot: [u8; 16],
    root_nonce: [u8; 16],
    original_cut: u64,
    now_boottime_nanoseconds: u64,
) -> ComparisonResult<OriginalBrokerCoveragePairV1> {
    let proof = GitCoverageBrokerProofV1::decode(bytes)?;
    if proof.role() != expected_role
        || original_boot == [0; 16]
        || root_nonce == [0; 16]
        || now_boottime_nanoseconds >= original_cut
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    catalog.compare_enrollment(enrollment)?;

    let manifest = BrokerSessionManifestV1::decode(original_manifest)?;
    let (protocol, version, prepare_method, read_method) = match expected_role {
        GitCoverageBrokerRoleV1::Mount => (
            BrokerSessionProtocolV1::Mount,
            (2, 0),
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1,
            BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1,
        ),
        GitCoverageBrokerRoleV1::Storage => (
            BrokerSessionProtocolV1::Storage,
            (1, 0),
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1,
            BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1,
        ),
    };
    if manifest.protocol() != protocol
        || manifest.protocol_version() != version
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.node_id() != enrollment.node_epoch().0
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    manifest.require_all_active()?;

    let [checkpoint_bytes, prepare_request, prepare_outcome, read_request, read_outcome] =
        proof.parts();
    let checkpoint = HistoricalSessionCheckpointV1::decode(checkpoint_bytes)?;
    let recorded_context = checkpoint.context();
    let independent_context = manifest.verification_context(
        original_boot, recorded_context.client_process(), recorded_context.broker_process(),
    )?;
    if independent_context != *recorded_context {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let transcript = checkpoint.verify()?;

    // These five carriers contain no preceding traffic. Replaying from the
    // actual signed provisional hello therefore requires sequences1 and2;
    // a later session pair must not fabricate an omitted prefix or scalar seed.
    let initial = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)?;
    let (prepare, next) = authenticate_original_exchange_v1(
        &initial, &checkpoint, prepare_method, prepare_request, prepare_outcome,
        original_cut, now_boottime_nanoseconds,
    )?;
    let (read, _) = authenticate_original_exchange_v1(
        &next, &checkpoint, read_method, read_request, read_outcome,
        original_cut, now_boottime_nanoseconds,
    )?;

    let comparison = prepare.request().git_coverage_request_v1()
        .ok_or(EnrollmentComparisonErrorV1::Refused)?.comparison()?;
    let readback = match comparison.prepare_mode() {
        aos_sandbox_core::format::git_upload_enrollment::GitCoveragePrepareModeV1::Original => {
            Some(compare_borrowed_coverage_pair(
                &proof, expected_role, &prepare, &read, enrollment, catalog, root_nonce, None,
            )?)
        }
        aos_sandbox_core::format::git_upload_enrollment::GitCoveragePrepareModeV1::ExistingPair => None,
    };

    Ok(OriginalBrokerCoveragePairV1 { checkpoint, prepare, read, readback })
}

// This preliminary mode is only a routing discriminator. The complete same
// carriers are authenticated and compared below before Root acquires writers.
fn existing_pair_mode(bytes: &[u8]) -> ComparisonResult<bool> {
    let proof = GitCoverageBrokerProofV1::decode(bytes)?;
    let request = decode_canonical_request_v1(proof.parts()[1])?;
    let wire = aos_proto::aos::sandbox::local::v1::GitProjectCoverageRequestV1::decode_from_slice(
        &request.message().body,
    ).map_err(|_| EnrollmentComparisonErrorV1::Refused)?;
    let comparison = aos_sandbox_core::format::git_upload_enrollment::GitCoverageRequestV1::decode(
        &wire.coverage,
    )?;
    Ok(comparison.prepare_mode()
        == aos_sandbox_core::format::git_upload_enrollment::GitCoveragePrepareModeV1::ExistingPair)
}

// One canonical packet/admission body advances both original exchanges. The
// returned state is historical DATA, not a Session or a send/replay permit.
fn authenticate_original_exchange_v1(
    traffic: &BrokerSessionTrafficStateV1,
    checkpoint: &HistoricalSessionCheckpointV1,
    method: BrokerMethod,
    request_bytes: &[u8],
    outcome_bytes: &[u8],
    original_cut: u64,
    now_boottime_nanoseconds: u64,
) -> ComparisonResult<(AuthenticatedBrokerMethodOutcomeV1, Box<BrokerSessionTrafficStateV1>)> {
    if request_bytes.len() > GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1
        || outcome_bytes.len() > GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let canonical = decode_canonical_request_v1(request_bytes)?;
    if canonical.signed_artifact().method() != method
        || !canonical.message().descriptors.is_empty()
    {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)?;
    let peer = checkpoint.peer();
    let policy = PeerPolicy {
        uid: peer.uid,
        gid: Some(peer.gid),
        audience: checkpoint.context().audience(),
    };
    let (request, pending) = match prepare_client_sent_authenticated_broker_method_request_v1(
        traffic, request_bytes, None, 0, peer, policy, now_boottime_nanoseconds,
        bindings, checkpoint.context(),
    )? {
        AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic } => {
            (request, next_traffic)
        }
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
            return Err(EnrollmentComparisonErrorV1::Refused);
        }
    };
    if request.deadline_boottime_nanoseconds() > original_cut {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    let canonical_outcome = decode_canonical_response_v1(outcome_bytes)?;
    if !canonical_outcome.message().descriptors.is_empty() {
        return Err(EnrollmentComparisonErrorV1::Refused);
    }
    match admit_client_received_authenticated_broker_method_outcome_v1(
        &pending, &request, outcome_bytes, None, 0, checkpoint.context(),
    )? {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, next_traffic }
            if matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. }) => {
                Ok((outcome, next_traffic))
            }
        _ => Err(EnrollmentComparisonErrorV1::Refused),
    }
}

fn original_coverage_readback_v1(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    fence: &GitCoverageFenceV1<'_>,
) -> ComparisonResult<GitCoverageOutcomeFieldsV1> {
    let original = outcome.request().git_coverage_request_v1()
        .ok_or(EnrollmentComparisonErrorV1::Refused)?;
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(EnrollmentComparisonErrorV1::Refused);
    };
    let response = compare_git_project_coverage_response_v1(exact_body, original)?;
    let readback = GitCoverageOutcomeV1::decode(&response.coverage)?;
    readback.compare_fence(fence)?;
    Ok(readback.fields())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical comparison DATA only. These fixtures construct no Journal,
    // authenticated peer, currentness owner, enrollment or positive admission.
    fn local_cut_data() -> [GitCoverageNativeCutDataV1; 3] {
        [
            GitCoverageNativeCutDataV1 {
                profile: GitCoverageJournalProfileV1::Controller,
                provision_origin: [1; 32],
                prefix: [2; 32],
                transactions: 1,
                records: 2,
                last_commit: Some(([3; 16], 4)),
            },
            GitCoverageNativeCutDataV1 {
                profile: GitCoverageJournalProfileV1::Source,
                provision_origin: [4; 32],
                prefix: [5; 32],
                transactions: 0,
                records: 0,
                last_commit: None,
            },
            GitCoverageNativeCutDataV1 {
                profile: GitCoverageJournalProfileV1::CacheBootstrap,
                provision_origin: [6; 32],
                prefix: [7; 32],
                transactions: 1,
                records: 1,
                last_commit: Some(([8; 16], 3)),
            },
        ]
    }

    fn metadata(cuts: &[GitCoverageNativeCutDataV1; 3]) -> Vec<u8> {
        encode_local_cut_metadata([9; 16], 10, [&cuts[0], &cuts[1], &cuts[2]])
            .unwrap()
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let checksum_offset = LOCAL_CUT_BYTES - 32;
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(LOCAL_CUT_DOMAIN)
            .chain_update(&bytes[..checksum_offset])
            .finalize()
            .into();
        bytes[checksum_offset..].copy_from_slice(&checksum);
    }

    #[test]
    fn root_response_keeps_authority_and_state_in_distinct_fixed_entries() {
        let authority = root_entry_offset(GitCoverageJournalProfileV1::RootAuthority).unwrap();
        let state = root_entry_offset(GitCoverageJournalProfileV1::RootPolicyState).unwrap();

        assert_eq!(authority, 32);
        assert_eq!(authority + ROOT_OBSERVATION_ENTRY_BYTES, state);
        assert_eq!(state + ROOT_OBSERVATION_ENTRY_BYTES + 32 + 32, ROOT_OBSERVATION_BYTES);
        assert_eq!(ROOT_OBSERVATION_BYTES, 1200);
        assert!(root_entry_offset(GitCoverageJournalProfileV1::Source).is_err());
        assert!(root_entry_offset(GitCoverageJournalProfileV1::CacheBootstrap).is_err());
    }

    #[test]
    fn local_metadata_preserves_source_empty_without_a_fabricated_commit() {
        let original = local_cut_data();
        let bytes = metadata(&original);

        let decoded = decode_local_cut_metadata(&bytes, [9; 16], 10).unwrap();

        assert_eq!(bytes.len(), 376);
        assert!(decoded == original);
        assert!(decoded[1].last_commit.is_none());
        assert_eq!((decoded[1].transactions, decoded[1].records), (0, 0));
        assert_ne!(decoded[1].provision_origin, [0; 32]);
        assert_ne!(decoded[1].prefix, [0; 32]);
    }

    #[test]
    fn local_metadata_empty_is_not_absence_or_cache_bootstrap_substitution() {
        let original = local_cut_data();
        let mut changed = original;
        changed[1].provision_origin = [0; 32];
        assert!(encode_local_cut_metadata([9; 16], 10,
            [&changed[0], &changed[1], &changed[2]]).is_err());

        changed = original;
        changed[1].profile = GitCoverageJournalProfileV1::CacheBootstrap;
        assert!(encode_local_cut_metadata([9; 16], 10,
            [&changed[0], &changed[1], &changed[2]]).is_err());

        changed = original;
        changed[2].last_commit = None;
        changed[2].transactions = 0;
        changed[2].records = 0;
        assert!(encode_local_cut_metadata([9; 16], 10,
            [&changed[0], &changed[1], &changed[2]]).is_err());
    }

    #[test]
    fn local_metadata_requires_actual_complete_native_frame_counts() {
        let mut changed = local_cut_data();
        changed[0].last_commit = Some(([3; 16], 5));
        assert!(encode_local_cut_metadata([9; 16], 10,
            [&changed[0], &changed[1], &changed[2]]).is_err());

        changed = local_cut_data();
        changed[1].records = 1;
        assert!(encode_local_cut_metadata([9; 16], 10,
            [&changed[0], &changed[1], &changed[2]]).is_err());
    }

    #[test]
    fn local_metadata_binds_nonce_cut_and_exact_extent() {
        let bytes = metadata(&local_cut_data());

        assert!(decode_local_cut_metadata(&bytes, [8; 16], 10).is_err());
        assert!(decode_local_cut_metadata(&bytes, [9; 16], 11).is_err());
        assert!(decode_local_cut_metadata(&bytes[..bytes.len() - 1], [9; 16], 10).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(decode_local_cut_metadata(&extra, [9; 16], 10).is_err());
    }

    #[test]
    fn local_metadata_rejects_rechecksummed_unknown_flags_and_empty_uuid_forgery() {
        let original = metadata(&local_cut_data());
        let source_row = 32 + LOCAL_CUT_ROW_BYTES;

        let mut changed = original.clone();
        changed[source_row + 2..source_row + 4].copy_from_slice(&2_u16.to_be_bytes());
        refresh_checksum(&mut changed);
        assert!(decode_local_cut_metadata(&changed, [9; 16], 10).is_err());

        changed = original;
        changed[source_row + 68] = 1;
        refresh_checksum(&mut changed);
        assert!(decode_local_cut_metadata(&changed, [9; 16], 10).is_err());
    }
}
