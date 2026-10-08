//! Routes closed coverage DATA through the existing authenticated outcome engine.
//!
//! The concrete domain owner owns the permanent denial and native readback.
//! This child adds neither a transport nor a signature/currentness engine;
//! it lends the original signed request into the same execution sandwich.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, GitProjectCoverageRequestV1, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion};
use aos_sandbox_storage::DormantStorageBrokerCallsiteV1 as _;
use sha2::{Digest as _, Sha256};
use buffa::Message as _;

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerExecutionFailureV1,
    DormantReceivedBrokerRequestV1,
};
use crate::ProtectedBrokerOutcomeCommitResultV1;

pub(crate) fn is_mount(method: BrokerMethod) -> bool {
    matches!(method,
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1)
}

pub(crate) fn is_storage(method: BrokerMethod) -> bool {
    matches!(method,
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1)
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Encodes the protected checkpoint for the retained Git coverage outcome.
    ///
    /// # Errors
    /// Rejects an invalid byte bound, changed outcome or connection peer, or
    /// missing or mismatched protected checkpoint; propagates journal failures.
    pub fn capture_git_coverage_checkpoint_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, crate::BrokerSessionSecurityError> {
        self.0.capture_git_coverage_checkpoint_v1(currentness, maximum_bytes)
    }

    /// Compares the retained Git coverage outcome against its protected session.
    ///
    /// # Errors
    /// Rejects a non-coverage method or changed outcome, session, or connection
    /// peer; propagates protected journal failures.
    pub fn compare_git_coverage_outcome_v1(
        &mut self,
        currentness: &crate::ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        self.0.compare_git_coverage_outcome_v1(currentness)
    }

    /// Prepares one of the four fixed Git coverage methods with its original cut.
    ///
    /// The payload and cutoff are correlation DATA from the retained enrollment
    /// attempt. The session engine authenticates the request and admits only
    /// the original authorization-free sequence-one or sequence-two exchange.
    ///
    /// # Errors
    /// Rejects another method, noncanonical or oversized coverage DATA, or an
    /// occupied original sequence; propagates session preparation failures.
    pub fn prepare_git_coverage_request_v1(
        &mut self,
        method: BrokerMethod,
        original_body: &[u8],
        original_cut: u64,
    ) -> Result<super::DormantBrokerRequestPreparationV1, crate::BrokerSessionSecurityError> {
        if !is_mount(method) && !is_storage(method) {
            return Err(crate::BrokerSessionSecurityError::manifest("Git coverage client method"));
        }
        // Validate canonical bounds before copying the payload into the same
        // wire builder. This is not enrollment or remote-owner admission.
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageRequestV1::decode(original_body)
            .map_err(|_| crate::BrokerSessionSecurityError::manifest("Git coverage client DATA"))?;
        let original_sequence = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1 => 1,
            BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => 2,
            _ => return Err(crate::BrokerSessionSecurityError::manifest("Git coverage client method")),
        };

        self.prepare_authenticated_request_with_original_cut(
            method,
            |coordinates| {
                let version = coordinates.protocol_version();
                let request = GitProjectCoverageRequestV1 {
                    header: Some(RequestHeader {
                        protocol_major: version.major().into(),
                        protocol_minor: version.minor().into(),
                        request_id: coordinates.request_id().to_vec(),
                        audience: coordinates.audience().into(),
                        deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
                        maximum_response_bytes: coordinates.maximum_response_bytes(),
                        ..Default::default()
                    }).into(),
                    coverage: original_body.to_vec(),
                    ..Default::default()
                };
                let body = request.encode_to_vec();
                if body.len() > aos_sandbox_protocol::git_project_coverage::GIT_COVERAGE_CLEARED_REQUEST_MAXIMUM_BYTES_V1 {
                    return Err(crate::BrokerSessionSecurityError::manifest("Git coverage request bound"));
                }
                Ok(BrokerRequestEnvelope { method: method.into(), body, ..Default::default() })
            },
            // The existing session engine chooses and authenticates this
            // sequence. Refuse before durable reservation if other traffic
            // already occupied either original exchange; never reseed it.
            |request| {
                request.authorization().is_none()
                    && request.client_sequence() == original_sequence
            },
            Some(original_cut),
        )
    }

    /// Appends or reads the same Mount denial fence before signing its DATA.
    ///
    /// # Errors
    /// Returns original request or ambiguous-outcome custody on a wrong route,
    /// changed Session, rejected domain comparison or incomplete native commit.
    #[doc(hidden)]
    pub fn execute_mount_git_coverage_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_mount::DormantMountBrokerCallErrorV1>,
    > {
        let matches = is_mount(request.0.method()) && request.0.authorization().is_none();
        let (request, context) = self.begin_execution(request, matches)?;
        let signed = &request.0;
        let body_digest = ObjectDigest::from_bytes(Sha256::digest(signed.exact_body()).into());
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());

        let response = match mount.consume_authenticated_git_coverage_v1(
            signed.method(), signed.exact_body(), signed.request_id(), body_digest,
            signed.peer(), signed.peer_policy(), version, context.boot_id(),
        ) {
            Ok(response) => response,
            Err(cause) => return Err(Self::unknown_domain(request, cause)),
        };
        self.finish_observed_success(request, response)
    }

    /// Appends or reads the same Storage denial fence with its real output owner.
    ///
    /// The output custody stays borrowed from the daemon. Neither a caller
    /// digest nor an absent output owner can replace that original ledger.
    ///
    /// # Errors
    /// Returns original request or ambiguous-outcome custody on a wrong route,
    /// changed Session, rejected domain comparison or incomplete native commit.
    #[doc(hidden)]
    pub fn execute_storage_git_coverage_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        let matches = is_storage(request.0.method()) && request.0.authorization().is_none();
        let (request, context) = self.begin_execution(request, matches)?;
        let signed = &request.0;
        let body_digest = ObjectDigest::from_bytes(Sha256::digest(signed.exact_body()).into());
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());

        let response = match storage.consume_authenticated_git_coverage_v1(
            signed.method(), signed.exact_body(), signed.request_id(), body_digest,
            signed.peer(), signed.peer_policy(), version, context.boot_id(), output,
        ) {
            Ok(response) => response,
            Err(cause) => return Err(Self::unknown_domain(request, cause)),
        };
        self.finish_observed_success(request, response)
    }
}
