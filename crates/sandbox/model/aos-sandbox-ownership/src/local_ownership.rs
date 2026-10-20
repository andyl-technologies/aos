//! Protected local lease issuance under the original paid service custody.
//!
//! The authority commits an unsigned claim before using its fixed signing
//! original, verifies the resulting generation, nonce, interval, signatures, and
//! exact prior-lease CAS against a live paired clock, and commits all returned
//! artifacts before exposing them. Authenticated Query/CompleteOrResume names
//! the exact durable intent; retry always uses the original claim binding.
//! This owner serves the local ownership daemon independently of coordinator
//! transport. Existing protected file names and canonical records are retained;
//! their historical coordinator spelling does not grant cross-host exclusivity.
//!

use aos_sandbox_model::format::decode_trust_policy;
use aos_sandbox_model::{
    DecodeLimits, KeyUsage, MediaType, OwnershipLeaseTrustAnchor, PortableMediaType,
    RawClockProvenance, RawPairedClockSample, SignaturePurpose, descriptor_for_bytes,
};
use aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1;
use aos_sandbox_ownership_protocol::protocol::{
    NegotiatedOwnershipSessionV1, OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1,
};

use crate::ownership_authority::{
    DurableOwnershipAuthority, DurableOwnershipAuthorityError, DurableOwnershipBeginOutcome,
    DurableOwnershipQueryOutcome, OwnershipAuthorityVerifier, OwnershipClaimV1,
    ProtectedOwnershipClockError, UnverifiedOwnershipLeaseResponse,
};
use crate::ownership_service::{
    OwnershipProtocolServiceError,
};

mod bootstrap;
mod format;
mod pricing;
mod signing;

pub(crate) use signing::{LocalOwnershipSigningOriginalV1, LocalOwnershipSigningAttemptV1};
pub(crate) use pricing::{fixed_startup_demand_v1, history_capture_demand_v1, retained_signing_demand_v1, retained_paired_clock_demand_v1, fixed_request_demand_v1, request_io_demand_v1};
use format::decode_bootstrap;

const PROTECTED_MULTI_NODE_DIRECTORY: &str = "/var/lib/aos/sandbox/multi-node";
const PROTECTED_LEASE_BOOTSTRAP: &str = "coordinator-ownership-bootstrap-v1.bin";
const PROTECTED_CLOCK_PROVENANCE: [u8; 16] = *b"AOSMULTICLOCKV1!";
const MAXIMUM_BOOTSTRAP_BYTES: usize = 128 * 1024;

/// Reports retained fixed local authority startup or native failure.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedLeaseAuthorityErrorV1 {
    /// The fixed protected journal could not be opened or authenticated.
    #[error("protected multi-node lease authority failed: {0}")]
    Authority(#[from] DurableOwnershipAuthorityError),
    /// The original bootstrap files or trust decoding retained a failure.
    #[error("fixed local ownership trust bootstrap failed: {0}")]
    Bootstrap(Box<ProtectedLocalBootstrapFailureV1>),
    /// The fixed credential or bootstrap key join retained a failure.
    #[error("fixed local ownership signing credential failed: {0}")]
    Signing(Box<ProtectedLocalSigningFailureV1>),
    /// Startup retains its returned native state, key and clock originals.
    #[error("local ownership startup retained a native failure: {0}")]
    Startup(Box<ProtectedLocalOwnershipStartupFailureV1>),
    /// A claim names a node other than the fixed local credential.
    #[error("ownership claim does not name the original local node")]
    ForeignNode,
    /// The genuine receiving original refused its closed startup interval.
    #[error("original ownership receiving admission is closed: {0}")]
    Receiving(#[from] crate::OwnershipReceivingClosedV1),
}

/// Retains failed bootstrap file acquisition and trust decoding.
pub struct ProtectedLocalBootstrapFailureV1 {
    original: bootstrap::LocalBootstrapOriginalV1,
}

impl std::fmt::Debug for ProtectedLocalBootstrapFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ProtectedLocalBootstrapFailureV1").finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProtectedLocalBootstrapFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("fixed local ownership trust bootstrap failed")
    }
}

impl std::error::Error for ProtectedLocalBootstrapFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

/// Retains a failed fixed credential original without exposing its key or files.
pub struct ProtectedLocalSigningFailureV1 {
    original: LocalOwnershipSigningOriginalV1,
    bootstrap: bootstrap::LocalBootstrapOriginalV1,
}

impl std::fmt::Debug for ProtectedLocalSigningFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ProtectedLocalSigningFailureV1").finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProtectedLocalSigningFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("fixed local ownership signing credential failed")
    }
}

impl std::error::Error for ProtectedLocalSigningFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Keeps the actual reached startup originals and returned native cause.
pub struct ProtectedLocalOwnershipStartupFailureV1 {
    durable: Option<DurableOwnershipAuthority>,
    captured_journal: Option<crate::Journal>,
    recovery: Option<crate::RecoveryReport>,
    receiving_error: Option<crate::OwnershipReceivingClosedV1>,
    history_error: Option<crate::ownership_authority::LocalHistoryCaptureFailureV1>,
    issuer: LocalOwnershipSigningOriginalV1,
    clock: ProtectedLeaseClockV1,
    bootstrap: bootstrap::LocalBootstrapOriginalV1,
}

impl std::fmt::Debug for ProtectedLocalOwnershipStartupFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ProtectedLocalOwnershipStartupFailureV1").finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProtectedLocalOwnershipStartupFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("local ownership startup is unavailable")
    }
}

impl std::error::Error for ProtectedLocalOwnershipStartupFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.clock.failure()
            .or_else(|| self.receiving_error.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.history_error.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

/// Owns the fixed protected ownership bootstrap, signing credential and lease journal.
///
/// Construction accepts no trust anchor, public key, issuer, clock, path, or
/// generation from its caller. The ownership policy and exact signing key
/// come from protected fixed files; the durable reducer independently
/// verifies every response before making its bytes observable.
pub struct ProtectedFixedLocalLeaseOwnerV1 {
    authority: ProtectedLocalLeaseAuthorityV1,
}

impl ProtectedFixedLocalLeaseOwnerV1 {
    /// Opens the complete fixed-root local ownership composition.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] unless the protected
    /// bootstrap, matching fixed ownership credential, lease journal, and
    /// live clock owner all open and authenticate exactly.
    pub(crate) fn open_fixed_protected(
        receiving: &mut crate::OwnershipServiceReceivingLoanV1<'_>,
    ) -> Result<Self, ProtectedLeaseAuthorityErrorV1> {
        receiving.admit_local_authority_startup_once_v1()?;
        let (verifier, issuer, bootstrap) = load_fixed_ownership_bootstrap()?;
        Ok(Self {
            authority: ProtectedLocalLeaseAuthorityV1::open_fixed_protected(receiving, verifier, issuer, bootstrap)?,
        })
    }

    /// Borrows the first retained local native or signing failure.
    #[must_use]
    pub fn retained_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.authority.durable.local_native_failure().or_else(|| {
            self.authority.signing.values().find_map(|attempt| attempt.failure(&self.authority.clock))
        })
    }

    pub(crate) fn authority(&self) -> &aos_sandbox_model::model::KeyReference {
        self.authority.durable.authority()
    }

    pub(crate) fn handle_paid_v1(
        &mut self,
        funding: &mut crate::ownership_component::funding::OwnershipOperationFundingLoanV1<'_>,
        session: &NegotiatedOwnershipSessionV1,
        request: &OwnershipRequestEnvelopeV1,
    ) -> LocalOwnershipProtocolAttemptV1 {
        let mut attempt = LocalOwnershipProtocolAttemptV1 { query: None, begin: None, response: None };
        attempt.response = Some((|| {
            crate::ownership_service::validate_service_session(session, self.authority())?;
            let request = session.validate_request_parts(*request.session_binding(),
                request.method(), request.body().clone())?;
            use aos_sandbox_ownership_protocol::protocol::OwnershipRequestBodyV1 as Body;
            let outcome = match request.body() {
                Body::Query(reference) => {
                    attempt.query = Some(self.authority.durable.query_local(funding, *reference));
                    crate::ownership_service::query_outcome_ref(attempt.query.as_ref()
                        .ok_or(OwnershipProtocolServiceError::InvalidSession)?)
                }
                Body::Begin(claim) => {
                    if self.authority.issuer.require_local_claim(claim).is_err() {
                        aos_sandbox_ownership_protocol::protocol::OwnershipResponseOutcomeV1::Error(
                            aos_sandbox_ownership_protocol::protocol::OwnershipProtocolErrorCodeV1::InvalidRequest)
                    } else {
                        attempt.begin = Some(self.authority.durable.begin_local(funding, claim));
                        crate::ownership_service::begin_outcome_ref(attempt.begin.as_ref()
                            .ok_or(OwnershipProtocolServiceError::InvalidSession)?, claim.action())
                    }
                }
                Body::CompleteOrResume(reference) => self.authority.complete_protocol(funding, *reference, &mut attempt),
            };
            Ok(session.response(&request, outcome)?)
        })());
        attempt
    }
}

pub(crate) struct LocalOwnershipProtocolAttemptV1 {
    query: Option<Result<DurableOwnershipQueryOutcome, DurableOwnershipAuthorityError>>,
    begin: Option<Result<DurableOwnershipBeginOutcome, DurableOwnershipAuthorityError>>,
    pub(crate) response: Option<Result<OwnershipResponseEnvelopeV1, OwnershipProtocolServiceError>>,
}

impl LocalOwnershipProtocolAttemptV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.query.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.begin.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.response.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}

/// Owns one fixed protected lease journal, issuer, and live paired clock source.
///
/// The issuer is deliberately private and has no signing method on this API.
/// Claims can reach it only after durable admission and exact CAS validation.
struct ProtectedLocalLeaseAuthorityV1 {
    durable: DurableOwnershipAuthority,
    issuer: LocalOwnershipSigningOriginalV1,
    clock: ProtectedLeaseClockV1,
    signing: std::collections::BTreeMap<[u8; 16], LocalOwnershipSigningAttemptV1>,
    bootstrap: bootstrap::LocalBootstrapOriginalV1,
    recovery: crate::RecoveryReport,
    funding_refusal: DurableOwnershipAuthorityError,
}

impl ProtectedLocalLeaseAuthorityV1 {
    /// Opens the fixed-root owner with one protected verifier generation.
    ///
    /// This constructs no socket, listener, task, readiness marker, or service
    /// registration. The supplied issuer becomes inaccessible except through
    /// the durable issue and recovery operations below.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] when the fixed protected
    /// journal cannot be opened or its full history fails authentication.
    fn open_fixed_protected(
        receiving: &mut crate::OwnershipServiceReceivingLoanV1<'_>,
        verifier: OwnershipAuthorityVerifier,
        issuer: LocalOwnershipSigningOriginalV1,
        bootstrap: bootstrap::LocalBootstrapOriginalV1,
    ) -> Result<Self, ProtectedLeaseAuthorityErrorV1> {
        let mut startup = ProtectedLocalOwnershipStartupFailureV1 {
            durable: None, captured_journal: None, recovery: None,
            receiving_error: None, history_error: None,
            issuer, clock: ProtectedLeaseClockV1::open(), bootstrap,
        };
        if startup.clock.failure().is_some() {
            return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
        }

        match receiving.open_local_authority_journal_once_v1() {
            Ok((journal, report)) => {
                startup.captured_journal = Some(journal);
                startup.recovery = Some(report);
            }
            Err(cause) => {
                startup.receiving_error = Some(cause);
                return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
            }
        }
        let Some(journal) = startup.captured_journal.as_ref() else {
            return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
        };
        if let Err(cause) = receiving.reserve_local_history_capture_once_v1(journal) {
            startup.receiving_error = Some(cause);
            return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
        }

        let Some(journal) = startup.captured_journal.take() else {
            return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
        };
        match DurableOwnershipAuthority::from_local_original_journal(journal, verifier) {
            Ok(durable) => startup.durable = Some(durable),
            Err(cause) => {
                startup.history_error = Some(cause);
                return Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)));
            }
        }
        match (startup.durable.take(), startup.recovery.take()) {
            (Some(durable), Some(recovery)) => Ok(Self {
                durable, issuer: startup.issuer, clock: startup.clock,
                signing: std::collections::BTreeMap::new(), bootstrap: startup.bootstrap, recovery,
                funding_refusal: DurableOwnershipAuthorityError::ResourceExhausted,
            }),
            (durable, recovery) => {
                startup.durable = durable;
                startup.recovery = recovery;
                Err(ProtectedLeaseAuthorityErrorV1::Startup(Box::new(startup)))
            }
        }
    }

    fn complete_protocol(
        &mut self,
        funding: &mut crate::ownership_component::funding::OwnershipOperationFundingLoanV1<'_>,
        reference: OwnershipTransactionReferenceV1,
        attempt: &mut LocalOwnershipProtocolAttemptV1,
    ) -> aos_sandbox_ownership_protocol::protocol::OwnershipResponseOutcomeV1 {
        use aos_sandbox_ownership_protocol::protocol::{
            OwnershipProtocolErrorCodeV1 as Code, OwnershipResponseOutcomeV1 as Outcome,
            OwnershipTransactionStatusV1 as Status,
        };
        attempt.query = Some(self.durable.query_local(funding, reference));
        match attempt.query.as_ref() {
            Some(Ok(DurableOwnershipQueryOutcome::Completed(response))) => Outcome::Status(Status::Completed((**response).clone())),
            Some(Ok(DurableOwnershipQueryOutcome::Absent)) => Outcome::Error(Code::NotFound),
            Some(Err(error)) => Outcome::Error(crate::ownership_service::map_durable_error(error, None)),
            Some(Ok(DurableOwnershipQueryOutcome::Pending { action })) => {
                let action = *action;
                match self.complete_request(funding, *reference.request_id()) {
                    Ok(response) => Outcome::Status(Status::Completed(response)),
                    Err(error) => Outcome::Error(crate::ownership_service::map_durable_error(error, Some(action))),
                }
            }
            None => Outcome::Error(Code::IntegrityFailure),
        }
    }

    fn complete_request(
        &mut self,
        funding: &mut crate::ownership_component::funding::OwnershipOperationFundingLoanV1<'_>,
        request: [u8; 16],
    ) -> Result<UnverifiedOwnershipLeaseResponse, &DurableOwnershipAuthorityError> {
        if !self.signing.contains_key(&request) && funding.retain_signing_v1().is_err() {
            // Keep the actual accounting refusal in the same financial owner;
            // no signing node or native clock observation has been allocated.
            return Err(&self.funding_refusal);
        }
        let attempt = self.signing.entry(request).or_insert_with(LocalOwnershipSigningAttemptV1::new);
        if attempt.completion.is_none() {
            let result = self.durable.complete_local(funding, request, &mut self.issuer, &mut self.clock, attempt);
            attempt.completion = Some(result);
        }
        match attempt.completion.get_or_insert(Err(DurableOwnershipAuthorityError::LocalNativeClosed)) {
            Ok(response) => Ok(response.clone()),
            Err(error) => Err(error),
        }
    }


}

fn load_fixed_ownership_bootstrap() -> Result<
    (OwnershipAuthorityVerifier, LocalOwnershipSigningOriginalV1, bootstrap::LocalBootstrapOriginalV1),
    ProtectedLeaseAuthorityErrorV1,
> {
    let mut original = bootstrap::LocalBootstrapOriginalV1::capture();
    let Some((verifier, issuer)) = original.take_binding() else {
        return Err(ProtectedLeaseAuthorityErrorV1::Bootstrap(Box::new(
            ProtectedLocalBootstrapFailureV1 { original },
        )));
    };
    if issuer.require_open().is_err() {
        return Err(ProtectedLeaseAuthorityErrorV1::Signing(Box::new(
            ProtectedLocalSigningFailureV1 { original: issuer, bootstrap: original },
        )));
    }
    Ok((verifier, issuer, original))
}

// The shared captured opener consumes this sole semantic format-owner recipe;
// callers cannot enlarge replay ceilings to fit an otherwise refused history.
pub(crate) fn fixed_journal_limits_v1() -> crate::JournalLimits {
    crate::ownership_authority::ownership_journal_limits()
}

fn fixed_bootstrap_error() -> ProtectedLeaseAuthorityErrorV1 {
    ProtectedLeaseAuthorityErrorV1::Authority(DurableOwnershipAuthorityError::CorruptState)
}

pub(crate) struct ProtectedLeaseClockV1 {
    baseline: aos_sandbox_broker::paired_clock::PairedClockBaselineV1,
    samples: Option<aos_sandbox_broker::paired_clock::PairedClockSamplesV1>,
}

impl ProtectedLeaseClockV1 {
    pub(crate) fn open() -> Self {
        Self { baseline: aos_sandbox_broker::paired_clock::PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(PROTECTED_CLOCK_PROVENANCE)),
            samples: Some(aos_sandbox_broker::paired_clock::PairedClockSamplesV1::new()) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.initial_failure().or_else(|| (0..2).find_map(|index| self.observation_failure(index)))
    }

    pub(crate) fn initial_failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.baseline.failure() }

    pub(crate) fn observation_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.samples.as_ref().and_then(|samples| samples.observation_failure(index))
    }

    // Only successful actual completion commit/replay/readback/name posts and
    // prepared.publish reach this private disposal. The original boot stays.
    pub(crate) fn retire_committed_clock_observations(&mut self) { self.samples = None; }

    pub(crate) fn sample(&mut self) -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        self.samples.get_or_insert_with(aos_sandbox_broker::paired_clock::PairedClockSamplesV1::new)
            .sample(&mut self.baseline)
    }
}
