//! Protected first issuance of a public holder capability.
//!
//! An authenticated public TLS peer establishes holder and certificate-key
//! custody. Trusted controller administration supplies the approved grants;
//! the current protected publisher policy, controller head, project revocation
//! mapping, and time fence independently bound the resulting record. This
//! module registers no route by which a peer can approve its own grants.

#[cfg(test)]
use aos_sandbox_core::DelegationLimits;
use aos_sandbox_core::{
    AuditId, CapabilityDraft, CapabilityId, CapabilityRecord, ChannelBinding, Grant, ObjectDigest,
    PrincipalId, ProjectId, ResourceKind, Revision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::cli_model::authorization_adapter::advance_initial_issuance_time_floor;
use crate::cli_model::authorization_adapter::CliAuthorizationAdapterError;
use crate::controller::ControllerProtectedClockV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_api_session::load_entitlement_credentials;
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod entitlement;
pub use entitlement::sign_entitlement_document_v1;
use entitlement::{EntitlementEntryV1, VerifiedEntitlementsV1};

#[cfg(test)]
const MAXIMUM_VALIDITY_SECONDS: i64 = 3_600;
const BOOTSTRAP_KEY_DOMAIN: &[u8] = b"aos.sandbox.public-capability-bootstrap-key.v1\0";
const BOOTSTRAP_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.public-capability-bootstrap-request.v1\0";
const BOOTSTRAP_KEY_PREFIX: &[u8] = b"bootstrap/";
const ENTITLEMENT_HEAD_KEY: &[u8] = b"entitlement/current";
const MAXIMUM_BOOTSTRAP_RECORDS: usize = 65_536;

/// An explicit grant approval supplied only by trusted controller administration.
///
/// The public holder cannot create this approval through the capability service.
/// Every grant is still checked against the current protected project policy.
#[cfg(test)]
pub(crate) struct InitialPublicCapabilityApprovalV1 {
    grants: Vec<Grant>,
    delegation: DelegationLimits,
    validity_seconds: u32,
}

#[cfg(test)]
impl InitialPublicCapabilityApprovalV1 {
    /// Records the grant set and validity approved by the trusted controller.
    ///
    /// # Errors
    ///
    /// Rejects an empty grant set or validity outside `1..=3600` seconds.
    pub(crate) fn new(
        grants: Vec<Grant>,
        delegation: DelegationLimits,
        validity_seconds: u32,
    ) -> Result<Self, InitialPublicCapabilityErrorV1> {
        if grants.is_empty() || !(1..=3_600).contains(&validity_seconds) {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        Ok(Self {
            grants,
            delegation,
            validity_seconds,
        })
    }
}

/// Returns the committed resource identity and secret holder handle.
///
/// The handle is intentionally omitted from `Debug`, audit, and public
/// projections. It may only be delivered on the authenticated holder channel.
pub struct IssuedPublicCapabilityV1 {
    id: CapabilityId,
    handle: [u8; 32],
}

impl IssuedPublicCapabilityV1 {
    /// Returns the non-authorizing public resource identity.
    #[must_use]
    pub const fn id(&self) -> CapabilityId {
        self.id
    }

    /// Returns the secret handle for delivery to the authenticated holder.
    #[must_use]
    pub const fn holder_handle(&self) -> &[u8; 32] {
        &self.handle
    }
}

/// Reports a failed first issuance without exposing a handle.
#[derive(Debug, thiserror::Error)]
pub enum InitialPublicCapabilityErrorV1 {
    /// Approval or current protected authority did not cover the requested grant.
    #[error("initial public capability issuance rejected")]
    Rejected,
    /// Protected publisher policy could not be validated.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyError),
    /// Protected capability custody or commit failed.
    #[error(transparent)]
    Authority(#[from] PublisherAuthorityError),
    /// Protected bootstrap transaction or replay failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

struct AuthenticatedHolderV1 {
    principal: PrincipalId,
    project: ProjectId,
    key_binding: ChannelBinding,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRecordV1 {
    version: u16,
    key_digest: [u8; 32],
    request_digest: [u8; 32],
    entitlement_digest: ObjectDigest,
    entitlement_generation: u64,
    capability_id: CapabilityId,
    principal: PrincipalId,
    project: ProjectId,
    channel_binding: [u8; 32],
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntitlementHeadV1 {
    version: u16,
    generation: u64,
    digest: ObjectDigest,
}

fn bootstrap_checked(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    entitlements: &VerifiedEntitlementsV1,
    idempotency_key: &[u8],
    now: i64,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    bootstrap_checked_inner(journal, holder, entitlements, idempotency_key, now, None)?
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)
}

struct PreparedInitialIssuerV1 {
    transaction: JournalTransaction,
    id: CapabilityId,
    handle: [u8; 32],
    principal: PrincipalId,
    key_binding: ChannelBinding,
}

// Genuine canonical inputs selected by the sole issuer, not a new recipe.
#[cfg(target_os = "linux")]
struct RetainedInitialInputsV1 {
    capability: CapabilityRecord,
    policy: crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: crate::publisher_policy::PublisherControllerHeadV1,
    revocation: crate::publisher_policy::PublisherProjectRevocationHeadV1,
}

// Inspection owns these originals in its real request, not a poll-local
// credential wrapper. Both selected routes use the same history comparison.
pub(crate) struct RetainedGitEntitlementReadV1 {
    credentials: crate::public_api_session::InitialEntitlementCredentialCustodyV1,
    decoded: Option<Result<VerifiedEntitlementsV1, InitialPublicCapabilityErrorV1>>,
    compared: Option<Result<(), InitialPublicCapabilityErrorV1>>,
    current: Option<Result<(), InitialPublicCapabilityErrorV1>>,
    attempted: bool,
    captured: bool,
    postcheck_failed: bool,
}

impl RetainedGitEntitlementReadV1 {
    pub(crate) fn new() -> Self {
        Self {
            credentials: crate::public_api_session::InitialEntitlementCredentialCustodyV1::new(),
            decoded: None,
            compared: None,
            current: None,
            attempted: false,
            captured: false,
            postcheck_failed: false,
        }
    }

    pub(crate) fn capture_and_compare(
        &mut self,
        journal: &mut Journal,
        project: ProjectId,
    ) -> Result<(), ()> {
        if self.attempted {
            return Err(());
        }
        self.attempted = true;
        self.credentials.capture()?;
        self.captured = true;
        let bytes = self.credentials.ready().ok_or(())?;
        self.decoded = Some(VerifiedEntitlementsV1::decode(bytes[0], bytes[1]));
        let document = self.decoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        self.compared = Some(compare_git_coverage_initial_entitlements_v1(
            journal, project, document,
        ));
        if matches!(self.compared, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(crate) fn postcheck(&mut self) -> Result<(), ()> {
        if self.attempted && self.credentials.recheck().is_err() {
            self.postcheck_failed = true;
        }
        if self.postcheck_failed {
            Err(())
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_current_inputs(
        &mut self,
        capability: &CapabilityRecord,
        policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
        controller: &crate::publisher_policy::PublisherControllerHeadV1,
        revocation: &crate::publisher_policy::PublisherRevocationHeadV1,
        now: i64,
    ) -> Result<(), ()> {
        if self.failure().is_some() || !matches!(self.compared, Some(Ok(()))) {
            return Err(());
        }
        self.current = Some((|| {
            let document = self.decoded.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
            require_current_entitlement_capability(
                document, capability, policy, controller,
                (revocation.scope, revocation.generation), now,
            )
        })());
        self.current.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if !self.captured {
            return self.credentials.failure().map(|cause| cause as _);
        }
        self.decoded.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.compared.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
    }

    pub(crate) fn postcheck_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.postcheck_failed {
            self.credentials.failure().map(|cause| cause as _)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
enum RetainedInitialCauseV1 {
    Deadline,
    Peer,
    Credentials,
    Entitlements,
    EntitlementHistory,
    Clock,
    Sample,
    Prefix,
    Floor,
    Preparation,
    Preflight,
    Commit,
    Readback,
    CrossingInputs,
    CrossingSample,
    CrossingPair,
    Refused,
}

/// Retains one genuine selected first-issuance request and native crossings.
///
/// The actual peer, original idempotency bytes, fixed credential files and
/// clock stay resident. This capsule has no grant/amount constructor; signed
/// entitlement and current policy remain the sole existing approval engine.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub struct RetainedGitInitialIssuanceV1 {
    peer: PublicApiPeer,
    peer_check: Option<Result<(), crate::public_api_session::PublicApiSessionError>>,
    peer_postcheck: Option<Result<(), crate::public_api_session::PublicApiSessionError>>,
    idempotency_key: Vec<u8>,
    expires_at: std::time::Instant,
    credentials: crate::public_api_session::InitialEntitlementCredentialCustodyV1,
    entitlements: Option<Result<VerifiedEntitlementsV1, InitialPublicCapabilityErrorV1>>,
    entitlement_history: Option<Result<(), InitialPublicCapabilityErrorV1>>,
    clock: Option<Result<ControllerProtectedClockV1, crate::ProtectedOwnershipClockError>>,
    sample: Option<Result<aos_sandbox_core::RawPairedClockSample, crate::ProtectedOwnershipClockError>>,
    post_sample: Option<Result<aos_sandbox_core::RawPairedClockSample, crate::ProtectedOwnershipClockError>>,
    crossing_inputs: Option<Result<RetainedInitialInputsV1, InitialPublicCapabilityErrorV1>>,
    crossing_sample: Option<Result<aos_sandbox_core::RawPairedClockSample, crate::ProtectedOwnershipClockError>>,
    crossing_pair: Option<Result<(), aos_sandbox_core::OwnershipLeaseVerificationError>>,
    prefix: Option<Result<bool, crate::journal::GitCoverageNativeHistoryErrorV1>>,
    floor: crate::cli_model::authorization_adapter::RetainedAuthorizationTimeFloorV1,
    recipe: Option<PreparedInitialIssuerV1>,
    prepared: Option<Result<Option<IssuedPublicCapabilityV1>, InitialPublicCapabilityErrorV1>>,
    transactions: Vec<JournalTransaction>,
    expected: Option<(CapabilityId, [u8; 32], PrincipalId, ChannelBinding)>,
    preflight: Option<Result<(), JournalError>>,
    commit: Option<Result<crate::journal::CommitResult, JournalError>>,
    issued: Option<Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1>>,
    first: Option<InitialPublicCapabilityErrorV1>,
    cause_source: Option<RetainedInitialCauseV1>,
    postcheck: Option<InitialPublicCapabilityErrorV1>,
    postcheck_source: Option<RetainedInitialCauseV1>,
    attempted: bool,
    complete: bool,
    retired: bool,
}

#[cfg(target_os = "linux")]
impl RetainedGitInitialIssuanceV1 {
    /// Parks the real installed request before any fallible preparation.
    #[doc(hidden)]
    pub fn new(
        peer: PublicApiPeer,
        idempotency_key: Vec<u8>,
        expires_at: std::time::Instant,
    ) -> Self {
        Self {
            peer,
            peer_check: None,
            peer_postcheck: None,
            idempotency_key,
            expires_at,
            credentials: crate::public_api_session::InitialEntitlementCredentialCustodyV1::new(),
            entitlements: None,
            entitlement_history: None,
            clock: None,
            sample: None,
            post_sample: None,
            crossing_inputs: None,
            crossing_sample: None,
            crossing_pair: None,
            prefix: None,
            floor: crate::cli_model::authorization_adapter::RetainedAuthorizationTimeFloorV1::default(),
            recipe: None,
            prepared: None,
            transactions: Vec::new(),
            expected: None,
            preflight: None,
            commit: None,
            issued: None,
            first: None,
            cause_source: None,
            postcheck: None,
            postcheck_source: None,
            attempted: false,
            complete: false,
            retired: false,
        }
    }

    pub(crate) fn prepare(
        &mut self,
        journal: &mut Journal,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<aos_sandbox_core::RawPairedClockSample, CliAuthorizationAdapterError> {
        let returned = self.prepare_inner(journal, catalog);
        match returned {
            Ok(sample) => Ok(sample),
            Err(cause) => {
                self.first.get_or_insert(cause);
                Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)
            }
        }
    }

    fn prepare_inner(
        &mut self,
        journal: &mut Journal,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<aos_sandbox_core::RawPairedClockSample, InitialPublicCapabilityErrorV1> {
        let refused = || InitialPublicCapabilityErrorV1::Rejected;
        if self.attempted || self.retired {
            return Err(refused());
        }
        self.attempted = true;
        self.cause_source = Some(RetainedInitialCauseV1::Deadline);
        if std::time::Instant::now() >= self.expires_at {
            return Err(refused());
        }
        self.cause_source = Some(RetainedInitialCauseV1::Peer);
        self.peer_check = Some(self.peer.recheck());
        if !matches!(self.peer_check, Some(Ok(()))) {
            return Err(refused());
        }

        self.cause_source = Some(RetainedInitialCauseV1::Credentials);
        self.credentials.capture().map_err(|_| refused())?;
        let bytes = self.credentials.ready().ok_or_else(refused)?;
        self.entitlements = Some(VerifiedEntitlementsV1::decode(bytes[0], bytes[1]));
        self.cause_source = Some(RetainedInitialCauseV1::Entitlements);
        self.entitlements.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
        self.clock = Some(ControllerProtectedClockV1::open_fixed());
        self.cause_source = Some(RetainedInitialCauseV1::Clock);
        let clock = self.clock.as_mut().and_then(|result| result.as_mut().ok()).ok_or_else(refused)?;
        self.sample = Some(clock.sample());
        self.cause_source = Some(RetainedInitialCauseV1::Sample);
        let sample = *self.sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;

        let document = self.entitlements.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        self.entitlement_history = Some(compare_git_coverage_initial_entitlements_v1(
            journal, self.peer.project(), document,
        ));
        self.cause_source = Some(RetainedInitialCauseV1::EntitlementHistory);
        if !matches!(self.entitlement_history, Some(Ok(()))) {
            return Err(refused());
        }

        self.prefix = Some((|| {
            let mut loan = journal.controller_git_coverage_native_prefix_v1(catalog)?;
            let has_floor = loan.existing_controller_read_floor_v1()
                .map_err(crate::journal::GitCoverageNativeHistoryErrorV1::from_first)?;
            loan.recheck().map_err(crate::journal::GitCoverageNativeHistoryErrorV1::from_first)?;
            Ok(has_floor)
        })());
        self.cause_source = Some(RetainedInitialCauseV1::Prefix);
        self.prefix.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
        self.cause_source = Some(RetainedInitialCauseV1::Floor);
        self.floor.prepare_existing_git_read(journal, sample).map_err(|_| refused())?;

        let holder = AuthenticatedHolderV1 {
            principal: self.peer.principal(),
            project: self.peer.project(),
            key_binding: self.peer.key_binding(),
        };
        let entitlements = self.entitlements.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
        self.prepared = Some(bootstrap_checked_inner(
            journal, holder, entitlements, &self.idempotency_key, sample.wall_seconds(), Some(&mut self.recipe),
        ));
        self.cause_source = Some(RetainedInitialCauseV1::Preparation);
        self.prepared.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;

        self.floor.park_initial_issuance_prefix(&mut self.transactions).map_err(|_| refused())?;
        if let Some(recipe) = self.recipe.take() {
            // Capacity was reserved before the floor moved. These are only
            // original canonical DATA; no physical owner leaves its reservoir.
            self.expected = Some((recipe.id, recipe.handle, recipe.principal, recipe.key_binding));
            self.transactions.push(recipe.transaction);
            require_git_coverage_initial_transaction_v1(
                &self.transactions[1], validate_bootstrap_namespace(journal)?,
            )?;
        }
        self.crossing_inputs = Some((|| {
            let capability = if self.expected.is_some() {
                let record = self.transactions.get(1).and_then(|tx| tx.records().first())
                    .ok_or_else(refused)?;
                crate::publisher_authority::decode_git_coverage_initial_content_read_v1(
                    record.key(), record.value().ok_or_else(refused)?,
                )?.0
            } else {
                let issued = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(Option::as_ref).ok_or_else(refused)?;
                PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?
                    .resolve_current(issued.id())?
            };
            let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
            Ok(RetainedInitialInputsV1 {
                capability,
                policy: store.current_policy(self.peer.project())?.ok_or_else(refused)?,
                controller: store.controller_head()?.ok_or_else(refused)?,
                revocation: store.project_revocation_head(self.peer.project())?.ok_or_else(refused)?,
            })
        })());
        self.cause_source = Some(RetainedInitialCauseV1::CrossingInputs);
        if !matches!(self.crossing_inputs, Some(Ok(_))) {
            return Err(refused());
        }
        self.preflight = Some(journal.preflight_transactions(&self.transactions));
        self.cause_source = Some(RetainedInitialCauseV1::Preflight);
        if !matches!(self.preflight, Some(Ok(()))) {
            return Err(refused());
        }
        self.cause_source = None;
        Ok(sample)
    }

    pub(crate) fn check_original_crossing(&mut self) -> Result<(), CliAuthorizationAdapterError> {
        if self.first.is_some() || self.retired {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        let returned = self.check_original_crossing_inner();
        if let Err(cause) = returned {
            self.first.get_or_insert(cause);
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        Ok(())
    }

    fn check_original_crossing_inner(&mut self) -> Result<(), InitialPublicCapabilityErrorV1> {
        let refused = || InitialPublicCapabilityErrorV1::Rejected;
        self.cause_source = Some(RetainedInitialCauseV1::CrossingSample);
        let clock = self.clock.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(refused)?;
        self.crossing_sample = Some(clock.sample());
        let sample = *self.crossing_sample.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        let original = *self.sample.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        self.cause_source = Some(RetainedInitialCauseV1::CrossingPair);
        self.crossing_pair = Some(original.validate_later_sample(sample));
        if !matches!(self.crossing_pair, Some(Ok(()))) {
            return Err(refused());
        }
        self.cause_source = Some(RetainedInitialCauseV1::Floor);
        self.floor.compare_original_post_clock(sample).map_err(|_| refused())?;
        self.cause_source = Some(RetainedInitialCauseV1::Deadline);
        if std::time::Instant::now() >= self.expires_at {
            return Err(refused());
        }
        self.cause_source = Some(RetainedInitialCauseV1::CrossingInputs);
        let inputs = self.crossing_inputs.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        let document = self.entitlements.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        require_current_entitlement_capability(
            document, &inputs.capability, &inputs.policy, &inputs.controller,
            (inputs.revocation.scope(), inputs.revocation.generation()), sample.wall_seconds(),
        )?;
        self.cause_source = None;
        Ok(())
    }

    pub(crate) fn commit_and_issue(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), CliAuthorizationAdapterError> {
        let returned = self.commit_and_issue_inner(journal);
        if let Err(cause) = returned {
            self.first.get_or_insert(cause);
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        Ok(())
    }

    fn commit_and_issue_inner(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), InitialPublicCapabilityErrorV1> {
        let refused = || InitialPublicCapabilityErrorV1::Rejected;
        if self.first.is_some() || self.commit.is_some() || self.complete || self.transactions.is_empty() {
            return Err(refused());
        }
        self.cause_source = Some(RetainedInitialCauseV1::Floor);
        self.floor.preflight_initial_issuance_floor(journal, &self.transactions[0])
            .map_err(|_| refused())?;
        self.check_original_crossing_inner()?;
        self.cause_source = Some(RetainedInitialCauseV1::Floor);
        self.floor.commit_prepared_initial_issuance_floor(journal, &self.transactions[0])
            .map_err(|_| refused())?;
        if let Some((id, handle, principal, binding)) = self.expected {
            self.cause_source = Some(RetainedInitialCauseV1::Preflight);
            self.preflight = Some(journal.preflight_transactions(&self.transactions[1..]));
            if !matches!(self.preflight, Some(Ok(()))) {
                return Err(refused());
            }
            self.check_original_crossing_inner()?;
            self.commit = Some(journal.commit(&self.transactions[1]));
            self.cause_source = Some(RetainedInitialCauseV1::Commit);
            if !matches!(self.commit, Some(Ok(_))) {
                return Err(refused());
            }
            self.issued = Some((|| {
                let registry = PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
                let current = registry.holder_handle(id, principal, binding)?;
                if current != handle {
                    return Err(refused());
                }
                Ok(IssuedPublicCapabilityV1 { id, handle })
            })());
            self.cause_source = Some(RetainedInitialCauseV1::Readback);
            if !matches!(self.issued, Some(Ok(_))) {
                return Err(refused());
            }
        }
        self.cause_source = None;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        self.cause_source.get_or_insert(RetainedInitialCauseV1::Refused);
        self.first.get_or_insert(InitialPublicCapabilityErrorV1::Rejected);
    }

    pub(crate) fn postcheck(&mut self) -> Result<(), ()> {
        // These independent observations run even after an action failure.
        // Their actual errors remain separate from the earlier action cause.
        if self.credentials.recheck().is_err() {
            self.postcheck_source.get_or_insert(RetainedInitialCauseV1::Credentials);
            self.postcheck.get_or_insert(InitialPublicCapabilityErrorV1::Rejected);
        }
        self.peer_postcheck = Some(self.peer.recheck());
        if !matches!(self.peer_postcheck, Some(Ok(()))) {
            self.postcheck_source.get_or_insert(RetainedInitialCauseV1::Peer);
            self.postcheck.get_or_insert(InitialPublicCapabilityErrorV1::Rejected);
        }
        if let Some(clock) = self.clock.as_mut().and_then(|result| result.as_mut().ok()) {
            self.post_sample = Some(clock.sample());
            let valid = self.post_sample.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|sample| self.floor.compare_original_post_clock(*sample).is_ok());
            if !valid {
                self.postcheck_source.get_or_insert(RetainedInitialCauseV1::Sample);
                self.postcheck.get_or_insert(InitialPublicCapabilityErrorV1::Rejected);
            }
            if let (Some(Ok(sample)), Some(Ok(inputs)), Some(Ok(document))) = (
                self.post_sample.as_ref(), self.crossing_inputs.as_ref(), self.entitlements.as_ref(),
            ) {
                if let Err(cause) = require_current_entitlement_capability(
                    document, &inputs.capability, &inputs.policy, &inputs.controller,
                    (inputs.revocation.scope(), inputs.revocation.generation()), sample.wall_seconds(),
                ) {
                    self.postcheck_source.get_or_insert(RetainedInitialCauseV1::CrossingInputs);
                    self.postcheck.get_or_insert(cause);
                }
            }
        }
        if std::time::Instant::now() >= self.expires_at {
            self.postcheck_source.get_or_insert(RetainedInitialCauseV1::Refused);
            self.postcheck.get_or_insert(InitialPublicCapabilityErrorV1::Rejected);
        }
        if self.postcheck.is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Borrows the real successful issuer result, without retiring its owners.
    #[doc(hidden)]
    #[must_use]
    pub fn issued(&self) -> Option<&IssuedPublicCapabilityV1> {
        if !self.complete || self.first.is_some() || self.postcheck.is_some() {
            return None;
        }
        self.issued.as_ref().and_then(|result| result.as_ref().ok())
            .or_else(|| self.prepared.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref))
    }

    /// Reports an actual pure issuer rejection for the existing negative reply.
    ///
    /// This observation cannot retire the failed owner or authorize a retry.
    #[doc(hidden)]
    #[must_use]
    pub fn rejected(&self) -> bool {
        matches!(self.cause_source, Some(RetainedInitialCauseV1::Entitlements))
            && matches!(self.entitlements, Some(Err(InitialPublicCapabilityErrorV1::Rejected)))
            || matches!(self.cause_source, Some(RetainedInitialCauseV1::Preparation))
                && matches!(self.first, Some(InitialPublicCapabilityErrorV1::Rejected))
    }

    /// Reports refusal at the original command deadline, not a renewed cut.
    #[doc(hidden)]
    #[must_use]
    pub fn deadline_exceeded(&self) -> bool {
        matches!(self.cause_source, Some(RetainedInitialCauseV1::Deadline))
            && self.first.is_some()
    }

    /// Borrows the first actual cause; later independent observations stay debt.
    #[doc(hidden)]
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native: Option<&(dyn std::error::Error + 'static)> = match self.cause_source {
            Some(RetainedInitialCauseV1::Peer) => self.peer_check.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Credentials) => self.credentials.failure().map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Entitlements) => self.entitlements.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::EntitlementHistory) => self.entitlement_history.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Clock) => self.clock.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Sample) => self.sample.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Prefix) => self.prefix.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Floor) => self.floor.failure().map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Preparation) => self.prepared.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Preflight) => self.preflight.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Commit) => self.commit.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Readback) => self.issued.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::CrossingInputs) => self.crossing_inputs.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::CrossingSample) => self.crossing_sample.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::CrossingPair) => self.crossing_pair.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            _ => None,
        };
        native.or_else(|| self.first.as_ref().map(|cause| cause as _))
            .or_else(|| self.postcheck_failure())
    }

    /// Borrows later independent observation debt, never release authority.
    #[doc(hidden)]
    #[must_use]
    pub fn postcheck_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native: Option<&(dyn std::error::Error + 'static)> = match self.postcheck_source {
            Some(RetainedInitialCauseV1::Credentials) => self.credentials.failure().map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Peer) => self.peer_postcheck.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RetainedInitialCauseV1::Sample) => self.post_sample.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            _ => None,
        };
        native.or_else(|| self.postcheck.as_ref().map(|cause| cause as _))
    }

    /// Permits only explicit local destruction after all successful bookends.
    ///
    /// # Errors
    /// Refuses incomplete or failed originals; this is not remote Drain.
    #[doc(hidden)]
    pub fn retire_local(&mut self) -> Result<(), InitialPublicCapabilityErrorV1> {
        if self.issued().is_none() {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        self.retired = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RetainedGitInitialIssuanceV1 {
    fn drop(&mut self) {
        if !self.retired {
            std::process::abort();
        }
    }
}

fn bootstrap_checked_inner(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    entitlements: &VerifiedEntitlementsV1,
    idempotency_key: &[u8],
    now: i64,
    retained_destination: Option<&mut Option<PreparedInitialIssuerV1>>,
) -> Result<Option<IssuedPublicCapabilityV1>, InitialPublicCapabilityErrorV1> {
    if !(16..=128).contains(&idempotency_key.len())
        || holder.principal.as_bytes() == &[0; 16]
        || holder.project.as_bytes() == &[0; 16]
        || holder.key_binding.as_bytes() == &[0; 32]
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    journal.ensure_protected_authority()?;
    let entry = entitlements.for_holder(
        holder.principal,
        holder.project,
        holder.key_binding.as_bytes(),
    )?;

    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store
            .current_policy(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store
            .controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store
            .project_revocation_head(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    if !initial_entitlement_is_current(entry, &policy, &controller,
        (revocation.scope(), revocation.generation()), now)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let key_digest = holder_key_digest(
        holder.principal,
        holder.project,
        holder.key_binding.as_bytes(),
    );
    let request_digest: [u8; 32] = Sha256::new()
        .chain_update(BOOTSTRAP_REQUEST_DOMAIN)
        .chain_update(key_digest)
        .chain_update((idempotency_key.len() as u64).to_be_bytes())
        .chain_update(idempotency_key)
        .chain_update(entitlements.digest().as_bytes())
        .finalize()
        .into();
    let key = bootstrap_key(&key_digest);
    let head = validate_bootstrap_namespace(journal)?;
    if head.as_ref().is_some_and(|head| {
        entitlements.generation() < head.generation
            || (entitlements.generation() == head.generation
                && entitlements.digest() != head.digest)
    }) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    if let Some(bytes) = journal.get(RecordNamespace::PublicCapabilityBootstrap, &key) {
        let retained: BootstrapRecordV1 = decode_canonical(bytes)?;
        if retained.request_digest != request_digest
            || retained.entitlement_digest != entitlements.digest()
            || retained.entitlement_generation != entitlements.generation()
            || retained.principal != holder.principal
            || retained.project != holder.project
            || retained.channel_binding != *holder.key_binding.as_bytes()
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let registry =
            PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
        let capability = registry.resolve_current(retained.capability_id)?;
        if !claims_match(
            &capability,
            &holder,
            entry,
            &policy,
            controller.principal,
            (revocation.scope(), revocation.generation()),
            now,
        ) {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let handle =
            registry.holder_handle(retained.capability_id, holder.principal, holder.key_binding)?;
        return Ok(Some(IssuedPublicCapabilityV1 {
            id: retained.capability_id,
            handle,
        }));
    }

    let expires_at = now
        .checked_add(i64::from(entry.validity_seconds))
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
    if expires_at > entry.expires_at || expires_at > policy.expires_at() {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let id = CapabilityId::new();
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id,
        issuer: controller.principal,
        audience: controller.principal,
        holder: holder.principal,
        channel_binding: holder.key_binding,
        root_subject: holder.principal,
        project: holder.project,
        sandbox: None,
        incarnation: None,
        grants: entry.grants.clone(),
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: None,
        not_before: now,
        expires_at,
        revocation_scope: revocation.scope(),
        revocation_generation: Revision::new(revocation.generation()),
        delegation: entry.delegation,
        parent_decision: AuditId::from_bytes(*id.as_bytes()),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let (authority_record, handle) =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?
            .prepare_initial_public_install(capability)?;
    let retained = BootstrapRecordV1 {
        version: 1,
        key_digest,
        request_digest,
        entitlement_digest: entitlements.digest(),
        entitlement_generation: entitlements.generation(),
        capability_id: id,
        principal: holder.principal,
        project: holder.project,
        channel_binding: *holder.key_binding.as_bytes(),
    };
    let mut records = vec![
        authority_record,
        JournalRecord::put(
            RecordNamespace::PublicCapabilityBootstrap,
            key,
            serde_json::to_vec(&retained).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?,
        ),
    ];
    if head.is_none_or(|head| entitlements.generation() > head.generation) {
        records.push(JournalRecord::put(
            RecordNamespace::PublicCapabilityBootstrap,
            ENTITLEMENT_HEAD_KEY.to_vec(),
            serde_json::to_vec(&EntitlementHeadV1 {
                version: 1,
                generation: entitlements.generation(),
                digest: entitlements.digest(),
            })
            .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?,
        ));
    }
    if let Some(destination) = retained_destination {
        *destination = Some(PreparedInitialIssuerV1 {
            transaction: JournalTransaction::new(*id.as_bytes(), records)
                .map_err(JournalError::from)?,
            id, handle, principal: holder.principal, key_binding: holder.key_binding,
        });
        return Ok(None);
    }
    journal.commit(&JournalTransaction::new(*id.as_bytes(), records).map_err(JournalError::from)?)?;
    let committed_handle =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?
            .holder_handle(id, holder.principal, holder.key_binding)?;
    if committed_handle != handle {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(Some(IssuedPublicCapabilityV1 { id, handle }))
}

fn grants_covered(
    grants: &[Grant],
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
) -> bool {
    grants.iter().all(|grant| {
        if grant.id().as_bytes() == &[0; 16] {
            return false;
        }
        let candidates = if grant.delegable() {
            policy.policy().delegable_grants()
        } else {
            policy.policy().effective_grants()
        };
        candidates.iter().any(|candidate| {
            candidate.resource_kind() == grant.resource_kind()
                && grant.operations().is_subset_of(candidate.operations())
                && candidate.selector().contains(grant.selector())
                && (grant.resource_kind() != ResourceKind::CachePublish
                    || matches!(
                        grant.selector(),
                        aos_sandbox_core::Selector::Resource { .. }
                    ))
        })
    })
}

// Reuses the ordinary issuer's exact ordered signed-entry/policy predicate.
fn initial_entitlement_is_current(
    entry: &EntitlementEntryV1,
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: &crate::publisher_policy::PublisherControllerHeadV1,
    revocation: (aos_sandbox_core::RevocationScopeId, u64),
    now: i64,
) -> bool {
    !(now < entry.not_before
        || now < policy.not_before()
        || now >= entry.expires_at
        || now >= policy.expires_at()
        || policy.generation() != entry.policy_generation
        || policy.descriptor().digest() != entry.policy_digest
        || controller.generation != entry.controller_generation
        || controller.principal.as_bytes() == &[0; 16]
        || revocation.0 != entry.revocation_scope
        || revocation.1 != entry.revocation_generation
        || !grants_covered(&entry.grants, policy))
}

fn require_current_entitlement_capability(
    document: &VerifiedEntitlementsV1,
    capability: &CapabilityRecord,
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: &crate::publisher_policy::PublisherControllerHeadV1,
    revocation: (aos_sandbox_core::RevocationScopeId, u64),
    now: i64,
) -> Result<(), InitialPublicCapabilityErrorV1> {
    let claims = capability.claims();
    let holder = AuthenticatedHolderV1 {
        principal: claims.holder,
        project: claims.project,
        key_binding: claims.channel_binding,
    };
    let entry = document.for_holder(holder.principal, holder.project, holder.key_binding.as_bytes())?;
    if !initial_entitlement_is_current(entry, policy, controller, revocation, now)
        || !claims_match(capability, &holder, entry, policy, controller.principal, revocation, now)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(())
}

fn claims_match(
    capability: &CapabilityRecord,
    holder: &AuthenticatedHolderV1,
    entry: &EntitlementEntryV1,
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: PrincipalId,
    revocation: (aos_sandbox_core::RevocationScopeId, u64),
    now: i64,
) -> bool {
    let claims = capability.claims();
    claims.issuer == controller
        && claims.audience == controller
        && claims.holder == holder.principal
        && claims.channel_binding == holder.key_binding
        && claims.root_subject == holder.principal
        && claims.project == holder.project
        && claims.sandbox.is_none()
        && claims.incarnation.is_none()
        && claims.assignment_epoch.is_none()
        && claims.grants == entry.grants
        && claims.delegation == entry.delegation
        && claims.policy_digest == policy.descriptor().digest()
        && claims.revocation_scope == revocation.0
        && claims.revocation_generation.get() == revocation.1
        && claims.not_before >= entry.not_before
        && claims.not_before <= now
        && now < claims.expires_at
        && claims.expires_at <= entry.expires_at
}

// This is historical DATA validation at each actual record's signed creation
// time, not current admission. The current evaluator still uses its original
// paired sample, peer, policy and revocation bookends independently.
fn compare_git_coverage_initial_entitlements_v1(
    journal: &mut Journal,
    project: ProjectId,
    document: &VerifiedEntitlementsV1,
) -> Result<(), InitialPublicCapabilityErrorV1> {
    let head = validate_bootstrap_namespace(journal)?;
    if head.is_some_and(|head| {
        head.generation != document.generation() || head.digest != document.digest()
    }) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store.current_policy(project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store.controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store.project_revocation_head(project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    for (key, bytes) in journal.records(RecordNamespace::PublicCapabilityBootstrap) {
        if key == ENTITLEMENT_HEAD_KEY {
            continue;
        }
        let original: BootstrapRecordV1 = decode_canonical(bytes)?;
        if original.project != project || original.entitlement_digest != document.digest()
            || original.entitlement_generation != document.generation()
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let capability = crate::publisher_authority::decode_git_coverage_initial_for_id_v1(
            journal, original.capability_id,
        )?;
        let holder = AuthenticatedHolderV1 {
            principal: original.principal,
            project: original.project,
            key_binding: ChannelBinding::new(original.channel_binding),
        };
        let entry = document.for_holder(holder.principal, holder.project, &original.channel_binding)?;
        if policy.generation() != entry.policy_generation
            || policy.descriptor().digest() != entry.policy_digest
            || controller.generation != entry.controller_generation
            || revocation.scope() != entry.revocation_scope
            || revocation.generation() != entry.revocation_generation
            || capability.claims().not_before < policy.not_before()
            || capability.claims().expires_at > policy.expires_at()
            || capability.claims().not_before.checked_add(i64::from(entry.validity_seconds))
                != Some(capability.claims().expires_at)
            || !grants_covered(&entry.grants, &policy)
            || !claims_match(
                &capability, &holder, entry, &policy, controller.principal,
                (revocation.scope(), revocation.generation()), capability.claims().not_before,
            )
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
    }
    Ok(())
}

fn bootstrap_key(digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(BOOTSTRAP_KEY_PREFIX.len() + digest.len());
    key.extend_from_slice(BOOTSTRAP_KEY_PREFIX);
    key.extend_from_slice(digest);
    key
}

fn holder_key_digest(principal: PrincipalId, project: ProjectId, binding: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(BOOTSTRAP_KEY_DOMAIN)
        .chain_update(principal.as_bytes())
        .chain_update(project.as_bytes())
        .chain_update(binding)
        .finalize()
        .into()
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, InitialPublicCapabilityErrorV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T =
        serde_json::from_slice(bytes).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    if serde_json::to_vec(&value).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)? != bytes {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(value)
}

fn validate_bootstrap_namespace(
    journal: &Journal,
) -> Result<Option<EntitlementHeadV1>, InitialPublicCapabilityErrorV1> {
    validate_bootstrap_records(journal.records(RecordNamespace::PublicCapabilityBootstrap))
}

fn validate_bootstrap_records<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Option<EntitlementHeadV1>, InitialPublicCapabilityErrorV1> {
    let mut head = None;
    let mut count = 0_usize;
    let mut greatest_record_generation = 0_u64;
    for (key, bytes) in records {
        count = count
            .checked_add(1)
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        if count > MAXIMUM_BOOTSTRAP_RECORDS || bytes.len() > 2_048 {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        if key == ENTITLEMENT_HEAD_KEY {
            let value: EntitlementHeadV1 = decode_canonical(bytes)?;
            if value.version != 1 || value.generation == 0 || value.digest.as_bytes() == &[0; 32] {
                return Err(InitialPublicCapabilityErrorV1::Rejected);
            }
            head = Some(value);
        } else if let Some(digest) = key.strip_prefix(BOOTSTRAP_KEY_PREFIX) {
            let value: BootstrapRecordV1 = decode_canonical(bytes)?;
            if digest.len() != 32
                || digest != value.key_digest
                || value.version != 1
                || value.request_digest == [0; 32]
                || value.entitlement_digest.as_bytes() == &[0; 32]
                || value.entitlement_generation == 0
                || value.capability_id.as_bytes() == &[0; 16]
                || value.principal.as_bytes() == &[0; 16]
                || value.project.as_bytes() == &[0; 16]
                || value.channel_binding == [0; 32]
                || value.key_digest
                    != holder_key_digest(value.principal, value.project, &value.channel_binding)
            {
                return Err(InitialPublicCapabilityErrorV1::Rejected);
            }
            greatest_record_generation =
                greatest_record_generation.max(value.entitlement_generation);
        } else {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
    }
    if count != 0 && head.is_none_or(|head| head.generation < greatest_record_generation) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    Ok(head)
}

/// Keeps only the bounded head and counters of validated initial-read groups.
#[derive(Default)]
pub(crate) struct GitCoverageInitialIssuanceHistoryV1 {
    head: Option<EntitlementHeadV1>,
    records: usize,
}

impl GitCoverageInitialIssuanceHistoryV1 {
    pub(crate) fn observe(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), InitialPublicCapabilityErrorV1> {
        let next = require_git_coverage_initial_transaction_v1(transaction, self.head)?;
        self.records = self.records.checked_add(1)
            .filter(|count| *count < MAXIMUM_BOOTSTRAP_RECORDS)
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        self.head = Some(next);
        Ok(())
    }

    pub(crate) fn compare_final(
        &self,
        journal: &Journal,
    ) -> Result<(), InitialPublicCapabilityErrorV1> {
        let actual = validate_bootstrap_namespace(journal)?;
        let heads_match = match (self.head, actual) {
            (None, None) => true,
            (Some(original), Some(actual)) => original.version == actual.version
                && original.generation == actual.generation && original.digest == actual.digest,
            _ => false,
        };
        if !heads_match
            || journal.records(RecordNamespace::PublisherAuthority).count() != self.records
            || journal.records(RecordNamespace::PublicCapabilityBootstrap)
                .filter(|(key, _)| *key != ENTITLEMENT_HEAD_KEY).count() != self.records
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        Ok(())
    }
}

fn require_git_coverage_initial_transaction_v1(
    transaction: &JournalTransaction,
    previous_head: Option<EntitlementHeadV1>,
) -> Result<EntitlementHeadV1, InitialPublicCapabilityErrorV1> {
    let records = transaction.records();
    if !(2..=3).contains(&records.len())
        || records[0].namespace() != RecordNamespace::PublisherAuthority
        || records[1].namespace() != RecordNamespace::PublicCapabilityBootstrap
        || records.iter().any(|record| record.value().is_none())
        || records[1].value().is_none_or(|value| value.len() > 2_048)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    let (capability, _) = crate::publisher_authority::decode_git_coverage_initial_content_read_v1(
        records[0].key(), records[0].value().ok_or(InitialPublicCapabilityErrorV1::Rejected)?,
    )?;
    let retained: BootstrapRecordV1 = decode_canonical(
        records[1].value().ok_or(InitialPublicCapabilityErrorV1::Rejected)?,
    )?;
    let claims = capability.claims();
    if retained.version != 1
        || retained.capability_id != capability.id()
        || transaction.id() != capability.id().as_bytes()
        || retained.principal != claims.holder
        || retained.project != claims.project
        || retained.channel_binding != *claims.channel_binding.as_bytes()
        || claims.root_subject != claims.holder
        || claims.issuer != claims.audience
        || claims.sandbox.is_some() || claims.incarnation.is_some()
        || claims.assignment_epoch.is_some()
        || retained.key_digest != holder_key_digest(
            retained.principal, retained.project, &retained.channel_binding,
        )
        || records[1].key() != bootstrap_key(&retained.key_digest)
        || retained.request_digest == [0; 32]
        || retained.entitlement_digest.as_bytes() == &[0; 32]
        || retained.entitlement_generation == 0
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    let next = EntitlementHeadV1 {
        version: 1, generation: retained.entitlement_generation,
        digest: retained.entitlement_digest,
    };
    let advances = previous_head.is_none_or(|old| next.generation > old.generation);
    if records.len() != if advances { 3 } else { 2 }
        || previous_head.is_some_and(|old| next.generation < old.generation
            || (next.generation == old.generation && next.digest != old.digest))
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    if advances {
        let head = &records[2];
        if head.namespace() != RecordNamespace::PublicCapabilityBootstrap
            || head.key() != ENTITLEMENT_HEAD_KEY
            || head.value().is_none_or(|value| value.len() > 2_048)
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let encoded: EntitlementHeadV1 = decode_canonical(
            head.value().ok_or(InitialPublicCapabilityErrorV1::Rejected)?,
        )?;
        if (encoded.version, encoded.generation, encoded.digest)
            != (next.version, next.generation, next.digest)
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
    }
    Ok(next)
}

pub(crate) fn require_git_coverage_initial_from_state_v1(
    transaction: &JournalTransaction,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), InitialPublicCapabilityErrorV1> {
    let head = validate_bootstrap_records(state.iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::PublicCapabilityBootstrap)
        .map(|((_, key), value)| (key.as_slice(), value.as_slice())))?;
    if transaction.records().iter().take(2).any(|record| {
        state.keys().any(|(namespace, key)| {
            *namespace == record.namespace() && key.as_slice() == record.key()
        })
    }) {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    require_git_coverage_initial_transaction_v1(transaction, head).map(|_| ())
}

/// Issues or replays the first capability under fixed signed deployment authority.
///
/// The request supplies only an idempotency key. The credential reader chooses
/// both the entitlement and verifier by fixed names under systemd custody.
///
/// # Errors
///
/// Rejects stale TLS evidence, absent or changed signed entitlement, invalid
/// current protected policy, or an ambiguous protected commit.
pub(crate) fn bootstrap(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    idempotency_key: &[u8],
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let holder = AuthenticatedHolderV1 {
        principal: peer.principal(),
        project: peer.project(),
        key_binding: peer.key_binding(),
    };
    let credentials =
        load_entitlement_credentials().map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let entitlements = VerifiedEntitlementsV1::decode(&credentials[0], &credentials[1])?;
    let mut clock = ControllerProtectedClockV1::open_fixed()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let observed = clock
        .sample()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    advance_initial_issuance_time_floor(journal, observed)
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;

    let issued = bootstrap_checked(
        journal,
        holder,
        &entitlements,
        idempotency_key,
        observed.wall_seconds(),
    )?;
    let current =
        load_entitlement_credentials().map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let current = VerifiedEntitlementsV1::decode(&current[0], &current[1])?;
    if current.digest() != entitlements.digest() {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    Ok(issued)
}

#[cfg(test)]
fn issue_checked(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    approval: InitialPublicCapabilityApprovalV1,
    now: i64,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    if holder.principal.as_bytes() == &[0; 16]
        || holder.project.as_bytes() == &[0; 16]
        || holder.key_binding.as_bytes() == &[0; 32]
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    // A single exclusive journal owner keeps all current-head checks and the
    // capability commit in one authority cut.
    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store
            .current_policy(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store
            .controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store
            .project_revocation_head(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    let expires_at = now
        .checked_add(i64::from(approval.validity_seconds))
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
    if now < policy.not_before()
        || expires_at > policy.expires_at()
        || expires_at <= now
        || expires_at - now > MAXIMUM_VALIDITY_SECONDS
        || controller.principal.as_bytes() == &[0; 16]
        || controller.generation == 0
        || revocation.generation() == 0
        || !grants_covered(&approval.grants, &policy)
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let id = CapabilityId::new();
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id,
        issuer: controller.principal,
        audience: controller.principal,
        holder: holder.principal,
        channel_binding: holder.key_binding,
        root_subject: holder.principal,
        project: holder.project,
        sandbox: None,
        incarnation: None,
        grants: approval.grants,
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: None,
        not_before: now,
        expires_at,
        revocation_scope: revocation.scope(),
        revocation_generation: Revision::new(revocation.generation()),
        delegation: approval.delegation,
        parent_decision: AuditId::from_bytes(*id.as_bytes()),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let mut registry =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
    registry.install_from_trusted_controller(*id.as_bytes(), capability)?;
    let handle = registry.holder_handle(id, holder.principal, holder.key_binding)?;
    Ok(IssuedPublicCapabilityV1 { id, handle })
}

#[cfg(test)]
mod tests;
