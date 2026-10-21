//! Authenticates current43 from the actual paid Controller Host Session cut.
//!
//! The existing stored/checkpoint/traffic/method captures retain every reached
//! model and cause. Root's own fixed trust original supplies both verification
//! keys and the fresh read nonce. No packet supplied by Controller can replace
//! the native journal, and a verified result alone cannot append a Root floor.

use aos_sandbox_protocol::domain_ledger::readonly::FixedJournalReadbackDataV1 as RootFixedNativeReadbackV1;

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableHistoryV1, BrokerSessionDurableRecordV1, BrokerSessionProtocolV1,
    BrokerSessionTrafficStateV1, HistoricalTrafficReplayCaptureV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    complete_signed_outcome_digest_v1,
};
use aos_sandbox_model::{
    RawPairedClockSample, RecordNamespace, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_protocol::authenticated_session::{
    all_methods::{
        outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1 as OutcomeCapture,
        request_capture::AuthenticatedBrokerMethodRequestCaptureV1 as RequestCapture,
    },
    historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    historical_method::HistoricalStartResourceMethodCaptureV2,
    stored_history::{
        StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryV1,
        canonical_protocol_key_v1,
    },
};
use aos_sandbox_protocol::host_execution_no_apply::current_lease::{
    CurrentHostNoApplyLeaseDataV2, HostNoApplyLeaseScopeV2,
};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootExecutionNoApplyStageReceivingV2};
use crate::policy_compiler::create_storage_current::controller_readonly::{
    storage_inventory::verify_current_execution_no_apply_session_retaining_v2,
};
use crate::policy_compiler::provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1;

use super::RootExecutionNoApplyHostTrustOriginalV2;

pub(super) mod host_history;

type Cause = Box<dyn Error>;
type SessionValues = (
    ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1,
);

pub(crate) struct RootExecutionNoApplyHostLeaseOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    reentry: Option<JournalError>,
}

struct Native {
    roster: host_history::HostHistoryOriginalV2,
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    verified: Option<Result<SessionValues, Cause>>,
    checkpoint: HistoricalSessionCheckpointVerifyCaptureV1,
    traffic: HistoricalTrafficReplayCaptureV1,
    method: HistoricalStartResourceMethodCaptureV2,
    lease: Option<Result<CurrentHostNoApplyLeaseDataV2, Cause>>,
    signed_outcome: Option<[u8; 32]>,
    body: Option<Result<(), Cause>>,
    external_trust: bool,
}

impl RootExecutionNoApplyHostLeaseOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            native: None,
            reentry: None,
        }
    }

    pub(crate) fn receiving_demand_v2(prefix: usize, entries: usize) -> Result<ResourceVector, JournalError> {
        let request = RequestCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        let outcome = OutcomeCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        // Both full-traffic and selected-method prefix replay keep their own
        // record vectors. Twenty raw planes cover complete stored/checkpoint,
        // history, HELLO/context, packet and pending/prior traffic copies.
        let rows = prefix
            .checked_mul(size_of::<BrokerSessionDurableRecordV1>())
            .and_then(|bytes| bytes.checked_mul(6))
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = prefix
            .checked_mul(20)
            .and_then(|bytes| bytes.checked_add(rows))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<Native>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        // Request/outcome captures coexist with their owned admissions and
        // canonical projection scratch in the existing retained method engine.
        let pair = request.checked_add(outcome)?;
        pair.checked_add(pair)?
            .checked_add(pair)?
            .checked_add(host_history::HostHistoryOriginalV2::receiving_demand(prefix, entries)?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn observe_once_v2(
        &mut self,
        stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            readonly
                .execution_no_apply_current_data_v2()?
                .host_current_lease_demand_data_v2()
        })());
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_execution_no_apply_host_current_lease_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native {
            roster: host_history::HostHistoryOriginalV2::new(),
            stored: Default::default(),
            verified: None,
            checkpoint: Default::default(),
            traffic: Default::default(),
            method: Default::default(),
            lease: None,
            signed_outcome: None,
            body: None,
            external_trust: false,
        }));
        readonly
            .execution_no_apply_current_data_v2()?
            .observe_host_current_lease_data_v2(self, trust, stage.controller_identity_v1())?;
        self.lease_data_v2().map(|_| ())
    }

    pub(crate) fn observe_native_data_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        controller: (u32, u32),
    ) -> Result<(), JournalError> {
        if self.reentry.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let original = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if original.body.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        original.body = Some(original.observe_body_v2(native, trust, controller));
        original.external_trust = trust.failure().is_some();
        self.lease_data_v2().map(|_| ())
    }

    /// Borrows authenticated comparison DATA while all original readers stay held.
    pub(crate) fn lease_data_v2(&self) -> Result<CurrentHostNoApplyLeaseDataV2, JournalError> {
        let native = self.body_native_v2()?;
        native
            .lease
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn signed_outcome_data_v2(&self) -> Result<[u8; 32], JournalError> {
        self.body_native_v2()?
            .signed_outcome
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn body_native_v2(&self) -> Result<&Native, JournalError> {
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.reentry.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(native.body, Some(Ok(())))
            || native.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(native)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.as_ref()?.failure())
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Native {
    fn observe_body_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        controller: (u32, u32),
    ) -> Result<(), Cause> {
        let sample = trust.next_sample_v2()?;
        let manifest = trust.manifest_v2()?;
        self.roster.observe_once(&native, manifest, controller)?;
        let comparison = trust.comparison_data_v2()?;
        let key = match comparison.fields().scope {
            HostNoApplyLeaseScopeV2::Active => canonical_protocol_key_v1(BrokerSessionProtocolV1::Host),
            HostNoApplyLeaseScopeV2::RecoveryCleanup => aos_sandbox_protocol::authenticated_session::
                stored_history::canonical_host_no_apply_cleanup_key_v1(),
        };
        let bytes = native
            .state
            .get(&(RecordNamespace::BrokerSessionTraffic, key.clone()))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.stored)?;
        let stored = self
            .stored
            .stored()
            .ok_or(JournalError::ProtectedBoundary)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if (checkpoint.peer().uid, checkpoint.peer().gid) != controller {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.verified = Some(match comparison.fields().scope {
            HostNoApplyLeaseScopeV2::Active => verify_current_execution_no_apply_session_retaining_v2(
                manifest, stored, checkpoint.client_hello_bytes(), checkpoint.broker_hello_bytes(),
                manifest.node_id(), sample.host_boot_id(), &mut self.checkpoint, &mut self.traffic,
            ),
            HostNoApplyLeaseScopeV2::RecoveryCleanup => crate::policy_compiler::create_storage_current::
                controller_readonly::storage_inventory::verify_current_execution_no_apply_cleanup_session_retaining_v2(
                    manifest, stored, manifest.node_id(), sample.host_boot_id(),
                    &mut self.checkpoint, &mut self.traffic,
                ),
        });
        let (context, transcript, history, _) = self
            .verified
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let last = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(JournalError::ProtectedBoundary)?;
        self.method.observe_host_current_no_apply_once_v2(
            history.records(),
            last,
            checkpoint,
            transcript,
        )?;
        let request = self
            .method
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let query = request
            .host_no_apply_current_lease_query_data_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let fields = comparison.fields();
        if query.comparison_v2() != comparison
            || query.read_nonce_v2() != trust.read_nonce_data_v2()?
            || request.session_binding() != transcript.session_binding()
            || fields.current_session != transcript.session_binding()
            || fields.native_boot != context.boot_id()
            || matches!(fields.scope, HostNoApplyLeaseScopeV2::Active)
                && fields.availability.fields().session != transcript.session_binding()
            || request.deadline_boottime_nanoseconds() > fields.native_cutoff
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.lease = Some((|| {
            self.method
                .outcome_v2()
                .ok_or(JournalError::ProtectedBoundary)?
                .recorded_host_no_apply_current_lease_v2()?
                .ok_or_else(|| JournalError::ProtectedBoundary.into())
        })());
        let lease = self
            .lease
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let companion = history
            .head()?
            .outcome_companion()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.signed_outcome = Some(complete_signed_outcome_digest_v1(
            companion.signed_outcome(),
        ));
        require_current_lease_sample_data_v2(lease, trust.next_sample_v2()?)?;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.roster.failure().or_else(|| self.stored
            .failure()
            .map(|cause| cause as _))
            .or_else(|| self.checkpoint.failure().map(|cause| cause as _))
            .or_else(|| self.traffic.cause())
            .or_else(|| {
                self.verified
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.method.failure_v2())
            .or_else(|| {
                self.lease
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                if self.external_trust {
                    None
                } else {
                    self.body
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }
            })
    }
}

fn require_current_lease_sample_data_v2(
    lease: CurrentHostNoApplyLeaseDataV2,
    sample: RawPairedClockSample,
) -> Result<(), JournalError> {
    let fields = lease.fields();
    if fields.native_boot != sample.host_boot_id()
        || fields.observed_clock > sample.boottime_nanoseconds()
        || sample.boottime_nanoseconds() >= fields.native_cutoff
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
