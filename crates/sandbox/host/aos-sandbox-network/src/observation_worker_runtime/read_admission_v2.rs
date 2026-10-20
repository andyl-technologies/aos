//! Joins the original O public handoff to live native Netd Source permission.
//!
//! This read-only borrower retains the real six public credential originals,
//! original completed local lease/fences/effect, signed request and native
//! transport subject. It has no journal key, mutation permit or lease issuer.

use std::error::Error;

use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_broker::receiving::{
    NetworkChildOperationBindingDataV2, NetworkChildSourceAffinityOriginalV2,
    NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2,
};
use aos_sandbox_broker::{
    AdmissionRequest, AuthorizationRecordError, BrokerAdmissionError, BrokerAuthorizationFenceV1,
    BrokerEffectClockComparisonV3, BrokerEffectClockDispositionV1, BrokerEffectIntentV1,
    BrokerSignedAdmissionOriginalV4, NetworkPublicCredentialsOriginalV2, NetworkPublicVerifierV2,
    ProtectedBrokerPublicCredentialRevalidationOriginalV1, ProtectedBrokerPublicCredentials,
};
use aos_sandbox_model::{
    BrokerAdmissionIntersection, BrokerAudience, BrokerVerb, ProtocolId, RawPairedClockSample,
    ResourceDimension as D, ResourceVector,
};
use aos_sandbox_linux::seqpacket::RecordBindingError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_protocol::semantics::network::CanonicalNetworkSemanticsV1;
use aos_sandbox_protocol::session::AuthorizationArtifactBytes;

use super::{NetworkNamespaceObservedStateKindV1, ObservationRequestV1};
use crate::observer_handoff_v2::ObserverHandoffDataV2;
use crate::worker_protocol::{NetworkWorkerProtocolError, decode_admitted_semantics};

/// Refuses the read while its owning original retains the actual first cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Network observer read admission is closed")]
pub(crate) struct ObserverReadClosedV2;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("the original observer effect clock is stale")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(error: aos_sandbox_linux::Error) -> Self {
        Self::Kernel(error)
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Origin,
    Source,
    Shape,
    Fence,
    Operation,
    Effect,
    Clock,
    SourceBefore,
    Credentials,
    Semantic,
    Observation,
    Signature,
    CredentialsAfter,
    SourceAfter,
    OriginAfter,
    ClockAfter,
    ClockFinal,
}

/// Owns one genuine original observer admission and every reached native prefix.
#[must_use]
pub(crate) struct NetworkObserverReadOriginalV2 {
    entered: bool,
    first: Option<First>,
    record: Option<ReceivedDescriptorRecord>,
    origin: Option<Result<(), RecordBindingError>>,
    origin_after: Option<Result<(), RecordBindingError>>,
    source_record: NetworkChildSourceRecordOriginalV2,
    source_before: NetworkChildSourceProbeOriginalV2,
    source_after: NetworkChildSourceProbeOriginalV2,
    source_negative_after: NetworkChildSourceProbeOriginalV2,
    credentials: NetworkPublicCredentialsOriginalV2,
    completed: Option<(NetworkPublicVerifierV2, ProtectedBrokerPublicCredentials)>,
    credentials_after: ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    fence: Option<Result<BrokerAuthorizationFenceV1, AuthorizationRecordError>>,
    operation: Option<Result<BrokerAuthorizationFenceV1, AuthorizationRecordError>>,
    effect: Option<Result<BrokerEffectIntentV1, AuthorizationRecordError>>,
    clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    clock_after: RetainedKernelPairedClockAttemptV1<ClockError>,
    clock_final: RetainedKernelPairedClockAttemptV1<ClockError>,
    clock_value: Option<RawPairedClockSample>,
    clock_checks: [Option<Result<(), BrokerAdmissionError>>; 3],
    semantic: Option<Result<CanonicalNetworkSemanticsV1, NetworkWorkerProtocolError>>,
    observation: Option<Result<ObservationRequestV1, super::NetworkObservationWorkerError>>,
    signed: BrokerSignedAdmissionOriginalV4,
    intersection: Option<Result<BrokerAdmissionIntersection, BrokerAdmissionError>>,
}

impl NetworkObserverReadOriginalV2 {
    /// Creates inert destinations before the parent quotes the whole programme.
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            record: None,
            origin: None,
            origin_after: None,
            source_record: NetworkChildSourceRecordOriginalV2::new(),
            source_before: NetworkChildSourceProbeOriginalV2::new(),
            source_after: NetworkChildSourceProbeOriginalV2::new(),
            source_negative_after: NetworkChildSourceProbeOriginalV2::new(),
            credentials: NetworkPublicCredentialsOriginalV2::new(),
            completed: None,
            credentials_after: ProtectedBrokerPublicCredentialRevalidationOriginalV1::new(),
            fence: None,
            operation: None,
            effect: None,
            clock: Default::default(),
            clock_after: Default::default(),
            clock_final: Default::default(),
            clock_value: None,
            clock_checks: [None, None, None],
            semantic: None,
            observation: None,
            signed: BrokerSignedAdmissionOriginalV4::new(),
            intersection: None,
        }
    }

    /// Quotes native/read owners beyond the separately priced exact O6 carrier.
    /// The same parent also adds its actual signed-verification quote and the
    /// finite Source-probe programme before PREBIRTH. Neither is a new bank.
    pub(crate) fn receiving_obligations_data_v2(
        original_request_bytes: usize,
    ) -> Option<ResourceVector> {
        if original_request_bytes == 0
            || original_request_bytes > aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES
        {
            return None;
        }
        let mut demand = NetworkPublicCredentialsOriginalV2::receiving_demand_v2().ok()?;
        demand = demand
            .checked_add(NetworkChildSourceRecordOriginalV2::receiving_obligations_data_v2()?)
            .ok()?;
        // The same retained Protocol supplier covers the reached protobuf and
        // canonical semantic models, including rejected partial repeated fields.
        demand = demand.checked_add(aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(original_request_bytes)?).ok()?;
        demand = demand
            .checked_add(crate::kernel_plan::compilation_receiving_demand_v4().ok()?)
            .ok()?;
        let revalidation =
            ProtectedBrokerPublicCredentialRevalidationOriginalV1::receiving_obligations_v1()?;
        let clock =
            RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<NetworkObserverReadLoanV2<'_, '_>>().checked_mul(2)?)?
            .checked_add(revalidation.0)?
            .checked_add(clock.checked_mul(3)?)?
            .checked_add(2 * 255)?;
        let files = revalidation.1.checked_add(
            RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
                .checked_mul(3)?,
        )?;
        let metadata = revalidation.2.checked_add(
            RetainedKernelPairedClockAttemptV1::<ClockError>::receiving_metadata_cells_v1()?
                .checked_mul(3)?,
        )?;
        demand
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                    .with(D::OpenFiles, u64::try_from(files).ok()?)
                    .with(D::MetadataEntries, u64::try_from(metadata).ok()?),
            )
            .ok()
    }

    /// Admits only the original signed operation after genuine child bootstrap.
    /// Native Source, socket and credential posts remain independently owed on
    /// failure. The received packet/subject remain resident after rights move.
    pub(crate) fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        channel: &mut DescriptorSubjectSocket,
        record: ReceivedDescriptorRecord,
    ) -> Result<(), ObserverReadClosedV2> {
        if self.entered {
            return self.refuse(First::Order);
        }
        self.entered = true;
        self.record = Some(record);
        let _ = self.capture_inner(source, channel);

        if let Some((_, credentials)) = self.completed.as_ref() {
            if credentials
                .revalidated_descriptor_evidence_retaining_v1(&mut self.credentials_after)
                .is_err()
            {
                self.first.get_or_insert(First::CredentialsAfter);
            }
        }
        if let Some(Ok(effect)) = self.effect.as_ref() {
            let after = self.clock_after.observe_once(None);
            let wait = if let Ok(clock) = after {
                self.clock_checks[1] = Some(classify_original(effect, clock));
                if !matches!(self.clock_checks[1], Some(Ok(()))) {
                    self.first.get_or_insert(First::ClockAfter);
                }
                original_wait(effect, clock).unwrap_or(rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                })
            } else {
                self.first.get_or_insert(First::ClockAfter);
                rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }
            };
            // This already-prepaid negative Source bookend remains owed after
            // clock refusal. Zero wait cannot renew D or authorize a read.
            if source
                .require_live_before_once_v2(&mut self.source_after, Some(&wait))
                .is_err()
            {
                self.first.get_or_insert(First::SourceAfter);
            }
        }
        if let Some(record) = self.record.as_ref() {
            self.origin_after = Some(channel.validate_received_origin_retaining(record));
            if !matches!(self.origin_after, Some(Ok(()))) {
                self.first.get_or_insert(First::OriginAfter);
            }
        }
        if let Some(Ok(effect)) = self.effect.as_ref() {
            match self.clock_final.observe_once(None) {
                Ok(clock) => {
                    self.clock_checks[2] = Some(classify_original(effect, clock));
                    if !matches!(self.clock_checks[2], Some(Ok(()))) {
                        self.first.get_or_insert(First::ClockFinal);
                    }
                }
                Err(_) => {
                    self.first.get_or_insert(First::ClockFinal);
                }
            }
        }
        if self.first.is_some() {
            // Native negative posts do not borrow effect authority and remain
            // owed even when an earlier failure fenced the Source query lane.
            let _ = source.observe_owed_native_after_once_v2(&mut self.source_negative_after);
            Err(ObserverReadClosedV2)
        } else {
            Ok(())
        }
    }

    fn capture_inner(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        channel: &mut DescriptorSubjectSocket,
    ) -> Result<(), ObserverReadClosedV2> {
        let record = self.record.as_ref().ok_or(ObserverReadClosedV2)?;
        self.origin = Some(channel.validate_received_origin_retaining(record));
        if !matches!(self.origin, Some(Ok(()))) {
            return self.refuse(First::Origin);
        }
        if source
            .require_same_netd_record_once_v2(record, &mut self.source_record)
            .is_err()
        {
            return self.refuse(First::Source);
        }
        let data = ObserverHandoffDataV2::decode(record.payload()).ok_or_else(|| {
            self.first.get_or_insert(First::Shape);
            ObserverReadClosedV2
        })?;
        if !source
            .operation_binding_data_v2()
            .is_some_and(|native| data.matches_native(native))
        {
            return self.refuse(First::Shape);
        }
        self.fence = Some(
            BrokerAuthorizationFenceV1::decode_network_handoff_payload_data_v2(data.sections[5]),
        );
        self.operation = Some(
            BrokerAuthorizationFenceV1::decode_network_handoff_payload_data_v2(data.sections[6]),
        );
        self.effect =
            Some(BrokerEffectIntentV1::decode_network_handoff_payload_data_v2(data.sections[7]));
        if !matches!(self.fence, Some(Ok(_))) {
            return self.refuse(First::Fence);
        }
        if !matches!(self.operation, Some(Ok(_))) {
            return self.refuse(First::Operation);
        }
        if !matches!(self.effect, Some(Ok(_))) {
            return self.refuse(First::Effect);
        }
        self.clock_value = self.clock.observe_once(None).ok();
        let clock = self.clock_value.ok_or_else(|| {
            self.first.get_or_insert(First::Clock);
            ObserverReadClosedV2
        })?;
        let effect = self
            .effect
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ObserverReadClosedV2)?;
        self.clock_checks[0] = Some(classify_original(effect, clock));
        if effect.host_boot_id() != &data.boot
            || effect.request_id() != &data.request_id
            || !matches!(self.clock_checks[0], Some(Ok(())))
        {
            return self.refuse(First::Clock);
        }
        let wait = original_wait(effect, clock).ok_or(ObserverReadClosedV2)?;
        if source
            .require_live_before_once_v2(&mut self.source_before, Some(&wait))
            .is_err()
        {
            return self.refuse(First::SourceBefore);
        }
        let expected = data.credentials;
        let record = self.record.as_mut().ok_or(ObserverReadClosedV2)?;
        let files = record
            .take_network_observer_handoff_descriptors_data_v2()
            .ok_or(ObserverReadClosedV2)?;
        let files = match files.try_into() {
            Ok(files) => files,
            Err(_files) => return self.refuse(First::Shape),
        };
        if self.credentials.capture_once_v2(files, expected).is_err() {
            return self.refuse(First::Credentials);
        }
        self.completed = self.credentials.take_completed_once_v2();
        if self.completed.is_none() {
            return self.refuse(First::Credentials);
        }
        let data = ObserverHandoffDataV2::decode(
            self.record.as_ref().ok_or(ObserverReadClosedV2)?.payload(),
        )
        .ok_or(ObserverReadClosedV2)?;
        self.semantic = Some(decode_admitted_semantics(data.sections[0]));
        self.observation = Some(ObservationRequestV1::decode(data.sections[8]));
        let semantic = match self.semantic.as_ref() {
            Some(Ok(value)) => value,
            _ => return self.refuse(First::Semantic),
        };
        let observation = match self.observation.as_ref() {
            Some(Ok(value)) => value,
            _ => return self.refuse(First::Observation),
        };
        let valid_mode = matches!(
            (semantic.broker_verb(), observation.expected_state.kind()),
            (
                BrokerVerb::NetworkPrepare,
                NetworkNamespaceObservedStateKindV1::DefaultDrop
            ) | (
                BrokerVerb::NetworkDestroy,
                NetworkNamespaceObservedStateKindV1::Absent
            )
        );
        if !valid_mode
            || *semantic.header().request_id() != data.request_id
            || observation.request_id != data.request_id
            || observation.effect_digest.as_bytes() != &data.effect_digest
            || observation.kernel_boot_id != data.boot
            || semantic.fence().broker_assignment().ok() != Some(observation.plan.assignment())
            || semantic
                .operation()
                .network_handle()
                .is_some_and(|handle| handle != observation.plan.network_handle())
        {
            return self.refuse(First::Observation);
        }
        let effect = self
            .effect
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ObserverReadClosedV2)?;
        let request = AdmissionRequest {
            audience: BrokerAudience::Network,
            protocol: ProtocolId::NetworkBroker,
            protocol_version: semantic.header().protocol_version(),
            assignment: observation.plan.assignment(),
            request_id: data.request_id,
            request_body: data.sections[0],
            descriptor_count: u16::from(semantic.preparation_content_reference_v2().is_some()),
            verb: semantic.broker_verb(),
            target: semantic.grant_target(),
            argument_commitment: semantic.argument_commitment(),
            request_deadline_boottime_nanoseconds: semantic
                .header()
                .deadline_boottime_nanoseconds(),
        };
        let artifacts = AuthorizationArtifactBytes {
            broker_plan: data.sections[1],
            broker_plan_signature: data.sections[2],
            ownership_lease: data.sections[3],
            ownership_lease_signature: data.sections[4],
        };
        let (verifier, _) = self.completed.as_ref().ok_or(ObserverReadClosedV2)?;
        self.intersection = Some(
            verifier.verify_original_network_read_once_v2(
                artifacts,
                request,
                &clock,
                self.fence
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ObserverReadClosedV2)?,
                self.operation
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(ObserverReadClosedV2)?,
                effect,
                &mut self.signed,
            ),
        );
        if !matches!(self.intersection, Some(Ok(_))) {
            return self.refuse(First::Signature);
        }
        Ok(())
    }

    /// Borrows only the actual received record for prepaid negative custody.
    /// This supplies no read admission, currentness or financial permission;
    /// the disposition owner must authenticate its actual Source and origin.
    pub(super) fn received_original_for_owed_custody_v3(
        &self,
    ) -> Option<&ReceivedDescriptorRecord> {
        self.record.as_ref()
    }

    /// Borrows the admitted original observation after every independent post.
    pub(super) fn request(&self) -> Result<&ObservationRequestV1, ObserverReadClosedV2> {
        if self.first.is_some() || !matches!(self.intersection, Some(Ok(_))) {
            return Err(ObserverReadClosedV2);
        }
        self.observation
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ObserverReadClosedV2)
    }

    /// Compares a separate namespace-carrier body with this admitted original.
    /// The caller still authenticates that carrier's same live Netd Source and
    /// actual namespace roles; this comparison grants no descriptor authority.
    pub(super) fn require_same_observation_request_data_v2(
        &self,
        payload: &[u8],
    ) -> Result<(), ObserverReadClosedV2> {
        self.request()?;
        let data = ObserverHandoffDataV2::decode(
            self.record.as_ref().ok_or(ObserverReadClosedV2)?.payload(),
        )
        .ok_or(ObserverReadClosedV2)?;
        if data.sections[8] != payload {
            return Err(ObserverReadClosedV2);
        }
        Ok(())
    }

    pub(crate) fn original_effect_v2(&self) -> Result<&BrokerEffectIntentV1, ObserverReadClosedV2> {
        self.request()?;
        self.effect
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ObserverReadClosedV2)
    }

    /// Lends only this admitted read and the same original native Source.
    pub(crate) fn borrow_live_read_v2<'held, 'native>(
        &'held self,
        source: &NetworkChildSourceLoanV2<'native>,
    ) -> Result<NetworkObserverReadLoanV2<'held, 'native>, ObserverReadClosedV2> {
        self.request()?;
        let data = ObserverHandoffDataV2::decode(
            self.record.as_ref().ok_or(ObserverReadClosedV2)?.payload(),
        )
        .ok_or(ObserverReadClosedV2)?;
        let binding = source
            .operation_binding_data_v2()
            .ok_or(ObserverReadClosedV2)?;
        if !data.matches_native(binding) {
            return Err(ObserverReadClosedV2);
        }
        let effect = self.original_effect_v2()?;
        let lease = self
            .operation
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ObserverReadClosedV2)?
            .local_lease_record();
        let credentials = &self.completed.as_ref().ok_or(ObserverReadClosedV2)?.1;
        let affinity = source
            .lend_affinity_original_v2()
            .map_err(|_| ObserverReadClosedV2)?;
        Ok(NetworkObserverReadLoanV2 {
            effect,
            lease,
            credentials,
            binding,
            affinity,
            plan: &self.request()?.plan,
        })
    }

    fn refuse<T>(&mut self, first: First) -> Result<T, ObserverReadClosedV2> {
        self.first.get_or_insert(first);
        Err(ObserverReadClosedV2)
    }

    /// Borrows retained native/typed detail without changing the primary cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let actual: Option<&(dyn Error + 'static)> = match self.first? {
            First::Source => self.source_record.failure(),
            First::SourceBefore => self.source_before.failure(),
            First::SourceAfter => self.source_after.failure(),
            First::Credentials => self.credentials.failure(),
            First::CredentialsAfter => self.credentials_after.failure(),
            First::Clock => self
                .clock
                .failure()
                .or_else(|| failure(&self.clock_checks[0])),
            First::ClockAfter => self
                .clock_after
                .failure()
                .or_else(|| failure(&self.clock_checks[1])),
            First::ClockFinal => self
                .clock_final
                .failure()
                .or_else(|| failure(&self.clock_checks[2])),
            First::Signature => self.signed.failure(),
            First::Origin => failure(&self.origin),
            First::OriginAfter => failure(&self.origin_after),
            First::Fence => failure(&self.fence),
            First::Operation => failure(&self.operation),
            First::Effect => failure(&self.effect),
            First::Semantic => failure(&self.semantic),
            First::Observation => failure(&self.observation),
            _ => None,
        };
        actual.or(Some(&ObserverReadClosedV2))
    }
}

/// Borrows the admitted read and its genuine still-enrolled native Source.
/// The type cannot authorize mutation, replace a fence or renew an operation.
pub(crate) struct NetworkObserverReadLoanV2<'held, 'native> {
    effect: &'held BrokerEffectIntentV1,
    lease: &'held aos_sandbox_model::LocalLeaseRecord,
    credentials: &'held ProtectedBrokerPublicCredentials,
    binding: NetworkChildOperationBindingDataV2,
    affinity: NetworkChildSourceAffinityOriginalV2<'native>,
    plan: &'held crate::NetworkKernelPlanV1,
}

impl NetworkObserverReadLoanV2<'_, '_> {
    /// Borrows only the canonical plan from this same admitted O original.
    pub(crate) fn original_kernel_plan_v2(&self) -> &crate::NetworkKernelPlanV1 {
        self.plan
    }

    /// Requires the shared helper port to borrow this exact native operation.
    /// Comparison DATA alone cannot construct either borrowed permission.
    pub(crate) fn require_same_native_source_v2(
        &self,
        source: &NetworkChildSourceLoanV2<'_>,
    ) -> Result<(), ObserverReadClosedV2> {
        source
            .require_same_affinity_original_v2(&self.affinity)
            .map_err(|_| ObserverReadClosedV2)?;
        if source.operation_binding_data_v2() != Some(self.binding) {
            return Err(ObserverReadClosedV2);
        }
        Ok(())
    }

    /// Rechecks the same public pins and unchanged signed WALL/BOOT/D.
    /// The shared private Source port supplies the actual protected clock and
    /// independently owns native Source probes and their negative bookends.
    pub(crate) fn require_current_before_read_v2(
        &self,
        actual_clock: RawPairedClockSample,
        original: &mut NetworkObserverReadCurrentOriginalV2,
    ) -> Result<(), ObserverReadClosedV2> {
        self.observe_public_current_once_v2(Some(actual_clock), original)
    }

    /// Performs only owed public-pin posts after a failed native clock sample.
    /// This always refuses positive use and never substitutes a clock sample.
    pub(crate) fn observe_owed_public_after_once_v2(
        &self,
        original: &mut NetworkObserverReadCurrentOriginalV2,
    ) -> Result<(), ObserverReadClosedV2> {
        self.observe_public_current_once_v2(None, original)
    }

    fn observe_public_current_once_v2(
        &self,
        actual_clock: Option<RawPairedClockSample>,
        original: &mut NetworkObserverReadCurrentOriginalV2,
    ) -> Result<(), ObserverReadClosedV2> {
        if original.entered {
            original.reentry = Some(ObserverReadClosedV2);
            return Err(ObserverReadClosedV2);
        }
        original.entered = true;
        original.current = Some(match actual_clock {
            Some(actual_clock) => BrokerEffectClockComparisonV3::from_effect(self.effect)
                .classify(&actual_clock)
                .and_then(|disposition| match disposition {
                    BrokerEffectClockDispositionV1::Fresh => Ok(()),
                    BrokerEffectClockDispositionV1::Expired => {
                        Err(BrokerAdmissionError::FenceRejected)
                    }
                }),
            None => Err(BrokerAdmissionError::FenceRejected),
        });
        // Public native bookends remain owed after clock refusal. No re-read
        // can replace the completed lease or turn expiry into a fresh permit.
        original.credentials_result = Some(
            self.credentials
                .revalidated_descriptor_evidence_retaining_v1(&mut original.credentials)
                .map(|_| ()),
        );
        if !matches!(original.current, Some(Ok(())))
            || !matches!(original.credentials_result, Some(Ok(())))
        {
            return Err(ObserverReadClosedV2);
        }
        Ok(())
    }

    pub(crate) fn original_effect_v2(&self) -> &BrokerEffectIntentV1 {
        self.effect
    }

    pub(crate) fn original_local_lease_v2(&self) -> &aos_sandbox_model::LocalLeaseRecord {
        self.lease
    }
}

/// Retains one finite public read frontier, including actual native read debt.
#[must_use]
pub(crate) struct NetworkObserverReadCurrentOriginalV2 {
    entered: bool,
    reentry: Option<ObserverReadClosedV2>,
    current: Option<Result<(), BrokerAdmissionError>>,
    credentials: ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    credentials_result: Option<Result<(), aos_sandbox_broker::BrokerAuthorityConfigError>>,
}

impl NetworkObserverReadCurrentOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            reentry: None,
            current: None,
            credentials: ProtectedBrokerPublicCredentialRevalidationOriginalV1::new(),
            credentials_result: None,
        }
    }

    /// Quotes only this actual public/read owner. The shared helper port pays
    /// its own protected clocks and Source probes once through their suppliers.
    pub(crate) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let credentials =
            ProtectedBrokerPublicCredentialRevalidationOriginalV1::receiving_obligations_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(credentials.0)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(credentials.1).ok()?)
                .with(D::MetadataEntries, u64::try_from(credentials.2).ok()?),
        )
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.current)
            .or_else(|| self.credentials.failure())
            .or_else(|| failure(&self.credentials_result))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

fn classify_original(
    effect: &BrokerEffectIntentV1,
    clock: RawPairedClockSample,
) -> Result<(), BrokerAdmissionError> {
    match BrokerEffectClockComparisonV3::from_effect(effect).classify(&clock)? {
        BrokerEffectClockDispositionV1::Fresh => Ok(()),
        BrokerEffectClockDispositionV1::Expired => Err(BrokerAdmissionError::FenceRejected),
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}

fn original_wait(
    effect: &BrokerEffectIntentV1,
    clock: RawPairedClockSample,
) -> Option<rustix::event::Timespec> {
    let remaining = effect
        .effect_deadline_boottime_nanoseconds()
        .checked_sub(clock.boottime_nanoseconds())?;
    if remaining == 0 {
        return None;
    }
    Some(rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).ok()?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).ok()?,
    })
}
