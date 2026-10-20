//! Retains Root's own four configured broker manifests through owed native posts.
//!
//! These fixed credential owners use the existing shared reader. Only actual
//! configured public manifests enter; no request packet supplies a trust key.
//! Canonical role checks yield comparison DATA, never a Session or six-owner
//! grant. The later independent packet/native verifier must use these models.

use super::*;
use aos_sandbox_broker::systemd_credentials::{
    RootCurrentStorageManifestCustodyV1, RootDeleteBrokerManifestsCustodyV2,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1,
    manifest::{
        BrokerSessionManifestAudienceV1, BrokerSessionManifestErrorV1, BrokerSessionManifestV1,
    },
};

#[derive(Clone, Copy)]
enum TrustFirst {
    Arm,
    ClockBefore,
    Before,
    Brokers,
    BrokerModel(usize),
    Storage,
    StorageModel,
    BrokerPost,
    StoragePost,
    After,
    ClockAfter,
    Reentry,
}

#[derive(Debug, thiserror::Error)]
enum ManifestError {
    #[error(transparent)]
    Canonical(#[from] BrokerSessionManifestErrorV1),
    #[error("the configured Root broker manifest has a different fixed role or audience")]
    Role,
}

pub(super) struct RootDeleteBrokerTrustOriginalV2 {
    brokers: Option<RootDeleteBrokerManifestsCustodyV2>,
    storage: Option<RootCurrentStorageManifestCustodyV1>,
    models: [Option<Result<BrokerSessionManifestV1, ManifestError>>; 4],
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_before_original: RetainedKernelPairedClockAttemptV1,
    clock_before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    clock_after_original: RetainedKernelPairedClockAttemptV1,
    clock_after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    entered: bool,
    brokers_entered: bool,
    storage_entered: bool,
    complete: bool,
    first: Option<TrustFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteBrokerTrustOriginalV2 {
    fn default() -> Self {
        Self {
            brokers: Some(RootDeleteBrokerManifestsCustodyV2::new()),
            storage: Some(RootCurrentStorageManifestCustodyV1::new()),
            models: std::array::from_fn(|_| None),
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            clock_before_original: Default::default(),
            clock_before: None,
            before_binding: None,
            clock_after_original: Default::default(),
            clock_after: None,
            after_binding: None,
            entered: false,
            brokers_entered: false,
            storage_entered: false,
            complete: false,
            first: None,
            closed: None,
        }
    }
}

impl RootDeleteBrokerTrustOriginalV2 {
    pub(super) fn demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(clock.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let demand = RootDeleteBrokerManifestsCustodyV2::dominant_demand()
            .ok_or_else(invalid)?
            .checked_add(
                RootCurrentStorageManifestCustodyV1::dominant_demand().ok_or_else(invalid)?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
                D::OpenFiles,
                2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
            ))
            .map_err(ResourceReservationErrorV1::from)?;
        if self.complete && self.brokers.is_none() && self.storage.is_none() {
            // Both whole fixed credential prefixes have physically gone after
            // their native rechecks and the enclosing Root/clock afters. The
            // clock originals remain owned; all memory/name bounds and SAME R
            // historical highwater/traffic remain unchanged.
            let clocks =
                u64::try_from(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                    .map_err(|_| invalid())?
                    .checked_mul(2)
                    .ok_or_else(invalid)?;
            Ok(demand.with(D::OpenFiles, clocks))
        } else {
            Ok(demand)
        }
    }

    fn observe_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(TrustFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(TrustFirst::Arm);
        } else {
            self.clock_before = Some(self.clock_before_original.observe_once(None));
            self.before_binding = Some(
                positive(&self.clock_before)
                    .and_then(|sample| challenge.require_current_clock_v1(*sample)),
            );
            self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
            if !matches!(self.before_binding, Some(Ok(()))) {
                self.first = Some(TrustFirst::ClockBefore);
            }
            if !matches!(self.before, Some(Ok(()))) {
                self.first.get_or_insert(TrustFirst::Before);
            }
            if self.first.is_none() {
                self.capture_primary();
            }
        }
        // Final native names/bytes are independently owed for each actual
        // entered credential capture, even after framing/model/capture failure.
        if self.brokers_entered
            && self
                .brokers
                .as_mut()
                .is_none_or(|native| native.recheck_once().is_err())
        {
            self.first.get_or_insert(TrustFirst::BrokerPost);
        }
        if self.storage_entered
            && self
                .storage
                .as_mut()
                .is_none_or(|native| native.recheck_once().is_err())
        {
            self.first.get_or_insert(TrustFirst::StoragePost);
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(TrustFirst::After);
        }
        self.clock_after = Some(self.clock_after_original.observe_once(None));
        self.after_binding = Some((|| {
            let before = *positive(&self.clock_before)?;
            let after = *positive(&self.clock_after)?;
            before
                .validate_later_sample(after)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(after)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(TrustFirst::ClockAfter);
        }
        if self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        // The four complete installed manifests are already owned by models.
        // No failed native prefix can reach this consuming disposal frontier.
        // The destinations stay absent: this original cannot recapture/rearm.
        drop(self.brokers.take());
        drop(self.storage.take());
        self.complete = true;
        Ok(())
    }

    fn capture_primary(&mut self) {
        let Some(brokers) = self.brokers.as_mut() else {
            self.first = Some(TrustFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return;
        };
        self.brokers_entered = true;
        if brokers.capture_once().is_err() {
            self.first = Some(TrustFirst::Brokers);
            return;
        }
        for (index, (bytes, protocol)) in [
            (brokers.host_bytes(), BrokerSessionProtocolV1::Host),
            (brokers.mount_bytes(), BrokerSessionProtocolV1::Mount),
            (brokers.network_bytes(), BrokerSessionProtocolV1::Network),
        ]
        .into_iter()
        .enumerate()
        {
            self.models[index] = Some(decode_fixed_manifest(bytes, protocol));
            if !matches!(self.models[index], Some(Ok(_))) {
                self.first = Some(TrustFirst::BrokerModel(index));
                return;
            }
        }
        let Some(storage) = self.storage.as_mut() else {
            self.first = Some(TrustFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return;
        };
        self.storage_entered = true;
        if storage.capture_once().is_err() {
            self.first = Some(TrustFirst::Storage);
            return;
        }
        self.models[3] = Some(decode_fixed_manifest(
            storage.bytes(),
            BrokerSessionProtocolV1::Storage,
        ));
        if !matches!(self.models[3], Some(Ok(_))) {
            self.first = Some(TrustFirst::StorageModel);
        }
    }

    pub(super) fn manifest(
        &self,
        index: usize,
    ) -> Result<&BrokerSessionManifestV1, RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.models
            .get(index)
            .and_then(|value| value.as_ref())
            .and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed(&self) -> bool {
        matches!(self.first, Some(TrustFirst::Arm)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            TrustFirst::Before | TrustFirst::After => {
                self.posts.property_failure_view_v1(self.failure()?)
            }
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            TrustFirst::Arm => self.posts.before_failure_v1().or_else(|| cause(&self.arm)),
            TrustFirst::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.before)),
            TrustFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            TrustFirst::ClockBefore => self
                .clock_before_original
                .failure()
                .or_else(|| cause(&self.clock_before))
                .or_else(|| cause(&self.before_binding)),
            TrustFirst::ClockAfter => self
                .clock_after_original
                .failure()
                .or_else(|| cause(&self.clock_after))
                .or_else(|| cause(&self.after_binding)),
            TrustFirst::Brokers => self
                .brokers
                .as_ref()?
                .capture_failure()
                .map(|cause| cause as _),
            TrustFirst::BrokerPost => self
                .brokers
                .as_ref()?
                .post_failure()
                .map(|cause| cause as _),
            TrustFirst::Storage => self
                .storage
                .as_ref()?
                .capture_failure()
                .map(|cause| cause as _),
            TrustFirst::StoragePost => self
                .storage
                .as_ref()?
                .post_failure()
                .map(|cause| cause as _),
            TrustFirst::BrokerModel(index) => cause(&self.models[index]),
            TrustFirst::StorageModel => cause(&self.models[3]),
            TrustFirst::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn decode_fixed_manifest(
    bytes: Option<&[u8]>,
    expected: BrokerSessionProtocolV1,
) -> Result<BrokerSessionManifestV1, ManifestError> {
    let manifest = BrokerSessionManifestV1::decode(bytes.ok_or(ManifestError::Role)?)?;
    manifest.require_all_active()?;
    if manifest.protocol() != expected
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
    {
        return Err(ManifestError::Role);
    }
    Ok(manifest)
}

impl RootDeleteControllerCurrentOriginalV1 {
    pub(in crate::policy_compiler::delete_root) fn observe_broker_trust_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.verified_authorization_cut_data_v2()?;
        if self.broker_trust.entered || self.first.is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::BrokerTrust,
        )?;
        if self.broker_trust.observe_once(flight, challenge).is_err() {
            self.first.get_or_insert(First::BrokerTrust);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn broker_manifests_v2(
        &self,
    ) -> Result<
        (
            &BrokerSessionManifestV1,
            &BrokerSessionManifestV1,
            &BrokerSessionManifestV1,
            &BrokerSessionManifestV1,
        ),
        RootDeleteErrorV1,
    > {
        self.verified_authorization_cut_data_v2()?;
        Ok((
            self.broker_trust.manifest(0)?,
            self.broker_trust.manifest(1)?,
            self.broker_trust.manifest(3)?,
            self.broker_trust.manifest(2)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker_session_protocol::{
        BrokerSessionKeyUsageV1 as Usage, BrokerSessionSignerReferenceV1,
        manifest::BrokerSessionManifestKeyPinV1,
    };
    use ed25519_dalek::SigningKey;

    fn manifest(revoked: bool) -> BrokerSessionManifestV1 {
        let usages = [
            Usage::ClientHello,
            Usage::BrokerHello,
            Usage::ClientRecord,
            Usage::BrokerOutcome,
        ];
        let pins = std::array::from_fn(|index| {
            let key = SigningKey::from_bytes(&[40 + index as u8; 32]);
            let signer = BrokerSessionSignerReferenceV1::for_signing_key(
                [10 + index as u8; 16],
                1,
                [20 + index as u8; 32],
                [30 + index as u8; 16],
                1,
                usages[index],
                &key,
            )
            .unwrap();
            BrokerSessionManifestKeyPinV1::new(
                signer,
                key.verifying_key().to_bytes(),
                1,
                1,
                revoked && index == 3,
                None,
            )
            .unwrap()
        });
        BrokerSessionManifestV1::new(
            BrokerSessionProtocolV1::Storage,
            BrokerSessionManifestAudienceV1::NodeController,
            1,
            0,
            [1; 16],
            [2; 16],
            1,
            [3; 32],
            1,
            [4; 32],
            1,
            [5; 32],
            [6; 16],
            pins,
        )
        .unwrap()
    }

    #[test]
    fn fixed_manifest_decoder_refuses_foreign_role_and_local_revocation() {
        let bytes = manifest(false).encode();
        assert!(decode_fixed_manifest(Some(&bytes), BrokerSessionProtocolV1::Storage).is_ok());
        for role in [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
        ] {
            assert!(matches!(
                decode_fixed_manifest(Some(&bytes), role),
                Err(ManifestError::Role)
            ));
        }
        assert!(
            decode_fixed_manifest(
                Some(&manifest(true).encode()),
                BrokerSessionProtocolV1::Storage
            )
            .is_err()
        );
        assert!(decode_fixed_manifest(None, BrokerSessionProtocolV1::Storage).is_err());
    }

    #[test]
    fn empty_native_destination_never_lends_a_trust_model() {
        let original = RootDeleteBrokerTrustOriginalV2::default();
        for index in 0..4 {
            assert!(original.manifest(index).is_err());
        }
    }
}
