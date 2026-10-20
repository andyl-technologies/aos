//! Captures only fixed Host trust and a fresh paid Root current-read challenge.
//!
//! The existing native public credential engine retains the same protected
//! Host manifest and both readbacks. No active ownership lease is needed to
//! verify an irreversible terminal during recovery. The comparison remains
//! DATA; this original grants neither a Host lease nor a Root floor append.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_broker::systemd_credentials::RootCurrentHostManifestCustodyV2;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1,
    manifest::{BrokerSessionManifestAudienceV1, BrokerSessionManifestV1},
};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::host_execution_no_apply::current_lease::CurrentHostNoApplyLeaseDataV2;

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootExecutionNoApplyStageReceivingV2};
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1, RootContinuationHorizonDataV1,
};

type Cause = Box<dyn Error>;

pub(crate) struct RootExecutionNoApplyHostTrustOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    reentry: Option<JournalError>,
}

struct Native {
    files: RootCurrentHostManifestCustodyV2,
    clock: RootContinuationClockGateV1,
    comparison: CurrentHostNoApplyLeaseDataV2,
    captured: Option<Result<(), ()>>,
    manifest: Option<Result<BrokerSessionManifestV1, Cause>>,
    nonce_originals: [RetainedKernelNonceOriginalV1; 2],
    nonces: [Option<Result<[u8; 16], EntropyError>>; 2],
    body: Option<Result<(), Cause>>,
    posted: Option<Result<(), ()>>,
    first: Option<Failure>,
    lease_crossing: Option<JournalError>,
}

#[derive(Clone, Copy)]
enum Failure {
    Clock,
    Capture,
    Manifest,
    FirstNonce,
    SecondNonce,
    Relation,
}

impl RootExecutionNoApplyHostTrustOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            native: None,
            reentry: None,
        }
    }

    /// Pays the actual fixed owner before constructing or observing native IO.
    pub(crate) fn prepare_once_v2(
        &mut self,
        stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        horizon: RootContinuationHorizonDataV1,
        comparison: CurrentHostNoApplyLeaseDataV2,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            let bytes = size_of::<Native>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
                .and_then(|bytes| {
                    bytes.checked_add(
                        RetainedKernelNonceOriginalV1::construction_bytes_v1()?.checked_mul(2)?,
                    )
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            RootCurrentHostManifestCustodyV2::dominant_demand()
                .ok_or(JournalError::JournalTooLarge)?
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_execution_no_apply_host_trust_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native {
            files: RootCurrentHostManifestCustodyV2::new(),
            clock: RootContinuationClockGateV1::new(horizon),
            comparison,
            captured: None,
            manifest: None,
            nonce_originals: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
            nonces: [None, None],
            body: None,
            posted: None,
            first: None,
            lease_crossing: None,
        }));
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        native.body = Some(native.observe_body_v2(stage));
        self.manifest_v2().map(|_| ())
    }

    pub(super) fn manifest_v2(&self) -> Result<&BrokerSessionManifestV1, JournalError> {
        let native = self.body_native_v2()?;
        native
            .manifest
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn read_nonce_data_v2(&self) -> Result<[u8; 32], JournalError> {
        self.body_native_v2()?.read_nonce_v2()
    }

    pub(super) fn comparison_data_v2(&self) -> Result<CurrentHostNoApplyLeaseDataV2, JournalError> {
        Ok(self.body_native_v2()?.comparison)
    }

    /// Narrows the same paid clock with this genuine acquisition's fresh cap.
    /// Every existing append, crossing, signature and ACK sample then enforces
    /// the bound; callers cannot supply an expiry or create another origin.
    pub(super) fn narrow_recovery_cap_v2(
        &mut self,
        acquisition: &super::RootExecutionNoApplyAcquisitionOriginalV2,
    ) -> Result<(), JournalError> {
        self.body_native_v2()?;
        let expires = acquisition.recover_wall_expiry_v2()?;
        self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .clock.narrow_wall_expiry_data_v1(expires);
        Ok(())
    }

    pub(super) fn next_sample_v2(&mut self) -> Result<RawPairedClockSample, JournalError> {
        self.body_native_v2()?;
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        let observed = native.clock.check_next_once_v1();
        if observed.is_err() {
            native.first.get_or_insert(Failure::Clock);
        }
        let sample = observed?;
        let fields = native.comparison.fields();
        if fields.native_boot != sample.host_boot_id()
            || sample.boottime_nanoseconds() >= fields.native_cutoff
        {
            native.first.get_or_insert(Failure::Relation);
            native
                .lease_crossing
                .get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(sample)
    }

    fn body_native_v2(&self) -> Result<&Native, JournalError> {
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.reentry.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(native.body, Some(Ok(())))
            || native.first.is_some()
            || native.files.failure().is_some()
            || native.clock.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(native)
    }

    /// Completes the independent native post even after a failed capture/body.
    pub(crate) fn finish_posts_once_v2(&mut self) {
        if let Some(native) = &mut self.native {
            if native.captured.is_some() && native.posted.is_none() {
                native.posted = Some(native.files.recheck_once());
            }
        }
    }

    pub(crate) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if matches!(self.body_native_v2()?.posted, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
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
        stage: &RootExecutionNoApplyStageReceivingV2<'_, '_>,
    ) -> Result<(), Cause> {
        let sample = self.clock.check_next_once_v1().inspect_err(|_| {
            self.first.get_or_insert(Failure::Clock);
        })?;
        self.captured = Some(self.files.capture_once());
        if !matches!(self.captured, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Capture);
            return Err(JournalError::ProtectedBoundary.into());
        }
        // The exact 920-byte manifest has fixed inline decoded geometry,
        // already included in Native before this capture or parse occurs.
        self.manifest = Some((|| {
            let bytes = self.files.bytes().ok_or(JournalError::ProtectedBoundary)?;
            let manifest = BrokerSessionManifestV1::decode(bytes)?;
            manifest.require_all_active()?;
            if manifest.protocol() != BrokerSessionProtocolV1::Host
                || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
                || manifest.node_id() != stage.enrolled_node_v1()?
                || manifest.node_id() != self.comparison.fields().accepted_source.fields().node
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(manifest)
        })());
        if !matches!(self.manifest, Some(Ok(_))) {
            self.first.get_or_insert(Failure::Manifest);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.nonces[0] = Some(self.nonce_originals[0].observe_once());
        if !matches!(self.nonces[0], Some(Ok(_))) {
            self.first.get_or_insert(Failure::FirstNonce);
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.nonces[1] = Some(self.nonce_originals[1].observe_once());
        if !matches!(self.nonces[1], Some(Ok(_))) {
            self.first.get_or_insert(Failure::SecondNonce);
            return Err(JournalError::ProtectedBoundary.into());
        }
        let fields = self.comparison.fields();
        if self.read_nonce_v2()? == [0; 32]
            || fields.native_boot != sample.host_boot_id()
            || fields.observed_clock > sample.boottime_nanoseconds()
            || sample.boottime_nanoseconds() >= fields.native_cutoff
        {
            self.first.get_or_insert(Failure::Relation);
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn read_nonce_v2(&self) -> Result<[u8; 32], JournalError> {
        let mut nonce = [0; 32];
        for (index, result) in self.nonces.iter().enumerate() {
            nonce[index * 16..(index + 1) * 16].copy_from_slice(
                result
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?,
            );
        }
        Ok(nonce)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(Failure::Clock) => self.clock.failure(),
            Some(Failure::Capture) => self.files.capture_failure().map(|cause| cause as _),
            Some(Failure::Manifest) => self
                .manifest
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(Failure::FirstNonce) => self.nonce_originals[0].failure().or_else(|| {
                self.nonces[0]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            Some(Failure::SecondNonce) => self.nonce_originals[1].failure().or_else(|| {
                self.nonces[1]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            Some(Failure::Relation) => self
                .lease_crossing
                .as_ref()
                .map(|cause| cause as _)
                .or_else(|| {
                    self.body
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }),
            None => None,
        };
        selected
            .or_else(|| self.clock.failure())
            .or_else(|| self.files.capture_failure().map(|cause| cause as _))
            .or_else(|| {
                self.body
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.files.post_failure().map(|cause| cause as _))
    }
}
