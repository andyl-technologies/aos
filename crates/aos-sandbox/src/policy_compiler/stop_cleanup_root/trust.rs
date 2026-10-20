//! Retains Stop's existing fixed public Host, ownership and general-plan inputs.
//!
//! The closed native issuer pays the complete fixed raw and bounded typed
//! capture programme before constructing this owner or invoking `decode_once`.
//! Every reached credential owes its independent original named readback even
//! after an earlier capture, model, policy, clock or financial refusal.

use std::{error::Error, mem::size_of};

use aos_sandbox_broker::systemd_credentials::{
    RootCurrentBrokerPlanCredentialCustodyV1, RootCurrentHostManifestCustodyV2,
    RootCurrentOwnershipCredentialCustodyV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1,
    manifest::{BrokerSessionManifestAudienceV1, BrokerSessionManifestV1},
};
use aos_sandbox_core::{DecodeLimits, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::trusted_policy::{
    OwnershipTrustConfigurationCaptureV1, OwnershipTrustConfigurationClosedV1,
    verifier_from_protected_policy_retaining_v1,
};

use crate::{
    journal::JournalError,
    policy_compiler::{
        create_storage_current::controller_readonly::public_trust::RootBrokerPlanPublicTrustDataV1,
        provisioning_current::RootContinuationClockGateV1,
    },
};

type Cause = Box<dyn Error>;

pub(super) struct Trust {
    ownership_files: RootCurrentOwnershipCredentialCustodyV1,
    broker_files: RootCurrentBrokerPlanCredentialCustodyV1,
    host_files: RootCurrentHostManifestCustodyV2,
    captures: [Option<Result<(), ()>>; 3],
    posts: [Option<Result<(), ()>>; 3],
    ownership: OwnershipTrustConfigurationCaptureV1,
    ownership_result: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    broker: Option<Result<RootBrokerPlanPublicTrustDataV1, Cause>>,
    manifest: Option<Result<BrokerSessionManifestV1, Cause>>,
    body: Option<Result<(), Cause>>,
    first_capture: Option<usize>,
    repeated: Option<JournalError>,
    entered: bool,
}

impl Trust {
    pub(super) fn new() -> Self {
        Self {
            ownership_files: RootCurrentOwnershipCredentialCustodyV1::new(),
            broker_files: RootCurrentBrokerPlanCredentialCustodyV1::new(),
            host_files: RootCurrentHostManifestCustodyV2::new(),
            captures: [None; 3],
            posts: [None; 3],
            ownership: OwnershipTrustConfigurationCaptureV1::new(),
            ownership_result: None,
            broker: None,
            manifest: None,
            body: None,
            first_capture: None,
            repeated: None,
            entered: false,
        }
    }

    pub(super) fn fixed_demand() -> Result<ResourceVector, JournalError> {
        let ownership =
            aos_sandbox_broker::systemd_credentials::ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1;
        let broker = aos_sandbox_protocol::authorization_artifact::SigningAuthority::maximum_canonical_policy_bytes_v1();
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(ownership)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    RootBrokerPlanPublicTrustDataV1::receiving_policy_width_bytes_v2(broker)?,
                )
            })
            // The 920-byte Host manifest has fixed inline decoded geometry.
            .and_then(|bytes| bytes.checked_add(3 * size_of::<BrokerSessionManifestV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootCurrentOwnershipCredentialCustodyV1::dominant_demand()
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(
                RootCurrentBrokerPlanCredentialCustodyV1::dominant_demand()
                    .ok_or(JournalError::JournalTooLarge)?,
            )?
            .checked_add(
                RootCurrentHostManifestCustodyV2::dominant_demand()
                    .ok_or(JournalError::JournalTooLarge)?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn capture_once(
        &mut self,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        if self.entered || self.repeated.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        for index in 0..3 {
            clock.check_next_once_v1()?;
            self.captures[index] = Some(match index {
                0 => self.ownership_files.capture_once(),
                1 => self.broker_files.capture_once(),
                _ => self.host_files.capture_once(),
            });
            if !matches!(self.captures[index], Some(Ok(()))) {
                self.first_capture = Some(index);
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    pub(super) fn decode_once(&mut self, node: [u8; 16]) -> Result<(), JournalError> {
        if self.body.is_some() || self.ownership_result.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.body = Some((|| {
            let (policy, public) = self
                .ownership_files
                .bytes()
                .ok_or(JournalError::ProtectedBoundary)?;
            let public: [u8; 32] = public.try_into()?;
            self.ownership_result = Some(verifier_from_protected_policy_retaining_v1(
                policy.to_vec(),
                public,
                DecodeLimits::default(),
                &mut self.ownership,
            ));
            if !matches!(self.ownership_result, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.broker = Some(RootBrokerPlanPublicTrustDataV1::from_fixed_public_data_v1(
                self.broker_files
                    .bytes()
                    .ok_or(JournalError::ProtectedBoundary)?,
            ));
            positive(&self.broker)?;
            self.manifest = Some((|| {
                let value = BrokerSessionManifestV1::decode(
                    self.host_files
                        .bytes()
                        .ok_or(JournalError::ProtectedBoundary)?,
                )?;
                value.require_all_active()?;
                if value.protocol() != BrokerSessionProtocolV1::Host
                    || value.audience() != BrokerSessionManifestAudienceV1::NodeController
                    || value.node_id() != node
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                Ok(value)
            })());
            positive(&self.manifest)?;
            Ok(())
        })());
        self.require_typed()
    }

    pub(super) fn require_typed(&self) -> Result<(), JournalError> {
        if matches!(self.body, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn manifest(&self) -> Result<&BrokerSessionManifestV1, JournalError> {
        self.require_typed()?;
        positive(&self.manifest)
    }

    pub(super) fn broker(&self) -> Result<&RootBrokerPlanPublicTrustDataV1, JournalError> {
        self.require_typed()?;
        positive(&self.broker)
    }

    pub(super) fn ownership(
        &self,
    ) -> Result<&aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier, JournalError> {
        self.require_typed()?;
        self.ownership
            .verifier()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn finish_posts(&mut self) {
        for index in 0..3 {
            if self.captures[index].is_some() && self.posts[index].is_none() {
                self.posts[index] = Some(match index {
                    0 => self.ownership_files.recheck_once(),
                    1 => self.broker_files.recheck_once(),
                    _ => self.host_files.recheck_once(),
                });
            }
        }
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        self.require_typed()?;
        if self.posts.iter().all(|post| matches!(post, Some(Ok(())))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let capture: Option<&(dyn Error + 'static)> = match self.first_capture {
            Some(0) => self
                .ownership_files
                .capture_failure()
                .map(|cause| cause as _),
            Some(1) => self.broker_files.capture_failure().map(|cause| cause as _),
            Some(_) => self.host_files.capture_failure().map(|cause| cause as _),
            None => None,
        };
        capture
            .or_else(|| self.ownership.failure())
            .or_else(|| {
                self.broker
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.manifest
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.body
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.ownership_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.broker_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.host_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
