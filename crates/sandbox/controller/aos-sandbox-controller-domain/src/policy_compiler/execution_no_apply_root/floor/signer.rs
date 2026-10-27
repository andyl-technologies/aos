//! Signs only genuine completed native78 or fresh cleanup-acquisition owners.
//!
//! The dedicated fixed secret remains in zeroizing native custody. This module
//! accepts no arbitrary signing callback, supplied key or decoded floor grant;
//! its closed signing entrances borrow actual completed native purpose loans.

use std::error::Error;
use std::fs::Metadata;
use std::path::Path;

use aos_sandbox_broker::systemd_credentials::RootNoApplySigningCredentialOriginalV2;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::host_execution_no_apply::{
    closed_controller::ClosedCreateFailurePrepareDataV2,
    root_attestation::{
        MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2, ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
        RootExecutionNoApplyAttestationFieldsV2, RootNoApplyPublicPinDataV2,
        encode_root_no_apply_attestation_signed_data_v2,
        encode_root_no_apply_attestation_unsigned_data_v2,
    },
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::journal::{
    CommitResult, Journal, JournalError, JournalTransaction,
    ProtectedJournalCurrentnessOriginalsV1, ProtectedJournalNamesV1,
    root_construction::RootJournalServingIdentityV1,
};
use crate::policy_compiler::{
    continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
    create_storage_current::pins::RootCurrentPinsStateV1,
    protected_owner::{POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT},
    provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
};

use super::{
    Floor, Head, RootExecutionNoApplyHostLeaseOriginalV2, RootExecutionNoApplyHostTrustOriginalV2,
    loan::Crossing,
};

type Cause = Box<dyn Error>;
type Witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>;

#[derive(Debug, thiserror::Error)]
#[error("dedicated Root NoApply signing key envelope is malformed")]
struct KeyEnvelopeError;

#[derive(Debug, thiserror::Error)]
#[error("dedicated Root NoApply signing key differs from its delivered public pin")]
struct KeyBindingError;

// Deliberately no Debug, clone, seed accessor or general signing method.
struct Key {
    signer: SigningKey,
    public: RootNoApplyPublicPinDataV2,
}

impl Key {
    // Pure credential DATA decoding. Only the real native credential capture
    // below supplies this to the genuine completed-floor signing programme.
    fn decode_canonical(bytes: &[u8]) -> Result<Self, Cause> {
        if bytes.len() != 80
            || bytes.get(..8) != Some(b"AOSRNK02")
            || Sha256::new()
                .chain_update(b"aos.sandbox.root.execution-no-apply-signing-key.v2\0")
                .chain_update(&bytes[..48])
                .finalize()
                .as_slice()
                != &bytes[48..]
        {
            return Err(KeyEnvelopeError.into());
        }
        let generation = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| KeyEnvelopeError)?);
        let seed =
            Zeroizing::new(<[u8; 32]>::try_from(&bytes[16..48]).map_err(|_| KeyEnvelopeError)?);
        let signer = SigningKey::from_bytes(&seed);
        if signer.verifying_key().is_weak() {
            return Err(KeyEnvelopeError.into());
        }
        let public =
            RootNoApplyPublicPinDataV2::new(generation, signer.verifying_key().to_bytes())?;
        Ok(Self { signer, public })
    }

    fn require_public_pin(&self, pin: RootNoApplyPublicPinDataV2) -> Result<(), KeyBindingError> {
        // Exact equality to the nonweak secret-derived key also rejects invalid
        // and weak point encodings. Generation is part of the pair.
        if self.public == pin {
            Ok(())
        } else {
            Err(KeyBindingError)
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Before,
    NamesBefore,
    ExternalTrust,
    Unsigned,
    Packet,
    Body,
    After,
    NamesAfter,
    Metadata,
    BeforeMetadata,
    FinalBinding,
    Reentry,
}

pub(in crate::policy_compiler::execution_no_apply_root) struct RootFloorSignerV2 {
    first: Option<First>,
    credential: RootNoApplySigningCredentialOriginalV2,
    capture: Option<Result<(), ()>>,
    key: Option<Result<Key, Cause>>,
    public_pin: Option<Result<RootNoApplyPublicPinDataV2, Cause>>,
    key_binding: Option<Result<(), KeyBindingError>>,
    before: Option<Result<(), ()>>,
    names: [ProtectedJournalCurrentnessOriginalsV1; 2],
    witnesses: [Witness; 2],
    observed_names: [Option<Result<ProtectedJournalNamesV1, JournalError>>; 2],
    unsigned: Option<Result<Vec<u8>, Cause>>,
    preimage: Vec<u8>,
    signature: Option<[u8; 64]>,
    packet: Option<Result<Vec<u8>, Cause>>,
    body: Option<Result<(), Cause>>,
    after: Option<Result<(), ()>>,
    metadata: Option<std::io::Result<Metadata>>,
    before_metadata: Option<std::io::Result<Metadata>>,
    final_binding: Option<Result<(), Cause>>,
    external_trust: bool,
    reentry: Option<JournalError>,
}

impl RootFloorSignerV2 {
    pub(in crate::policy_compiler::execution_no_apply_root) fn new() -> Self {
        Self {
            first: None,
            credential: RootNoApplySigningCredentialOriginalV2::new(),
            capture: None,
            key: None,
            public_pin: None,
            key_binding: None,
            before: None,
            names: std::array::from_fn(|_| Default::default()),
            witnesses: std::array::from_fn(|_| Default::default()),
            observed_names: std::array::from_fn(|_| None),
            unsigned: None,
            preimage: Vec::new(),
            signature: None,
            packet: None,
            body: None,
            after: None,
            metadata: None,
            before_metadata: None,
            final_binding: None,
            external_trust: false,
            reentry: None,
        }
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn receiving_demand_v2()
    -> Result<ResourceVector, JournalError> {
        let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
        )?;
        let witness = Witness::receiving_footprint_v1().ok_or(JournalError::JournalTooLarge)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| n.checked_add(witness.memory_bytes.checked_mul(2)?))
            .and_then(|n| n.checked_add(MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2.checked_mul(8)?))
            .and_then(|n| {
                n.checked_add(
                    ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2
                        .len()
                        .checked_mul(3)?,
                )
            })
            .and_then(|n| n.checked_add(std::mem::size_of::<Key>().checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<SigningPayloadV2>().checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<SigningProgrammeV2<'_, '_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2.len().checked_mul(3)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootNoApplySigningCredentialOriginalV2::receiving_demand_v2()
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(one)?
            .checked_add(one)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn prepare_once_v2(
        &mut self,
    ) -> Result<(), JournalError> {
        if self.capture.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.capture = Some(self.credential.capture_once_v2().map_err(|_| ()));
        if !matches!(self.capture, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.key = Some((|| {
            let bytes = self.credential.bytes_v2().ok_or(KeyEnvelopeError)?;
            Key::decode_canonical(bytes)
        })());
        // Decode both independently delivered originals before comparing them.
        // A failed key decode must not discard the public decoder's own result.
        self.public_pin = Some((|| {
            let bytes = self.credential.public_bytes_v2().ok_or(KeyEnvelopeError)?;
            RootNoApplyPublicPinDataV2::decode_canonical(bytes).map_err(Into::into)
        })());
        self.key_binding = Some((|| {
            let key = positive(&self.key).map_err(|_| KeyBindingError)?;
            let pin = positive(&self.public_pin).map_err(|_| KeyBindingError)?;
            key.require_public_pin(*pin)
        })());
        positive(&self.key_binding).map(|_| ())
    }

    pub(super) fn sign_once_v2(
        &mut self,
        loan: &CompletedFloorSigningLoanV2<'_>,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
    ) {
        self.sign_programme_once_v2(&mut SigningProgrammeV2::Floor { loan, trust });
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn sign_acquisition_once_v2(
        &mut self,
        loan: &super::super::acquisition::CompletedAcquisitionSigningLoanV2<'_>,
        clock: &mut crate::policy_compiler::provisioning_current::RootContinuationClockGateV1,
    ) {
        self.sign_programme_once_v2(&mut SigningProgrammeV2::Acquisition { loan, clock });
    }

    // Both closed purposes share the same actual native key/name/post engine.
    // The programme is a private finite union of genuine completed owners;
    // neither variant accepts an arbitrary byte signer or supplied credential.
    fn sign_programme_once_v2(&mut self, programme: &mut SigningProgrammeV2<'_, '_>) {
        if self.body.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.body = Some(self.sign_body_v2(programme));
        if matches!(self.body, Some(Err(_))) {
            self.first.get_or_insert(First::Body);
        }
        self.external_trust = programme.external_failure_v2();
        self.finish_posts_once_v2();
        let authority = programme.authority_v2();
        self.observed_names[1] =
            Some(authority.observe_held_physical_names_retaining_v1(
                &mut self.names[1],
                &mut self.witnesses[1],
            ));
        if !matches!(self.observed_names[1], Some(Ok(_))) {
            self.first.get_or_insert(First::NamesAfter);
        }
        self.metadata = Some(authority.held_native_receiving_metadata_v1().0);
        if !matches!(self.metadata, Some(Ok(_))) {
            self.first.get_or_insert(First::Metadata);
        }
        self.final_binding = Some((|| {
            if positive(&self.observed_names[0])? != positive(&self.observed_names[1])?
                || positive(&self.before_metadata)?.len() != positive(&self.metadata)?.len()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            programme.require_end_v2(positive(&self.metadata)?.len())?;
            programme.require_current_v2()?;
            let sample = programme.next_sample_v2()?;
            programme.require_live_at_v2(sample)?;
            Ok(())
        })());
        self.external_trust |= programme.external_failure_v2();
        if matches!(self.final_binding, Some(Err(_))) {
            self.first
                .get_or_insert(if programme.external_failure_v2() {
                    First::ExternalTrust
                } else {
                    First::FinalBinding
                });
        }
    }

    fn sign_body_v2(&mut self, programme: &mut SigningProgrammeV2<'_, '_>) -> Result<(), Cause> {
        positive(&self.key_binding)?;
        positive(&self.key)?;
        programme.require_current_v2()?;
        self.before = Some(self.credential.before_sign_once_v2().map_err(|_| ()));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        positive(&self.before)?;
        let authority = programme.authority_v2();
        self.observed_names[0] =
            Some(authority.observe_held_physical_names_retaining_v1(
                &mut self.names[0],
                &mut self.witnesses[0],
            ));
        if !matches!(self.observed_names[0], Some(Ok(_))) {
            self.first.get_or_insert(First::NamesBefore);
        }
        let names = *positive(&self.observed_names[0])?;
        self.before_metadata = Some(authority.held_native_receiving_metadata_v1().0);
        if !matches!(self.before_metadata, Some(Ok(_))) {
            self.first.get_or_insert(First::BeforeMetadata);
        }
        let end = positive(&self.before_metadata)?.len();
        programme.require_end_v2(end)?;
        let sample = programme.next_sample_v2().inspect_err(|_| {
            self.first.get_or_insert(First::ExternalTrust);
        })?;
        programme.require_live_at_v2(sample)?;
        let public = positive(&self.key)?.public;
        let payload = programme.payload_data_v2(public, names, end)?;
        self.unsigned = Some(payload.encode_unsigned_v2());
        if !matches!(self.unsigned, Some(Ok(_))) {
            self.first.get_or_insert(First::Unsigned);
        }
        self.preimage.extend_from_slice(payload.domain_v2());
        self.preimage.extend_from_slice(positive(&self.unsigned)?);
        self.signature = Some(positive(&self.key)?.signer.sign(&self.preimage).to_bytes());
        self.packet =
            Some(payload.encode_signed_v2(self.signature.ok_or(JournalError::ProtectedBoundary)?));
        if !matches!(self.packet, Some(Ok(_))) {
            self.first.get_or_insert(First::Packet);
        }
        positive(&self.packet)
            .map(|_| ())
            .map_err(|cause| cause.into())
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn finish_posts_once_v2(&mut self) {
        if self.capture.is_some() && self.after.is_none() {
            self.after = Some(self.credential.finish_posts_once_v2().map_err(|_| ()));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
        }
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn packet_bytes_v2(
        &self,
    ) -> Result<&[u8], JournalError> {
        if self.reentry.is_some()
            || self.failure().is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.final_binding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.credential
            .require_complete_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        positive(&self.packet).map(Vec::as_slice)
    }

    pub(super) fn prepare_failure(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.capture, Some(Err(()))) {
            return self.credential.failure().map(|cause| cause as _);
        }
        self.key
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause.as_ref())
            .or_else(|| {
                self.public_pin
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.key_binding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    pub(super) fn external_trust_failed(&self) -> bool {
        self.external_trust
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn external_trust_is_first_v2(
        &self,
    ) -> bool {
        matches!(self.first, Some(First::ExternalTrust))
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn failure(
        &self,
    ) -> Option<&(dyn Error + 'static)> {
        self.prepare_failure().or_else(|| match self.first {
            Some(First::Before | First::After) => self.credential.failure().map(|cause| cause as _),
            Some(First::NamesBefore) => self.names[0]
                .failure()
                .or_else(|| self.witnesses[0].failure())
                .or_else(|| {
                    self.observed_names[0]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            Some(First::ExternalTrust) => None,
            Some(First::Unsigned) => self
                .unsigned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(First::Packet) => self
                .packet
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(First::Body) => self
                .body
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(First::NamesAfter) => self.names[1]
                .failure()
                .or_else(|| self.witnesses[1].failure())
                .or_else(|| {
                    self.observed_names[1]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            Some(First::Metadata) => self
                .metadata
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            Some(First::BeforeMetadata) => self
                .before_metadata
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            Some(First::FinalBinding) => self
                .final_binding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Some(First::Reentry) => self.reentry.as_ref().map(|cause| cause as _),
            None => None,
        })
    }
}

enum SigningProgrammeV2<'loan, 'held> {
    Floor {
        loan: &'loan CompletedFloorSigningLoanV2<'held>,
        trust: &'loan mut RootExecutionNoApplyHostTrustOriginalV2,
    },
    Acquisition {
        loan: &'loan super::super::acquisition::CompletedAcquisitionSigningLoanV2<'held>,
        clock: &'loan mut crate::policy_compiler::provisioning_current::RootContinuationClockGateV1,
    },
}

enum SigningPayloadV2 {
    Floor(RootExecutionNoApplyAttestationFieldsV2),
    Acquisition(aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2),
}

impl SigningProgrammeV2<'_, '_> {
    fn authority_v2(&self) -> &Journal {
        match self {
            Self::Floor { loan, .. } => loan.authority,
            Self::Acquisition { loan, .. } => loan.authority_v2(),
        }
    }

    fn require_current_v2(&self) -> Result<(), JournalError> {
        match self {
            Self::Floor { loan, trust } => {
                trust.require_complete_v2()?;
                loan.require_current_v2()
            }
            Self::Acquisition { loan, .. } => loan.require_current_v2(),
        }
    }

    fn require_end_v2(&self, end: u64) -> Result<(), JournalError> {
        match self {
            Self::Floor { loan, .. } if loan.committed.durable_bytes != end => {
                Err(JournalError::ProtectedBoundary)
            }
            _ => Ok(()),
        }
    }

    fn next_sample_v2(&mut self) -> Result<aos_sandbox_model::RawPairedClockSample, JournalError> {
        match self {
            Self::Floor { trust, .. } => trust.next_sample_v2(),
            Self::Acquisition { clock, .. } => clock.check_next_once_v1(),
        }
    }

    fn require_live_at_v2(
        &self,
        sample: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        match self {
            Self::Floor { loan, .. } => loan.require_live_at_v2(sample),
            Self::Acquisition { loan, .. } => loan.require_current_at_v2(sample),
        }
    }

    fn external_failure_v2(&self) -> bool {
        match self {
            Self::Floor { trust, .. } => trust.failure().is_some(),
            Self::Acquisition { clock, .. } => clock.failure().is_some(),
        }
    }

    fn payload_data_v2(
        &self,
        public: RootNoApplyPublicPinDataV2,
        names: ProtectedJournalNamesV1,
        end: u64,
    ) -> Result<SigningPayloadV2, Cause> {
        Ok(match self {
            Self::Floor { loan, trust } => {
                SigningPayloadV2::Floor(RootExecutionNoApplyAttestationFieldsV2 {
                    generation: public.generation_v2(),
                    key_commitment: public.key_commitment_v2(),
                    authority_names: names,
                    authority_next: loan.authority.snapshot_sequence(),
                    authority_end: end,
                    root_read_nonce: trust.read_nonce_data_v2()?,
                    floor: loan.floor,
                    head: Head::from_floor_data_v2(loan.floor),
                    prepare: ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(loan.floor)?,
                })
            }
            Self::Acquisition { loan, .. } => {
                SigningPayloadV2::Acquisition(loan.fields_data_v2(names, end, public)?)
            }
        })
    }
}

impl SigningPayloadV2 {
    fn domain_v2(&self) -> &'static [u8] {
        match self {
            Self::Floor(_) => ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
            Self::Acquisition(_) => aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
        }
    }

    fn encode_unsigned_v2(&self) -> Result<Vec<u8>, Cause> {
        match self {
            Self::Floor(data) => Ok(encode_root_no_apply_attestation_unsigned_data_v2(*data)?),
            Self::Acquisition(data) => Ok(aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::encode_root_no_apply_recovery_acquisition_unsigned_data_v2(*data)?),
        }
    }

    fn encode_signed_v2(&self, signature: [u8; 64]) -> Result<Vec<u8>, Cause> {
        match self {
            Self::Floor(data) => Ok(encode_root_no_apply_attestation_signed_data_v2(*data, signature)?),
            Self::Acquisition(data) => Ok(aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::encode_root_no_apply_recovery_acquisition_signed_data_v2(*data, signature)?),
        }
    }
}

/// Borrows actual completed append/readback/posts, never a decoded floor alone.
pub(super) struct CompletedFloorSigningLoanV2<'held> {
    pub(super) authority: &'held Journal,
    pub(super) policy: &'held Journal,
    pub(super) pins: &'held RootCurrentPinsStateV1,
    pub(super) interval: &'held RootExecutionNoApplyPolicyOriginalV2,
    pub(super) readonly: &'held RootCreateFinalityReadonlyOriginalV1,
    pub(super) host: &'held RootExecutionNoApplyHostLeaseOriginalV2,
    pub(super) before: &'held [RootJournalServingIdentityV1; 2],
    pub(super) after: &'held [RootJournalServingIdentityV1; 2],
    pub(super) transaction: &'held JournalTransaction,
    pub(super) committed: &'held CommitResult,
    pub(super) floor: Floor,
    pub(super) crossing: &'held Crossing,
}

impl CompletedFloorSigningLoanV2<'_> {
    fn require_live_at_v2(
        &self,
        sample: aos_sandbox_model::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        let sources = self
            .interval
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= sources.0.head().expires_at().min(sources.1.expires_at()) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_current_v2(&self) -> Result<(), JournalError> {
        self.crossing.require_complete()?;
        super::require_readback_data_v2(
            self.authority,
            self.transaction,
            self.floor,
            self.committed,
        )?;
        self.authority
            .require_root_serving_identity_v1(&self.after[0])?;
        self.policy
            .require_root_serving_identity_v1(&self.before[1])?;
        self.policy
            .require_root_serving_identity_v1(&self.after[1])?;
        self.pins
            .require_serving_policy_v1(self.policy)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.interval
            .require_complete_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if self.interval.verified_v1().is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.readonly.require_complete_v1()?;
        if self
            .readonly
            .execution_no_apply_current_data_v2()?
            .global_controller_cut_data_v2()?
            != self.floor.fields().controller_cut
            || self.host.lease_data_v2()? != self.floor.fields().host_lease
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2;
    use ed25519_dalek::{Signature, VerifyingKey};

    fn envelope(generation: u64) -> Zeroizing<[u8; 80]> {
        let mut bytes = Zeroizing::new([0; 80]);
        bytes[..8].copy_from_slice(b"AOSRNK02");
        bytes[8..16].copy_from_slice(&generation.to_be_bytes());
        let mut filled = 16;
        while filled < 48 {
            let count = rustix::rand::getrandom(
                &mut bytes[filled..48],
                rustix::rand::GetRandomFlags::empty(),
            )
            .unwrap();
            assert_ne!(count, 0);
            filled += count;
        }
        seal(&mut bytes);
        bytes
    }

    fn seal(bytes: &mut [u8; 80]) {
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.root.execution-no-apply-signing-key.v2\0")
            .chain_update(&bytes[..48])
            .finalize();
        bytes[48..].copy_from_slice(&checksum);
    }

    #[test]
    fn secret_envelope_rejects_noncanonical_extent_and_generation() {
        let bytes = envelope(9);
        let key = Key::decode_canonical(&bytes[..]).unwrap();
        assert_eq!(key.public.generation_v2(), 9);
        let encoded = key.public.encode_canonical();
        assert_eq!(
            RootNoApplyPublicPinDataV2::decode_canonical(&encoded).unwrap(),
            key.public
        );
        assert!(Key::decode_canonical(&bytes[..79]).is_err());
        let mut trailing = Zeroizing::new(bytes.to_vec());
        trailing.push(0);
        assert!(Key::decode_canonical(&trailing).is_err());
        let mut changed = Zeroizing::new(*bytes);
        changed[20] ^= 1;
        assert!(Key::decode_canonical(&changed[..]).is_err());
        changed[..8].copy_from_slice(b"AOSRNP02");
        seal(&mut changed);
        assert!(Key::decode_canonical(&changed[..]).is_err());
        assert!(Key::decode_canonical(&envelope(0)[..]).is_err());
    }

    #[test]
    fn secret_and_delivered_public_pin_must_match_key_and_generation() {
        let key = Key::decode_canonical(&envelope(11)[..]).unwrap();
        let public =
            RootNoApplyPublicPinDataV2::decode_canonical(&key.public.encode_canonical()).unwrap();
        assert!(key.require_public_pin(public).is_ok());

        for generation in [1, 12, u64::MAX] {
            let changed =
                RootNoApplyPublicPinDataV2::new(generation, public.public_key_v2()).unwrap();
            assert!(key.require_public_pin(changed).is_err());
        }

        let other = Key::decode_canonical(&envelope(11)[..]).unwrap();
        assert!(key.require_public_pin(other.public).is_err());
        for bytes in [[0; 32], [0xff; 32]] {
            let changed = RootNoApplyPublicPinDataV2::new(11, bytes).unwrap();
            assert!(key.require_public_pin(changed).is_err());
        }
    }

    #[test]
    fn refused_pair_keeps_both_decode_causes_and_closes_packet() {
        let mut signer = RootFloorSignerV2::new();
        signer.key = Some(Err(KeyEnvelopeError.into()));
        signer.public_pin = Some(Err(RootNoApplyPublicPinDataV2::decode_canonical(
            b"foreign framing",
        )
        .unwrap_err()
        .into()));
        signer.key_binding = Some(Err(KeyBindingError));

        assert!(signer.prepare_failure().unwrap().is::<KeyEnvelopeError>());
        assert!(signer.public_pin.as_ref().unwrap().as_ref().unwrap_err().is::<
            aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootNoApplyAttestationDataErrorV2,
        >());
        assert!(signer.packet_bytes_v2().is_err());
        assert!(signer.key_binding.as_ref().unwrap().is_err());
    }

    #[test]
    fn credential_key_rejects_foreign_signature_and_domain() {
        let bytes = envelope(11);
        let key = Key::decode_canonical(&bytes[..]).unwrap();
        let public =
            RootNoApplyPublicPinDataV2::decode_canonical(&key.public.encode_canonical()).unwrap();
        let verifying = VerifyingKey::from_bytes(&public.public_key_v2()).unwrap();
        let unsigned = b"passive canonical fixture body; no floor authority";
        let mut preimage = ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2.to_vec();
        preimage.extend_from_slice(unsigned);
        let signature = key.signer.sign(&preimage);
        assert!(verifying.verify_strict(&preimage, &signature).is_ok());

        let other = Key::decode_canonical(&envelope(11)[..]).unwrap();
        let foreign = VerifyingKey::from_bytes(&other.public.public_key_v2()).unwrap();
        assert!(foreign.verify_strict(&preimage, &signature).is_err());
        let changed_generation =
            RootNoApplyPublicPinDataV2::new(12, public.public_key_v2()).unwrap();
        assert_ne!(
            changed_generation.key_commitment_v2(),
            public.key_commitment_v2()
        );
        let mut wrong_domain = ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2.to_vec();
        wrong_domain.extend_from_slice(unsigned);
        assert!(verifying.verify_strict(&wrong_domain, &signature).is_err());
        let mut bad = signature.to_bytes();
        bad[0] ^= 1;
        assert!(
            verifying
                .verify_strict(&preimage, &Signature::from_bytes(&bad))
                .is_err()
        );
        let mut corrupted_pin = public.encode_canonical();
        corrupted_pin[79] ^= 1;
        assert!(RootNoApplyPublicPinDataV2::decode_canonical(&corrupted_pin).is_err());

        let mut zero_generation = public.encode_canonical();
        zero_generation[8..16].fill(0);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.root.execution-no-apply-public-pin.v2\0")
            .chain_update(&zero_generation[..48])
            .finalize();
        zero_generation[48..].copy_from_slice(&checksum);
        assert!(RootNoApplyPublicPinDataV2::decode_canonical(&zero_generation).is_err());
    }
}
