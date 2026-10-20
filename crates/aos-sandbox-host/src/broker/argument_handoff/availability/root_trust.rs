//! Verifies Root floor attestations beside Host's same held no-Apply programme.
//!
//! The fixed public pin uses Broker's protected credential engine. Signature
//! and full owned43/42 comparisons supply DATA validation only; the parent
//! keeps the genuine paid19 writers and Root78 barrier through CAS and ACK.

use std::collections::TryReserveError;
use std::error::Error;

use aos_sandbox_broker::systemd_credentials::{
    HostNoApplyRootPublicCredentialClosedV2, HostNoApplyRootPublicCredentialOriginalV2,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::{
    MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2, ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    closed_controller::{CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, ClosedCreateFailurePrepareDataV2},
    current_lease::CurrentHostNoApplyLeaseDataV2,
    recovery_acquisition::{
        MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2,
        ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
        RootNoApplyRecoveryAcquisitionDataErrorV2, RootNoApplyRecoveryAcquisitionDataV2,
        RootNoApplyRecoveryAcquisitionFieldsV2,
    },
    root_attestation::{
        MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2, ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
        RootExecutionNoApplyAttestationDataV2, RootNoApplyAttestationDataErrorV2,
        RootNoApplyPublicPinDataV2,
    },
};
use ed25519_dalek::{Signature, SignatureError, VerifyingKey};

/// Reports refusal while all reached native and cryptographic causes stay held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Host Root no-Apply trust comparison remains closed")]
pub(super) struct HostNoApplyRootTrustClosedV2;

#[derive(Clone, Copy)]
enum First {
    Pin,
    PinData,
    Key,
    WeakKey,
    Artifact,
    Acquisition,
    Signature(SignaturePurpose),
    Association,
    Order,
}

#[derive(Clone, Copy)]
enum SignaturePurpose {
    Acquisition,
    Floor,
}

impl SignaturePurpose {
    const fn index(self) -> usize {
        match self {
            Self::Acquisition => 0,
            Self::Floor => 1,
        }
    }
}

/// Borrows the native recipient coordinates of the actual current-control turn.
pub(super) struct HostNoApplyRecoveryRecipientV2 {
    pub node: [u8; 16],
    pub boot: [u8; 16],
    pub session: [u8; 32],
    pub request: [u8; 16],
    pub deadline: u64,
    pub clock: RawPairedClockSample,
}

struct RootSignatureAttemptV2 {
    allocation: Option<Result<(), TryReserveError>>,
    preimage: Vec<u8>,
    signature: Option<Result<(), SignatureError>>,
    entered: bool,
}

impl RootSignatureAttemptV2 {
    fn new() -> Self {
        Self {
            allocation: None,
            preimage: Vec::new(),
            signature: None,
            entered: false,
        }
    }

    fn verify_once(
        &mut self,
        key: &VerifyingKey,
        domain: &[u8],
        unsigned: &[u8],
        signature: [u8; 64],
    ) -> Result<(), HostNoApplyRootTrustClosedV2> {
        if self.entered {
            return Err(HostNoApplyRootTrustClosedV2);
        }
        self.entered = true;
        let length = domain
            .len()
            .checked_add(unsigned.len())
            .ok_or(HostNoApplyRootTrustClosedV2)?;
        self.allocation = Some(self.preimage.try_reserve_exact(length));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(HostNoApplyRootTrustClosedV2);
        }
        self.preimage.extend_from_slice(domain);
        self.preimage.extend_from_slice(unsigned);
        self.signature =
            Some(key.verify_strict(&self.preimage, &Signature::from_bytes(&signature)));
        if !matches!(self.signature, Some(Ok(()))) {
            return Err(HostNoApplyRootTrustClosedV2);
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.allocation
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.signature
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

#[derive(Clone, Copy)]
enum PinPost {
    PreliminaryBefore,
    PreliminaryAfter,
    NonceBefore,
    NonceAfter,
    FloorBefore,
    FloorAfter,
    AckBefore,
    AckAfter,
}

/// Retains the pin and distinct acquisition and floor verification attempts.
pub(super) struct HostNoApplyRootTrustOriginalV2 {
    pin: HostNoApplyRootPublicCredentialOriginalV2,
    pin_data: Option<Result<RootNoApplyPublicPinDataV2, RootNoApplyAttestationDataErrorV2>>,
    key: Option<Result<VerifyingKey, SignatureError>>,
    artifact: Option<Result<(), RootNoApplyAttestationDataErrorV2>>,
    acquisition: Option<Result<(), RootNoApplyRecoveryAcquisitionDataErrorV2>>,
    acquired: Option<RootNoApplyRecoveryAcquisitionFieldsV2>,
    signatures: [RootSignatureAttemptV2; 2],
    compared: Option<Result<(), HostNoApplyRootTrustClosedV2>>,
    entered: bool,
    verified: bool,
    first: Option<First>,
}

impl HostNoApplyRootTrustOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            pin: HostNoApplyRootPublicCredentialOriginalV2::new(),
            pin_data: None,
            key: None,
            artifact: None,
            acquisition: None,
            acquired: None,
            signatures: std::array::from_fn(|_| RootSignatureAttemptV2::new()),
            compared: None,
            entered: false,
            verified: false,
            first: None,
        }
    }

    // The actual initial19 borrower admits this complete finite recipe before
    // construction. Literal canonical floor/prepare/head scratch is sequential;
    // its overlaps and the retained signature preimage are separately covered.
    pub(super) fn receiving_demand_v2() -> Option<ResourceVector> {
        let preimage = ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2
            .len()
            .checked_add(MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2)?
            .checked_add(ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2.len())?
            .checked_add(MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2)?;
        let models = std::mem::size_of::<RootExecutionNoApplyAttestationDataV2<'static>>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<RootNoApplyRecoveryAcquisitionDataV2<'static>>().checked_mul(3)?)?
            .checked_add(MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2.checked_mul(3)?)?
            .checked_add(CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2.checked_mul(3)?)?
            .checked_add(ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2.checked_mul(3)?)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(preimage.checked_mul(3)?)?
            .checked_add(models)?
            .checked_add(std::mem::size_of::<VerifyingKey>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Signature>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(4)?)?;
        HostNoApplyRootPublicCredentialOriginalV2::receiving_demand_v2()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
            .ok()
    }

    pub(super) fn observe_before_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        if self.pin_data.is_some() || self.first.is_some() {
            return self.refuse(First::Order);
        }
        if self.pin.capture_once_v2().is_err() {
            return self.refuse(First::Pin);
        }
        let bytes = self.pin.bytes_v2().ok_or(HostNoApplyRootTrustClosedV2)?;
        self.pin_data = Some(RootNoApplyPublicPinDataV2::decode_canonical(bytes));
        let Some(Ok(pin)) = self.pin_data else {
            return self.refuse(First::PinData);
        };
        self.key = Some(VerifyingKey::from_bytes(&pin.public_key_v2()));
        let Some(Ok(key)) = self.key.as_ref() else {
            return self.refuse(First::Key);
        };
        if key.is_weak() {
            return self.refuse(First::WeakKey);
        }
        Ok(())
    }

    pub(super) fn preliminary_before_once_v2(
        &mut self,
    ) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::PreliminaryBefore)
    }

    /// Verifies the distinct paid cleanup-read authorization before writer entry.
    ///
    /// Every recipient coordinate comes from the actual current-control turn.
    /// This attempt neither consumes the later floor-signature destination nor
    /// supplies Apply, Seal, CAS or replacement-owner authority.
    pub(super) fn verify_acquisition_once_v2(
        &mut self,
        bytes: &[u8],
        recipient: HostNoApplyRecoveryRecipientV2,
    ) -> Result<RootNoApplyRecoveryAcquisitionFieldsV2, HostNoApplyRootTrustClosedV2> {
        if self.acquisition.is_some()
            || self.entered
            || self.first.is_some()
            || self.pin.bytes_v2().is_none()
        {
            return self.refuse(First::Order);
        }
        let parsed = match RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(bytes) {
            Ok(parsed) => {
                self.acquisition = Some(Ok(()));
                parsed
            }
            Err(cause) => {
                self.acquisition = Some(Err(cause));
                return self.refuse(First::Acquisition);
            }
        };
        let Some(Ok(pin)) = self.pin_data else {
            return self.refuse(First::PinData);
        };
        let Some(Ok(key)) = self.key.as_ref() else {
            return self.refuse(First::Key);
        };
        let fields = parsed.fields_v2();
        if fields.generation != pin.generation_v2()
            || fields.key_commitment != pin.key_commitment_v2()
        {
            return self.refuse(First::Association);
        }
        if self.signatures[SignaturePurpose::Acquisition.index()]
            .verify_once(
                key,
                ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
                parsed.unsigned_bytes_v2(),
                parsed.signature_bytes_v2(),
            )
            .is_err()
        {
            return self.refuse(First::Signature(SignaturePurpose::Acquisition));
        }
        if fields.host_node != recipient.node
            || fields.host_boot != recipient.boot
            || fields.host_session != recipient.session
            || fields.controller_nonce[..16] != recipient.request
            || recipient.clock.host_boot_id() != recipient.boot
            || recipient.clock.boottime_nanoseconds() < fields.first_clock
            || recipient.clock.boottime_nanoseconds() >= recipient.deadline
            || recipient.deadline > fields.cutoff
            || recipient.clock.wall_seconds() >= fields.policy_expires_at
        {
            return self.refuse(First::Association);
        }
        self.acquired = Some(fields);
        Ok(fields)
    }

    pub(super) fn preliminary_after_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::PreliminaryAfter)
    }

    pub(super) fn nonce_before_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::NonceBefore)
    }

    pub(super) fn nonce_after_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::NonceAfter)
    }

    pub(super) fn floor_before_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::FloorBefore)
    }

    pub(super) fn floor_after_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::FloorAfter)
    }

    pub(super) fn ack_before_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::AckBefore)
    }

    pub(super) fn ack_after_once_v2(&mut self) -> Result<(), HostNoApplyRootTrustClosedV2> {
        self.pin_post(PinPost::AckAfter)
    }

    fn pin_post(&mut self, post: PinPost) -> Result<(), HostNoApplyRootTrustClosedV2> {
        let owed = matches!(
            post,
            PinPost::PreliminaryAfter
                | PinPost::NonceAfter
                | PinPost::FloorAfter
                | PinPost::AckAfter
        );
        if !owed && self.first.is_some() {
            return Err(HostNoApplyRootTrustClosedV2);
        }
        let result: Result<(), HostNoApplyRootPublicCredentialClosedV2> = match post {
            PinPost::PreliminaryBefore => self.pin.preliminary_before_once_v2(),
            PinPost::PreliminaryAfter => self.pin.preliminary_after_once_v2(),
            PinPost::NonceBefore => self.pin.nonce_before_once_v2(),
            PinPost::NonceAfter => self.pin.nonce_after_once_v2(),
            PinPost::FloorBefore => self.pin.floor_before_once_v2(),
            PinPost::FloorAfter => self.pin.floor_after_once_v2(),
            PinPost::AckBefore => self.pin.ack_before_once_v2(),
            PinPost::AckAfter => self.pin.ack_after_once_v2(),
        };
        if result.is_err() {
            self.first.get_or_insert(First::Pin);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(HostNoApplyRootTrustClosedV2)
        }
    }

    /// Strictly compares the artifact to the parent's actual held42/43 originals.
    ///
    /// No expected Root instance or native Root cut is supplied by Controller
    /// DATA. The dedicated signature authenticates those internally joined
    /// fields. Full equality with the actual owned current lease binds node,
    /// assignment, accepted Create/execution,39H/T, Host cuts and current43.
    /// The caller retains the literal authenticated42 input through all posts.
    ///
    /// # Errors
    /// Retains malformed canonical bytes, changed generation/key, invalid or
    /// weak key, allocation/signature failure, stale challenge/43/prepare or
    /// repeated entry. Success is comparison only, never a floor capability.
    pub(super) fn verify_once_v2(
        &mut self,
        bytes: &[u8],
        challenge: [u8; 32],
        current: CurrentHostNoApplyLeaseDataV2,
        signed43: [u8; 32],
        root_nonce: [u8; 32],
        prepare: ClosedCreateFailurePrepareDataV2,
    ) -> Result<(), HostNoApplyRootTrustClosedV2> {
        if self.entered || self.first.is_some() || self.pin.bytes_v2().is_none() {
            return self.refuse(First::Order);
        }
        self.entered = true;
        let parsed = match RootExecutionNoApplyAttestationDataV2::decode_canonical(bytes) {
            Ok(parsed) => {
                self.artifact = Some(Ok(()));
                parsed
            }
            Err(cause) => {
                self.artifact = Some(Err(cause));
                return self.refuse(First::Artifact);
            }
        };
        let Some(Ok(pin)) = self.pin_data else {
            return self.refuse(First::PinData);
        };
        let Some(Ok(key)) = self.key.as_ref() else {
            return self.refuse(First::Key);
        };
        if parsed.generation_v2() != pin.generation_v2()
            || parsed.key_commitment_v2() != pin.key_commitment_v2()
        {
            return self.refuse(First::Association);
        }
        if self.signatures[SignaturePurpose::Floor.index()]
            .verify_once(
                key,
                ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
                parsed.unsigned_bytes_v2(),
                parsed.signature_bytes_v2(),
            )
            .is_err()
        {
            return self.refuse(First::Signature(SignaturePurpose::Floor));
        }
        let floor = parsed.floor_data_v2().fields();
        if let Some(acquired) = self.acquired {
            let history_matches = match acquired.history {
                None => floor.revision == 1 && floor.predecessor_floor == [0; 32],
                Some(history) => {
                    history.current_revision.checked_add(1) == Some(floor.revision)
                        && floor.predecessor_floor == history.current_floor
                        && prepare.identity == history.prepare.identity
                        && prepare.wall_seconds == history.prepare.wall_seconds
                        && prepare.predecessor == history.prepare.predecessor
                        && prepare.successor == history.prepare.successor
                }
            };
            if !history_matches
                || acquired
                    .root_instance
                    .is_some_and(|instance| instance != floor.root_instance)
                || acquired.authority_names != parsed.authority_names_v2()
                || acquired.authority_next != floor.authority_next
                || acquired.policy_commitment != floor.policy_commitment
                || acquired.controller_cut != floor.controller_cut
            {
                return self.refuse(First::Association);
            }
        }
        self.compared = Some(
            if challenge != [0; 32]
                && signed43 != [0; 32]
                && root_nonce != [0; 32]
                && current.fields().challenge == challenge
                && floor.host_lease == current
                && floor.signed_current_outcome == signed43
                && parsed.root_read_nonce_v2() == root_nonce
                && parsed.prepare_data_v2() == prepare
            {
                Ok(())
            } else {
                Err(HostNoApplyRootTrustClosedV2)
            },
        );
        if !matches!(self.compared, Some(Ok(()))) {
            return self.refuse(First::Association);
        }
        self.verified = true;
        Ok(())
    }

    fn refuse<T>(&mut self, cause: First) -> Result<T, HostNoApplyRootTrustClosedV2> {
        self.first.get_or_insert(cause);
        Err(HostNoApplyRootTrustClosedV2)
    }

    pub(super) fn completed_comparison_v2(&self) -> bool {
        self.verified && self.first.is_none() && self.pin.bytes_v2().is_some()
    }

    pub(super) fn completed_acquisition_v2(
        &self,
    ) -> Option<RootNoApplyRecoveryAcquisitionFieldsV2> {
        self.first.is_none().then_some(self.acquired).flatten()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Pin => self.pin.failure(),
            First::PinData => self
                .pin_data
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Key => self.key.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Artifact => self
                .artifact
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Acquisition => self.acquisition.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Signature(purpose) => self.signatures[purpose.index()].failure(),
            First::WeakKey | First::Association | First::Order => None,
        };
        cause.or(Some(&HostNoApplyRootTrustClosedV2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn sign(key: &SigningKey, domain: &[u8], unsigned: &[u8]) -> [u8; 64] {
        let mut bytes = domain.to_vec();
        bytes.extend_from_slice(unsigned);
        key.sign(&bytes).to_bytes()
    }

    #[test]
    fn acquisition_and_floor_keep_independent_once_only_signature_destinations() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let key = signer.verifying_key();
        let unsigned = b"retained exact Root comparison";
        let mut attempts = std::array::from_fn::<_, 2, _>(|_| RootSignatureAttemptV2::new());

        for (purpose, domain) in [
            (
                SignaturePurpose::Acquisition,
                ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
            ),
            (
                SignaturePurpose::Floor,
                ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
            ),
        ] {
            attempts[purpose.index()]
                .verify_once(&key, domain, unsigned, sign(&signer, domain, unsigned))
                .unwrap();
            assert!(
                attempts[purpose.index()]
                    .verify_once(&key, domain, unsigned, sign(&signer, domain, unsigned))
                    .is_err()
            );
        }

        assert_ne!(attempts[0].preimage, attempts[1].preimage);
        assert!(
            attempts
                .iter()
                .all(|attempt| matches!(attempt.signature, Some(Ok(()))))
        );
    }

    #[test]
    fn wrong_domain_retains_exact_first_signature_error_and_preimage() {
        let signer = SigningKey::from_bytes(&[8; 32]);
        let key = signer.verifying_key();
        let unsigned = b"exact signed acquisition";
        let signature = sign(
            &signer,
            ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
            unsigned,
        );
        let mut attempt = RootSignatureAttemptV2::new();

        assert!(
            attempt
                .verify_once(
                    &key,
                    ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2,
                    unsigned,
                    signature
                )
                .is_err()
        );
        let first = attempt.failure().unwrap() as *const dyn Error;
        let retained = attempt.preimage.clone();
        assert!(
            attempt
                .verify_once(
                    &key,
                    ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2,
                    unsigned,
                    signature
                )
                .is_err()
        );

        assert!(std::ptr::eq(first, attempt.failure().unwrap()));
        assert_eq!(attempt.preimage, retained);
        assert!(
            attempt
                .failure()
                .unwrap()
                .downcast_ref::<SignatureError>()
                .is_some()
        );
    }
}
