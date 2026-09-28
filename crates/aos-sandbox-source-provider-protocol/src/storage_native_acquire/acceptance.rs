//! Stable Storage acceptance, dedicated-role signatures, and one-FD reply.
//!
//! `AOSZNA03` is the 216-byte unsigned acceptance described by the parent
//! module. Its signed form appends the existing 88-byte AOSZHSG1 signer and
//! a 64-byte signature. Neither form contains its own issuance-journal head.
//! The final 80-byte topology claim uses the existing canonical proof codec.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use super::request::SignedStorageNativeAcquireRequestV2;
use super::topology::{native_nonrecursive_topology, require_profile_shape};
use super::{Reader, StorageNativeAcquireErrorV2, digest, nonzero, versioned_header};
use crate::{
    RECURSIVE_TOPOLOGY_PROOF_BYTES_V1, RecursiveTopologyProofV1,
    SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1, SignedStorageZfsHoldReceiptV1,
    SourceProviderDescriptorRole, SourceProviderSigningKeyV1, SourceRootObservationV1,
    StorageZfsHoldReceiptV1, StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
    decode_acquire_request, decode_recursive_topology_proof_v1, encode_recursive_topology_proof_v1,
    source_root_descriptor_commitment_v1,
};

const MAGIC: &[u8; 8] = b"AOSZNA03";
const REPLY_MAGIC: &[u8; 8] = b"AOSZNP03";
const VERSION: u16 = 3;
/// Exact canonical width of one unsigned V3 Storage acceptance.
pub const STORAGE_NATIVE_ACCEPTANCE_BYTES_V3: usize = 136 + RECURSIVE_TOPOLOGY_PROOF_BYTES_V1;

/// Exact canonical width of one dedicated-role signed V3 Storage acceptance.
pub const SIGNED_STORAGE_NATIVE_ACCEPTANCE_BYTES_V3: usize =
    STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 + 88 + 64;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.native-acceptance.digest.v3\0";
const SIGNED_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.native-acceptance.signed-digest.v3\0";
pub(super) const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.storage.native-acceptance.signature.v3\0";

/// Exact canonical width of one V3 positive reply, excluding the SourceRoot FD.
pub const STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3: usize =
    24 + SIGNED_STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 + SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1;

const _: () = assert!(STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 == 216);
const _: () = assert!(SIGNED_STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 == 368);
const _: () = assert!(STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3 == 1192);

/// Commits exact signed inputs and the original descriptor without installing authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeAcceptanceV3 {
    issuance_id: [u8; 16],
    request_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    descriptor: SourceRootObservationV1,
    topology: RecursiveTopologyProofV1,
}

impl StorageNativeAcceptanceV3 {
    /// Constructs the stable record for a separate Storage issuance journal.
    ///
    /// Storage must independently verify both signed inputs and retain the
    /// inspected original descriptor before committing this claim. Counts must
    /// come from its complete held-root measurement; this constructor validates
    /// only scalar profile shape, not measurement provenance or crosslinks.
    ///
    /// # Errors
    ///
    /// Rejects sentinel issuance/commitments or counts outside the nonrecursive profile.
    pub fn new(
        issuance_id: [u8; 16],
        request_digest: ObjectDigest,
        receipt_digest: ObjectDigest,
        descriptor: SourceRootObservationV1,
        topology: RecursiveTopologyProofV1,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if issuance_id == [0; 16] || !nonzero(request_digest) || !nonzero(receipt_digest) {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        require_profile_shape(&topology)?;
        Ok(Self {
            issuance_id,
            request_digest,
            receipt_digest,
            descriptor,
            topology,
        })
    }

    /// Returns the stable Storage issuance identity.
    #[must_use]
    pub const fn issuance_id(&self) -> [u8; 16] {
        self.issuance_id
    }

    /// Returns the exact signed Provider request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the exact signed AOSZHR01 receipt commitment.
    #[must_use]
    pub const fn receipt_digest(&self) -> ObjectDigest {
        self.receipt_digest
    }

    /// Returns the original kernel-lifetime descriptor claim.
    #[must_use]
    pub const fn descriptor(&self) -> &SourceRootObservationV1 {
        &self.descriptor
    }

    /// Returns the signed native nonrecursive topology claim.
    #[must_use]
    pub const fn topology(&self) -> &RecursiveTopologyProofV1 {
        &self.topology
    }

    /// Commits exactly one original read-only O_PATH SourceRoot descriptor.
    #[must_use]
    pub fn descriptor_commitment(&self) -> ObjectDigest {
        source_root_descriptor_commitment_v1(&self.descriptor)
    }

    /// Encodes the fixed 216-byte acceptance, excluding its journal and signature.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3] {
        let mut bytes = [0; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.issuance_id);
        bytes[32..64].copy_from_slice(self.request_digest.as_bytes());
        bytes[64..96].copy_from_slice(self.receipt_digest.as_bytes());
        bytes[96..112].copy_from_slice(&self.descriptor.kernel_boot_id());
        bytes[112..120].copy_from_slice(&self.descriptor.device().to_be_bytes());
        bytes[120..128].copy_from_slice(&self.descriptor.inode().to_be_bytes());
        bytes[128..136].copy_from_slice(&self.descriptor.unique_mount_id().to_be_bytes());
        bytes[136..].copy_from_slice(&encode_recursive_topology_proof_v1(&self.topology));
        bytes
    }

    /// Decodes the exact read-only O_PATH directory descriptor claim.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, framing, reserved bytes, or descriptor sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::versioned(bytes, MAGIC, VERSION)?;
        let issuance_id = reader.take()?;
        let request_digest = reader.digest()?;
        let receipt_digest = reader.digest()?;
        let descriptor = SourceRootObservationV1::new(
            reader.take()?,
            reader.u64()?,
            reader.u64()?,
            reader.u64()?,
            true,
            true,
            true,
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let topology =
            decode_recursive_topology_proof_v1(reader.bytes(RECURSIVE_TOPOLOGY_PROOF_BYTES_V1)?)
                .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        reader.done()?;
        Self::new(
            issuance_id,
            request_digest,
            receipt_digest,
            descriptor,
            topology,
        )
    }

    /// Commits the stable unsigned acceptance for durable journal crosslinks.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(DIGEST_DOMAIN, &self.to_canonical_bytes())
    }
}

/// Carries a dedicated ZFS receipt-role signature over a Storage acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageNativeAcceptanceV3 {
    acceptance: StorageNativeAcceptanceV3,
    signer: StorageZfsHoldSignerV1,
    signature: [u8; 64],
}

impl SignedStorageNativeAcceptanceV3 {
    /// Signs accepted evidence using the independently pinned dedicated role.
    ///
    /// This primitive neither journals acceptance nor establishes live custody.
    #[must_use]
    pub fn sign(
        acceptance: StorageNativeAcceptanceV3,
        signer: StorageZfsHoldSignerV1,
        key: &SigningKey,
    ) -> Self {
        let message =
            storage_signing_message(SIGNATURE_DOMAIN, &acceptance.to_canonical_bytes(), signer);
        Self {
            acceptance,
            signer,
            signature: key.sign(&message).to_bytes(),
        }
    }

    /// Returns the immutable unsigned acceptance.
    #[must_use]
    pub const fn acceptance(&self) -> &StorageNativeAcceptanceV3 {
        &self.acceptance
    }

    /// Returns the dedicated Storage receipt signer.
    #[must_use]
    pub const fn signer(&self) -> StorageZfsHoldSignerV1 {
        self.signer
    }

    /// Encodes exact acceptance, signer, and signature bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.acceptance.to_canonical_bytes().to_vec();
        bytes.extend_from_slice(&self.signer.encode());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes an untrusted dedicated-role signed acceptance.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, malformed acceptance/signer, or zero signature.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != SIGNED_STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let acceptance = StorageNativeAcceptanceV3::from_canonical_bytes(
            &bytes[..STORAGE_NATIVE_ACCEPTANCE_BYTES_V3],
        )?;
        let signer = StorageZfsHoldSignerV1::decode(
            &bytes[STORAGE_NATIVE_ACCEPTANCE_BYTES_V3..STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 + 88],
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        let signature = bytes[STORAGE_NATIVE_ACCEPTANCE_BYTES_V3 + 88..]
            .try_into()
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        if signature == [0; 64] {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(Self {
            acceptance,
            signer,
            signature,
        })
    }

    /// Verifies only the pinned dedicated Storage role and signature.
    ///
    /// # Errors
    ///
    /// Rejects a foreign signer, weak/mismatched key, or invalid signature.
    pub fn verify(
        &self,
        verifier: StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        verify_storage_signature(
            SIGNATURE_DOMAIN,
            &self.acceptance.to_canonical_bytes(),
            self.signer,
            &self.signature,
            verifier,
        )
    }

    /// Commits the exact signed acceptance for Provider completion persistence.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(SIGNED_DIGEST_DOMAIN, &self.to_canonical_bytes())
    }
}

/// Carries signed acceptance and receipt with exactly one SourceRoot FD contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeAcquireReplyV3 {
    acceptance: SignedStorageNativeAcceptanceV3,
    receipt: SignedStorageZfsHoldReceiptV1,
}

impl StorageNativeAcquireReplyV3 {
    /// Constructs a structurally matching positive reply without sending an FD.
    ///
    /// # Errors
    ///
    /// Rejects a receipt digest or dedicated-role signer mismatch.
    pub fn new(
        acceptance: SignedStorageNativeAcceptanceV3,
        receipt: SignedStorageZfsHoldReceiptV1,
    ) -> Result<Self, StorageNativeAcquireErrorV2> {
        if acceptance.acceptance.receipt_digest != receipt.digest()
            || acceptance.signer != receipt.signer()
        {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        require_topology_crosslinks(acceptance.acceptance(), &receipt)?;
        Ok(Self {
            acceptance,
            receipt,
        })
    }

    /// Returns the immutable dedicated-role signed acceptance.
    #[must_use]
    pub const fn acceptance(&self) -> &SignedStorageNativeAcceptanceV3 {
        &self.acceptance
    }

    /// Returns the exact AOSZHR01 signed primary Storage observation.
    #[must_use]
    pub const fn receipt(&self) -> &SignedStorageZfsHoldReceiptV1 {
        &self.receipt
    }

    /// Encodes the positive packet without descriptor integers or socket paths.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3);
        versioned_header(&mut bytes, REPLY_MAGIC, VERSION);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(SourceProviderDescriptorRole::SourceRoot as u8);
        bytes.extend_from_slice(&[0; 5]);
        bytes.extend_from_slice(&self.acceptance.to_canonical_bytes());
        bytes.extend_from_slice(&self.receipt.encode());
        bytes
    }

    /// Decodes the exact positive packet, never the negative-only old carrier.
    ///
    /// # Errors
    ///
    /// Rejects wrong size, descriptor count/role, padding, or nested records.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        if bytes.len() != STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3 {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let mut reader = Reader::versioned(bytes, REPLY_MAGIC, VERSION)?;
        if reader.take::<2>()? != 1_u16.to_be_bytes()
            || reader.take::<1>()? != [SourceProviderDescriptorRole::SourceRoot as u8]
            || reader.take::<5>()? != [0; 5]
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let acceptance = SignedStorageNativeAcceptanceV3::from_canonical_bytes(
            reader.bytes(SIGNED_STORAGE_NATIVE_ACCEPTANCE_BYTES_V3)?,
        )?;
        let receipt = SignedStorageZfsHoldReceiptV1::decode(
            reader.bytes(SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1)?,
        )
        .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)?;
        reader.done()?;
        Self::new(acceptance, receipt)
    }

    /// Verifies the cryptographic graph and original descriptor claim only.
    ///
    /// Protected owners must separately establish current heads, acceptance
    /// journal readback, and retained original live FD custody before success.
    ///
    /// # Errors
    ///
    /// Rejects any signature, current expected receipt, crosslink, time, or FD mismatch.
    pub fn verify_for(
        &self,
        context: StorageNativeAcquireVerificationV3<'_>,
    ) -> Result<VerifiedStorageNativeAcquireV3, StorageNativeAcquireErrorV2> {
        context.request.verify(
            context.provider_signer,
            context.provider_key,
            context.root_signer,
            context.root_key,
        )?;
        context
            .storage_verifier
            .verify_for(&self.receipt, context.expected_receipt, context.now_seconds)
            .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
        self.acceptance.verify(context.storage_verifier)?;
        // The receipt signer is now independently pinned, not self-asserted.
        // Recompute the profile under its exact primary-journal cut and signed inputs.
        require_topology_crosslinks(self.acceptance.acceptance(), &self.receipt)?;
        let claims = context.request.request().claims();
        let catalog = claims.catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                claims.selection().0,
            )
            .map_err(|_| StorageNativeAcquireErrorV2::Mismatch)?;
        let root =
            decode_acquire_request(context.request.request().signed_root_request().subject())
                .map_err(|_| StorageNativeAcquireErrorV2::Mismatch)?;
        let (issued, expires) = claims.validity();
        let acceptance = self.acceptance.acceptance();
        if acceptance.request_digest != context.request.digest()
            || acceptance.receipt_digest != self.receipt.digest()
            || acceptance.descriptor != *context.observed_descriptor
            || root.boot_id() != acceptance.descriptor.kernel_boot_id()
            || context.descriptor_roles != [SourceProviderDescriptorRole::SourceRoot]
            || self.receipt.receipt().attempt() != claims.attempt()
            || self.receipt.receipt().binding_digest() != claims.selection().0
            || self.receipt.receipt().resource() != &resource
            || self.receipt.receipt().snapshot() != &snapshot
            || self.receipt.receipt().validity().0 < issued
            || self.receipt.receipt().validity().1 > expires
            || context.now_seconds < issued
            || context.now_seconds >= expires
        {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        Ok(VerifiedStorageNativeAcquireV3 {
            request_digest: context.request.digest(),
            acceptance: acceptance.clone(),
            signed_acceptance_digest: self.acceptance.digest(),
        })
    }
}

/// Supplies independently recovered pins, expected receipt, and FD observation.
pub struct StorageNativeAcquireVerificationV3<'a> {
    /// Names the exact signed request retained by the Provider attempt.
    pub request: &'a SignedStorageNativeAcquireRequestV2,
    /// Pins the Provider outcome signer through protected trust.
    pub provider_signer: &'a SourceProviderSigningKeyV1,
    /// Supplies that signer's independently trusted Ed25519 key.
    pub provider_key: &'a [u8; 32],
    /// Pins the original broker record signer through protected trust.
    pub root_signer: &'a SourceProviderSigningKeyV1,
    /// Supplies the original broker signer's trusted Ed25519 key.
    pub root_key: &'a [u8; 32],
    /// Pins the dedicated Storage ZFS receipt role, not generic backend attestation.
    pub storage_verifier: StorageZfsHoldVerifierV1,
    /// Names the independently observed current Storage tuple, not decoded self-claims.
    pub expected_receipt: &'a StorageZfsHoldReceiptV1,
    /// Names the inspected original descriptor; scalars alone prove no custody.
    pub observed_descriptor: &'a SourceRootObservationV1,
    /// Names the actually received descriptor roles in order.
    pub descriptor_roles: &'a [SourceProviderDescriptorRole],
    /// Supplies trusted current Unix seconds.
    pub now_seconds: i64,
}

/// Retains a verified cryptographic graph without granting live-custody authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStorageNativeAcquireV3 {
    request_digest: ObjectDigest,
    acceptance: StorageNativeAcceptanceV3,
    signed_acceptance_digest: ObjectDigest,
}

/// Models the runtime owner's separately established original descriptor custody.
///
/// A scalar variant is not kernel evidence. A production owner must derive
/// this fact from its retained original descriptor, never a reopened path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageNativeDescriptorCustodyV2 {
    /// The original descriptor remains continuously held by a live owner.
    RetainedOriginal,
    /// No live owner retains the original descriptor.
    Lost,
}

impl VerifiedStorageNativeAcquireV3 {
    /// Returns the verified exact signed request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the verified exact signed receipt commitment.
    #[must_use]
    pub const fn receipt_digest(&self) -> ObjectDigest {
        self.acceptance.receipt_digest
    }

    /// Returns the immutable acceptance and original descriptor identity.
    #[must_use]
    pub const fn acceptance(&self) -> &StorageNativeAcceptanceV3 {
        &self.acceptance
    }

    /// Returns the verified signed topology claim, not live measurement authority.
    #[must_use]
    pub const fn topology(&self) -> &RecursiveTopologyProofV1 {
        self.acceptance.topology()
    }

    /// Returns the exact signed acceptance commitment for durable Provider replay.
    #[must_use]
    pub const fn signed_acceptance_digest(&self) -> ObjectDigest {
        self.signed_acceptance_digest
    }

    /// Returns the stable unsigned acceptance commitment retained by Storage.
    #[must_use]
    pub fn acceptance_payload_digest(&self) -> ObjectDigest {
        self.acceptance.digest()
    }

    /// Requires the original descriptor identity for a structurally exact retry.
    ///
    /// A future kernel owner must additionally retain original live custody.
    /// A remounted equivalent snapshot is rejected, including after reboot.
    ///
    /// # Errors
    ///
    /// Rejects any changed boot, device, inode, mount ID, or descriptor flag.
    pub fn require_original_descriptor(
        &self,
        observed: &SourceRootObservationV1,
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        if &self.acceptance.descriptor != observed {
            return Err(StorageNativeAcquireErrorV2::Mismatch);
        }
        Ok(())
    }

    /// Requires exact original identity and retained custody for a modeled retry.
    ///
    /// This check grants no send authority. Total custody loss requires
    /// authenticated cleanup/absence; an equivalent remount cannot recover it.
    ///
    /// # Errors
    ///
    /// Rejects lost original custody or a changed descriptor identity.
    pub fn require_exact_live_retry(
        &self,
        observed: &SourceRootObservationV1,
        custody: StorageNativeDescriptorCustodyV2,
    ) -> Result<(), StorageNativeAcquireErrorV2> {
        if custody == StorageNativeDescriptorCustodyV2::Lost {
            return Err(StorageNativeAcquireErrorV2::CustodyLost);
        }
        self.require_original_descriptor(observed)
    }
}

fn require_topology_crosslinks(
    acceptance: &StorageNativeAcceptanceV3,
    receipt: &SignedStorageZfsHoldReceiptV1,
) -> Result<(), StorageNativeAcquireErrorV2> {
    let expected = native_nonrecursive_topology(
        acceptance.request_digest,
        receipt,
        &acceptance.descriptor,
        acceptance.topology.entry_count(),
        acceptance.topology.byte_count(),
    )?;
    if acceptance.topology != expected {
        return Err(StorageNativeAcquireErrorV2::Mismatch);
    }
    Ok(())
}

pub(super) fn storage_signing_message(
    domain: &[u8],
    subject: &[u8],
    signer: StorageZfsHoldSignerV1,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + subject.len() + 88);
    message.extend_from_slice(domain);
    message.extend_from_slice(subject);
    message.extend_from_slice(&signer.encode());
    message
}

pub(super) fn verify_storage_signature(
    domain: &[u8],
    subject: &[u8],
    signer: StorageZfsHoldSignerV1,
    signature: &[u8; 64],
    verifier: StorageZfsHoldVerifierV1,
) -> Result<(), StorageNativeAcquireErrorV2> {
    let (expected_signer, public_key) = verifier.projection();
    if signer != expected_signer {
        return Err(StorageNativeAcquireErrorV2::Authority);
    }
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| StorageNativeAcquireErrorV2::Authority)?;
    key.verify_strict(
        &storage_signing_message(domain, subject, signer),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| StorageNativeAcquireErrorV2::Authority)
}
