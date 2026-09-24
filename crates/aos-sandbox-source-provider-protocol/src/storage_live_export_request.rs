//! Signed Provider-to-Storage request for one LocalLive export.
//!
//! The Provider signs an exact selected catalog row and embeds the original
//! RootMount-signed Acquire request. Storage must independently pin both keys,
//! compare the selection to current protected catalogs, and journal the exact
//! request before any export effect. This transport-neutral contract does not
//! authorize signing a Storage lease by itself.
//!
//! ```text
//! AOSSPR01 | version:u16be=1 | reserved[6]=0 |
//! plan-id[16] | protected-attempt-digest[32] | normalized-intent-digest[32] |
//! effect-id[16] | backend-id[32] |
//! resource-namespace-digest[32] | resource-id[32] | resource-generation:u64be |
//! resource-digest[32] | catalog-generation:u64be | catalog-digest[32] |
//! selection-generation:u64be | selection-digest[32] |
//! export-id[16] | export-generation:u64be | workspace-id[32] |
//! source-assignment-digest[32] | issued-seconds:i64be | expires-seconds:i64be |
//! signed-root-request-length:u32be | signed-root-request[.length] |
//! provider-authority-id[16] | provider-generation:u64be |
//! provider-authority-digest[32] | provider-key-id[16] |
//! provider-key-generation:u64be | provider-public-key-digest[32] |
//! ed25519-signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::codec::{MAXIMUM_FRAME_BYTES, decode_acquire_request};
use crate::crypto::{
    SignedSourceProviderRequestV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    verify_request,
};
use crate::model::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, AcquireSourceRequestV1, SourceProviderMethod,
    SourceResourceV1,
};

const MAGIC: &[u8; 8] = b"AOSSPR01";
const VERSION: u16 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.provider.storage-export-request.signature.v1\0";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.provider.storage-export-request.digest.v1\0";
const SIGNER_BYTES: usize = 112;
const SIGNATURE_BYTES: usize = 64;
const NON_ROOT_BYTES: usize = 436 + SIGNER_BYTES + SIGNATURE_BYTES;

/// Reports malformed, unauthenticated, or conflicting export-plan bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageLiveExportRequestErrorV1 {
    /// An identity, version, bound, or wire field is invalid.
    #[error("Provider-to-Storage export request is noncanonical")]
    Noncanonical,
    /// The pinned RootMount request is absent, mismatched, or unauthenticated.
    #[error("Provider-to-Storage export request has invalid RootMount authority")]
    RootAuthority,
    /// The pinned Provider signer or its signature is invalid.
    #[error("Provider-to-Storage export request has invalid Provider authority")]
    ProviderAuthority,
    /// The same plan identity was reused for different signed bytes.
    #[error("Provider-to-Storage export request conflicts with a prior plan")]
    ReplayConflict,
}

/// Selects one Storage-published export and its protected workspace assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportSelectorV1 {
    export_id: [u8; 16],
    export_generation: u64,
    workspace_id: [u8; 32],
    source_assignment_digest: ObjectDigest,
}

impl StorageLiveExportSelectorV1 {
    /// Constructs an exact export selector to compare against current Storage state.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::Noncanonical`] for sentinels.
    pub fn new(
        export_id: [u8; 16],
        export_generation: u64,
        workspace_id: [u8; 32],
        source_assignment_digest: ObjectDigest,
    ) -> Result<Self, StorageLiveExportRequestErrorV1> {
        if export_id == [0; 16]
            || export_generation == 0
            || workspace_id == [0; 32]
            || source_assignment_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }
        Ok(Self {
            export_id,
            export_generation,
            workspace_id,
            source_assignment_digest,
        })
    }

    /// Returns the logical Storage export ID.
    #[must_use]
    pub const fn export_id(self) -> [u8; 16] {
        self.export_id
    }

    /// Returns the current Storage export generation.
    #[must_use]
    pub const fn export_generation(self) -> u64 {
        self.export_generation
    }

    /// Returns the opaque Storage workspace handle.
    #[must_use]
    pub const fn workspace_id(self) -> [u8; 32] {
        self.workspace_id
    }

    /// Returns the protected source-assignment commitment.
    #[must_use]
    pub const fn source_assignment_digest(self) -> ObjectDigest {
        self.source_assignment_digest
    }
}

/// Binds one protected Provider attempt to a selected resource and RootMount request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageLiveExportRequestV1 {
    plan_id: [u8; 16],
    protected_attempt_digest: ObjectDigest,
    normalized_intent_digest: ObjectDigest,
    effect_id: [u8; 16],
    backend_id: ObjectDigest,
    resource: SourceResourceV1,
    selector: StorageLiveExportSelectorV1,
    issued_seconds: i64,
    expires_seconds: i64,
    signed_root_request: SignedSourceProviderRequestV1,
}

impl StorageLiveExportRequestV1 {
    /// Constructs the signed plan subject without granting export authority.
    ///
    /// The caller must derive the attempt, exact selected row, and selector
    /// from protected current Provider state. Storage repeats those checks
    /// against its own state before any effect.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::Noncanonical`] for invalid
    /// commitments, a legacy or non-kernel-coupled RootMount request, or an
    /// interval exceeding the RootMount request's bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: [u8; 16],
        protected_attempt_digest: ObjectDigest,
        normalized_intent_digest: ObjectDigest,
        effect_id: [u8; 16],
        backend_id: ObjectDigest,
        resource: SourceResourceV1,
        selector: StorageLiveExportSelectorV1,
        issued_seconds: i64,
        expires_seconds: i64,
        signed_root_request: SignedSourceProviderRequestV1,
    ) -> Result<Self, StorageLiveExportRequestErrorV1> {
        if plan_id == [0; 16]
            || protected_attempt_digest.as_bytes() == &[0; 32]
            || normalized_intent_digest.as_bytes() == &[0; 32]
            || effect_id == [0; 16]
            || backend_id.as_bytes() == &[0; 32]
            || signed_root_request.method() != SourceProviderMethod::Acquire
        {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }

        let root_request = decode_acquire_request(signed_root_request.subject())
            .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)?;
        let duration = expires_seconds.checked_sub(issued_seconds);
        if root_request.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V2
            || !root_request.kernel_coupled()
            || issued_seconds <= 0
            || issued_seconds > root_request.deadline_seconds()
            || duration.is_none_or(|seconds| {
                seconds <= 0 || seconds as u64 > root_request.requested_lease_seconds()
            })
        {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }

        Ok(Self {
            plan_id,
            protected_attempt_digest,
            normalized_intent_digest,
            effect_id,
            backend_id,
            resource,
            selector,
            issued_seconds,
            expires_seconds,
            signed_root_request,
        })
    }

    /// Returns the idempotency identity journaled by Storage.
    #[must_use]
    pub const fn plan_id(&self) -> [u8; 16] {
        self.plan_id
    }

    /// Returns the protected Provider attempt commitment.
    #[must_use]
    pub const fn protected_attempt_digest(&self) -> ObjectDigest {
        self.protected_attempt_digest
    }

    /// Returns the normalized intent commitment from the authenticated attempt.
    #[must_use]
    pub const fn normalized_intent_digest(&self) -> ObjectDigest {
        self.normalized_intent_digest
    }

    /// Returns the exact Provider effect ID.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the Provider backend assignment commitment.
    #[must_use]
    pub const fn backend_id(&self) -> ObjectDigest {
        self.backend_id
    }

    /// Returns the exact selected Provider catalog resource and selection.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the requested Storage export and workspace assignment.
    #[must_use]
    pub const fn selector(&self) -> StorageLiveExportSelectorV1 {
        self.selector
    }

    /// Returns the requested inclusive lease issue time.
    #[must_use]
    pub const fn issued_seconds(&self) -> i64 {
        self.issued_seconds
    }

    /// Returns the requested exclusive lease expiry.
    #[must_use]
    pub const fn expires_seconds(&self) -> i64 {
        self.expires_seconds
    }

    /// Returns the embedded signed RootMount consumer and attachment request.
    #[must_use]
    pub const fn signed_root_request(&self) -> &SignedSourceProviderRequestV1 {
        &self.signed_root_request
    }

    /// Decodes the already-canonical embedded RootMount Acquire subject.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::Noncanonical`] if the
    /// embedded request can no longer be decoded.
    pub fn root_acquire(&self) -> Result<AcquireSourceRequestV1, StorageLiveExportRequestErrorV1> {
        decode_acquire_request(self.signed_root_request.subject())
            .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let root_bytes = self.signed_root_request.to_canonical_bytes();
        let mut bytes = Vec::with_capacity(512 + root_bytes.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.plan_id);
        bytes.extend_from_slice(self.protected_attempt_digest.as_bytes());
        bytes.extend_from_slice(self.normalized_intent_digest.as_bytes());
        bytes.extend_from_slice(&self.effect_id);
        bytes.extend_from_slice(self.backend_id.as_bytes());
        bytes.extend_from_slice(self.resource.resource_namespace_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.resource_id());
        bytes.extend_from_slice(&self.resource.resource_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.resource_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.catalog_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.catalog_digest().as_bytes());
        bytes.extend_from_slice(&self.resource.selection_generation().to_be_bytes());
        bytes.extend_from_slice(self.resource.selection_digest().as_bytes());
        bytes.extend_from_slice(&self.selector.export_id);
        bytes.extend_from_slice(&self.selector.export_generation.to_be_bytes());
        bytes.extend_from_slice(&self.selector.workspace_id);
        bytes.extend_from_slice(self.selector.source_assignment_digest.as_bytes());
        bytes.extend_from_slice(&self.issued_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.expires_seconds.to_be_bytes());
        bytes.extend_from_slice(&(root_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&root_bytes);
        bytes
    }
}

/// Carries one Provider-signed, RootMount-bound Storage export request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageLiveExportRequestV1 {
    request: StorageLiveExportRequestV1,
    signer: SourceProviderSigningKeyV1,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedStorageLiveExportRequestV1 {
    /// Signs a plan with the Provider outcome key after Provider-side validation.
    ///
    /// This is a cryptographic primitive, not a protected catalog or attempt
    /// verifier. The production issuer must not call it on caller-supplied plan
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::ProviderAuthority`] for a
    /// wrong-use signer or public-key mismatch.
    pub fn sign(
        request: StorageLiveExportRequestV1,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, StorageLiveExportRequestErrorV1> {
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.public_key_digest()
                != digest(Sha256::digest(signing_key.verifying_key().as_bytes()).into())
        {
            return Err(StorageLiveExportRequestErrorV1::ProviderAuthority);
        }

        let message = signed_message(&request, &signer);
        let signature = signing_key.sign(&message).to_bytes();
        Ok(Self {
            request,
            signer,
            signature,
        })
    }

    /// Returns the exact signed plan subject.
    #[must_use]
    pub const fn request(&self) -> &StorageLiveExportRequestV1 {
        &self.request
    }

    /// Returns the Provider signer reference to pin independently.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Encodes the exact versioned signed plan.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.request.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes one bounded, canonical signed plan without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::Noncanonical`] for invalid
    /// framing, fields, nested RootMount bytes, or trailing data.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageLiveExportRequestErrorV1> {
        if bytes.len() > MAXIMUM_FRAME_BYTES + NON_ROOT_BYTES {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }
        let mut reader = Reader::new(bytes);
        if reader.take::<8>()? != *MAGIC
            || u16::from_be_bytes(reader.take()?) != VERSION
            || reader.take::<6>()? != [0; 6]
        {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }

        let plan_id = reader.take()?;
        let protected_attempt_digest = digest(reader.take()?);
        let normalized_intent_digest = digest(reader.take()?);
        let effect_id = reader.take()?;
        let backend_id = digest(reader.take()?);
        let resource = SourceResourceV1::new(
            digest(reader.take()?),
            reader.take()?,
            u64::from_be_bytes(reader.take()?),
            digest(reader.take()?),
            u64::from_be_bytes(reader.take()?),
            digest(reader.take()?),
            u64::from_be_bytes(reader.take()?),
            digest(reader.take()?),
        )
        .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)?;
        let selector = StorageLiveExportSelectorV1::new(
            reader.take()?,
            u64::from_be_bytes(reader.take()?),
            reader.take()?,
            digest(reader.take()?),
        )?;
        let issued_seconds = i64::from_be_bytes(reader.take()?);
        let expires_seconds = i64::from_be_bytes(reader.take()?);
        let root_length = u32::from_be_bytes(reader.take()?) as usize;
        if root_length == 0 || root_length > MAXIMUM_FRAME_BYTES {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }
        let signed_root_request =
            SignedSourceProviderRequestV1::from_canonical_bytes(reader.take_slice(root_length)?)
                .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)?;
        let request = StorageLiveExportRequestV1::new(
            plan_id,
            protected_attempt_digest,
            normalized_intent_digest,
            effect_id,
            backend_id,
            resource,
            selector,
            issued_seconds,
            expires_seconds,
            signed_root_request,
        )?;

        let signer = SourceProviderSigningKeyV1::new(
            reader.take()?,
            u64::from_be_bytes(reader.take()?),
            digest(reader.take()?),
            reader.take()?,
            u64::from_be_bytes(reader.take()?),
            digest(reader.take()?),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)?;
        let signature = reader.take()?;
        if !reader.is_empty() {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }

        let signed = Self {
            request,
            signer,
            signature,
        };
        if signed.to_canonical_bytes() != bytes {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }
        Ok(signed)
    }

    /// Verifies both independently pinned signers and exact nested signatures.
    ///
    /// This does not establish current catalog state, durable replay state,
    /// protected attempt state, or physical Storage export truth.
    ///
    /// # Errors
    ///
    /// Returns Root or Provider authority errors for a mismatched signer,
    /// weak or mismatched key, or invalid Ed25519 signature.
    pub fn verify(
        &self,
        expected_provider_signer: &SourceProviderSigningKeyV1,
        provider_public_key: &[u8; 32],
        expected_root_signer: &SourceProviderSigningKeyV1,
        root_public_key: &[u8; 32],
    ) -> Result<(), StorageLiveExportRequestErrorV1> {
        if self.request.signed_root_request.signer() != expected_root_signer {
            return Err(StorageLiveExportRequestErrorV1::RootAuthority);
        }
        verify_request(&self.request.signed_root_request, root_public_key)
            .map_err(|_| StorageLiveExportRequestErrorV1::RootAuthority)?;

        if &self.signer != expected_provider_signer
            || self.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || self.signer.public_key_digest() != digest(Sha256::digest(provider_public_key).into())
        {
            return Err(StorageLiveExportRequestErrorV1::ProviderAuthority);
        }
        let public_key = VerifyingKey::from_bytes(provider_public_key)
            .map_err(|_| StorageLiveExportRequestErrorV1::ProviderAuthority)?;
        if public_key.is_weak() {
            return Err(StorageLiveExportRequestErrorV1::ProviderAuthority);
        }
        let signature = Signature::from_bytes(&self.signature);
        public_key
            .verify_strict(&signed_message(&self.request, &self.signer), &signature)
            .map_err(|_| StorageLiveExportRequestErrorV1::ProviderAuthority)
    }

    /// Returns the digest Storage must journal with this exact signed request.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        digest(hasher.finalize().into())
    }

    /// Compares one prior journaled plan ID and signed digest for exact replay.
    /// Call this only after both signatures and the protected prior journal
    /// entry have been authenticated; equality does not authorize an effect.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportRequestErrorV1::ReplayConflict`] when the
    /// same plan ID names different signed bytes.
    pub fn classify_replay(
        &self,
        prior_plan_id: [u8; 16],
        prior_signed_digest: ObjectDigest,
    ) -> Result<StorageLiveExportRequestReplayV1, StorageLiveExportRequestErrorV1> {
        if prior_plan_id != self.request.plan_id {
            return Ok(StorageLiveExportRequestReplayV1::NewIdentity);
        }
        if prior_signed_digest == self.digest() {
            Ok(StorageLiveExportRequestReplayV1::ExactReplay)
        } else {
            Err(StorageLiveExportRequestErrorV1::ReplayConflict)
        }
    }
}

/// Classifies a journal comparison without performing any export effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageLiveExportRequestReplayV1 {
    /// The journal has no entry for this plan identity.
    NewIdentity,
    /// The journal holds this exact signed request digest.
    ExactReplay,
}

fn signed_message(
    request: &StorageLiveExportRequestV1,
    signer: &SourceProviderSigningKeyV1,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(600);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&request.subject_bytes());
    encode_signer(&mut message, signer);
    message
}

fn encode_signer(bytes: &mut Vec<u8>, signer: &SourceProviderSigningKeyV1) {
    bytes.reserve(SIGNER_BYTES);
    bytes.extend_from_slice(&signer.authority_id());
    bytes.extend_from_slice(&signer.authority_generation().to_be_bytes());
    bytes.extend_from_slice(signer.authority_digest().as_bytes());
    bytes.extend_from_slice(&signer.key_id());
    bytes.extend_from_slice(&signer.key_generation().to_be_bytes());
    bytes.extend_from_slice(signer.public_key_digest().as_bytes());
}

const fn digest(bytes: [u8; 32]) -> ObjectDigest {
    ObjectDigest::from_bytes(bytes)
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StorageLiveExportRequestErrorV1> {
        let bytes = self.take_slice(N)?;
        bytes
            .try_into()
            .map_err(|_| StorageLiveExportRequestErrorV1::Noncanonical)
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], StorageLiveExportRequestErrorV1> {
        if self.remaining.len() < len {
            return Err(StorageLiveExportRequestErrorV1::Noncanonical);
        }
        let (head, tail) = self.remaining.split_at(len);
        self.remaining = tail;
        Ok(head)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        SourceUseV1, digest_logical_binding_bytes, encode_acquire_request,
        prospective_mount_apply_template_digest_v1, sign_request,
    };

    fn test_digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn mount_template() -> Vec<u8> {
        let mut bytes = Vec::new();
        for tag in 1u8..=27 {
            let value = match tag {
                1 => b"AOSMSEM1".to_vec(),
                2 => 1u16.to_be_bytes().to_vec(),
                _ => vec![tag, tag.wrapping_add(1)],
            };
            bytes.push(tag);
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&value);
        }
        bytes
    }

    fn root_request(root_key: &SigningKey, v2: bool) -> SignedSourceProviderRequestV1 {
        let template = mount_template();
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let binding = b"exact-root-mount-attachment".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        let request = if v2 {
            AcquireSourceRequestV1::new_v2(
                test_digest(1),
                2,
                [3; 16],
                4,
                template,
                template_digest,
                SourceUseV1::MountCreate,
                [5; 16],
                [6; 16],
                [7; 16],
                8,
                test_digest(9),
                binding,
                binding_digest,
                1000,
                60,
                test_digest(10),
                false,
                0,
                true,
            )
            .unwrap()
        } else {
            AcquireSourceRequestV1::new(
                test_digest(1),
                2,
                [3; 16],
                test_digest(4),
                template,
                template_digest,
                SourceUseV1::MountCreate,
                [5; 16],
                [6; 16],
                [7; 16],
                8,
                test_digest(9),
                binding,
                binding_digest,
                1000,
                60,
                test_digest(10),
                false,
                0,
                true,
            )
            .unwrap()
        };
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [7; 16],
            8,
            test_digest(9),
            [11; 16],
            12,
            SourceProviderKeyUsageV1::RootMountRecord,
            root_key,
        )
        .unwrap();
        sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&request),
            signer,
            root_key,
        )
        .unwrap()
    }

    fn signed_plan(
        root_key: &SigningKey,
        provider_key: &SigningKey,
        workspace_id: [u8; 32],
    ) -> SignedStorageLiveExportRequestV1 {
        let resource = SourceResourceV1::new(
            test_digest(13),
            [14; 32],
            15,
            test_digest(16),
            17,
            test_digest(18),
            19,
            test_digest(20),
        )
        .unwrap();
        let selector =
            StorageLiveExportSelectorV1::new([21; 16], 22, workspace_id, test_digest(24)).unwrap();
        let request = StorageLiveExportRequestV1::new(
            [25; 16],
            test_digest(26),
            test_digest(27),
            [28; 16],
            test_digest(29),
            resource,
            selector,
            900,
            930,
            root_request(root_key, true),
        )
        .unwrap();
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [30; 16],
            31,
            test_digest(32),
            [33; 16],
            34,
            SourceProviderKeyUsageV1::ProviderOutcome,
            provider_key,
        )
        .unwrap();
        SignedStorageLiveExportRequestV1::sign(request, signer, provider_key).unwrap()
    }

    #[test]
    fn canonical_plan_binds_both_signers_and_exact_root_attachment() {
        let root_key = SigningKey::from_bytes(&[41; 32]);
        let provider_key = SigningKey::from_bytes(&[42; 32]);
        let plan = signed_plan(&root_key, &provider_key, [23; 32]);
        let wire = plan.to_canonical_bytes();
        let decoded = SignedStorageLiveExportRequestV1::from_canonical_bytes(&wire).unwrap();

        assert_eq!(decoded, plan);
        assert_eq!(
            wire.len()
                - plan
                    .request()
                    .signed_root_request()
                    .to_canonical_bytes()
                    .len(),
            NON_ROOT_BYTES,
        );
        assert_eq!(decoded.request().resource().resource_id(), [14; 32]);
        assert_eq!(decoded.request().selector().workspace_id(), [23; 32]);
        assert_eq!(
            decoded.request().root_acquire().unwrap().binding(),
            b"exact-root-mount-attachment"
        );
        assert_eq!(
            decoded
                .request()
                .root_acquire()
                .unwrap()
                .holder_generation(),
            8
        );
        decoded
            .verify(
                plan.signer(),
                &provider_key.verifying_key().to_bytes(),
                plan.request().signed_root_request().signer(),
                &root_key.verifying_key().to_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn decode_rejects_noncanonical_and_legacy_root_requests() {
        let root_key = SigningKey::from_bytes(&[41; 32]);
        let provider_key = SigningKey::from_bytes(&[42; 32]);
        let plan = signed_plan(&root_key, &provider_key, [23; 32]);
        let wire = plan.to_canonical_bytes();

        let mut reserved = wire.clone();
        reserved[10] = 1;
        assert!(SignedStorageLiveExportRequestV1::from_canonical_bytes(&reserved).is_err());
        let mut version = wire.clone();
        version[9] = 2;
        assert!(SignedStorageLiveExportRequestV1::from_canonical_bytes(&version).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SignedStorageLiveExportRequestV1::from_canonical_bytes(&trailing).is_err());
        assert!(
            SignedStorageLiveExportRequestV1::from_canonical_bytes(&wire[..wire.len() - 1])
                .is_err()
        );

        let legacy = StorageLiveExportRequestV1::new(
            [25; 16],
            test_digest(26),
            test_digest(27),
            [28; 16],
            test_digest(29),
            plan.request().resource().clone(),
            plan.request().selector(),
            900,
            930,
            root_request(&root_key, false),
        );
        assert_eq!(legacy, Err(StorageLiveExportRequestErrorV1::Noncanonical));

        let overlong = StorageLiveExportRequestV1::new(
            [25; 16],
            test_digest(26),
            test_digest(27),
            [28; 16],
            test_digest(29),
            plan.request().resource().clone(),
            plan.request().selector(),
            900,
            961,
            root_request(&root_key, true),
        );
        assert_eq!(overlong, Err(StorageLiveExportRequestErrorV1::Noncanonical));
    }

    #[test]
    fn signatures_and_journal_replay_are_exact() {
        let root_key = SigningKey::from_bytes(&[41; 32]);
        let provider_key = SigningKey::from_bytes(&[42; 32]);
        let plan = signed_plan(&root_key, &provider_key, [23; 32]);
        let changed = signed_plan(&root_key, &provider_key, [35; 32]);

        assert_eq!(
            plan.classify_replay(plan.request().plan_id(), plan.digest()),
            Ok(StorageLiveExportRequestReplayV1::ExactReplay),
        );
        assert_eq!(
            changed.classify_replay(plan.request().plan_id(), plan.digest()),
            Err(StorageLiveExportRequestErrorV1::ReplayConflict),
        );
        assert_eq!(
            plan.classify_replay([36; 16], changed.digest()),
            Ok(StorageLiveExportRequestReplayV1::NewIdentity),
        );

        let mut tampered = plan.to_canonical_bytes();
        tampered[16 + 16 + 32] ^= 1;
        let tampered = SignedStorageLiveExportRequestV1::from_canonical_bytes(&tampered).unwrap();
        assert_eq!(
            tampered.verify(
                plan.signer(),
                &provider_key.verifying_key().to_bytes(),
                plan.request().signed_root_request().signer(),
                &root_key.verifying_key().to_bytes(),
            ),
            Err(StorageLiveExportRequestErrorV1::ProviderAuthority),
        );
        assert_eq!(
            plan.verify(
                plan.signer(),
                &provider_key.verifying_key().to_bytes(),
                plan.request().signed_root_request().signer(),
                &provider_key.verifying_key().to_bytes(),
            ),
            Err(StorageLiveExportRequestErrorV1::RootAuthority),
        );
    }
}
