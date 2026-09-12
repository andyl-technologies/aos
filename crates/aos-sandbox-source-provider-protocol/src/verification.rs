//! Composite SourceProvider response verification.
//!
//! These entry points cryptographically authenticate signed protocol records,
//! validate their complete graph, and return opaque results. Process and
//! descriptor observations remain supplied model inputs until a future branded
//! kernel adapter establishes their provenance.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::codec::{
    SourceProviderFrameError, SourceProviderMessageV1, decode_acquire_request,
    decode_inventory_request, decode_release_request, validate_message_descriptor_contract,
};
use crate::crypto::{
    SignedSourceExportLeaseV1, SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1,
    SignedSourceProviderRequestV1, SignedSourceProviderStatusV1, SignedSourceReleaseReceiptV1,
    SourceProviderSignatureError, digest_acquire_request, digest_inventory_request,
    digest_provider_proof, digest_release_request, digest_signed_export_lease,
    digest_signed_request, empty_descriptor_set_commitment_v1, provider_resource_commitment_v1,
    response_result_digest_v1, verify_hello, verify_inventory, verify_provider_receipt,
    verify_release_receipt, verify_request, verify_response_status,
};
use crate::model::{
    AcquireSourceRequestV1, AcquireSourceResponseV1, InventorySourceResponseV1,
    ReleaseSourceResponseV1, SourceProviderDescriptorRole, SourceProviderMethod,
    SourceProviderStatus, SourceProviderValidationError, require_digest, require_generation,
    require_nonzero,
};
use crate::proof::SourceProviderProofV1;
use crate::trust::{
    ProtectedSourceProviderRouteV1, SourceProviderSessionV1, SourceProviderTrustAnchorV1,
    SourceProviderTrustError,
};

/// Reports a failed complete SourceProvider verification graph.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderVerificationError {
    /// A typed protocol body is malformed or noncanonical.
    #[error("SourceProvider typed message verification failed: {0}")]
    Codec(#[from] SourceProviderFrameError),
    /// Canonical signature or signed-envelope verification failed.
    #[error("SourceProvider signature verification failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
    /// Trust, route, or supplied session verification failed.
    #[error("SourceProvider trust, route, or session verification failed: {0}")]
    Trust(#[from] SourceProviderTrustError),
    /// A semantic value or descriptor table was invalid.
    #[error("SourceProvider semantic verification failed: {0}")]
    InvalidValue(#[from] SourceProviderValidationError),
    /// A request, response, lease, receipt, route, or observation cross-link differs.
    #[error("SourceProvider verified inputs do not describe one operation")]
    CrossLink,
    /// A request or returned lease lies outside supplied current bounds.
    #[error("SourceProvider operation is outside current time or ownership bounds")]
    Bounds,
    /// Provider state is below or equivocates with a supplied rollback floor.
    #[error("SourceProvider authority, catalog, resource, or selection violated its floor")]
    Rollback,
}

/// Models current controller and ownership bounds supplied to verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderVerificationContextV1 {
    now_seconds: i64,
    maximum_lease_expiry_seconds: i64,
    node_id: [u8; 16],
    boot_id: [u8; 16],
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    revocation_digest: ObjectDigest,
    expected_request_sequence: u64,
    expected_response_sequence: u64,
}

impl SourceProviderVerificationContextV1 {
    /// Constructs shaped current bounds for one Root Mount holder.
    ///
    /// Production callers must obtain these values from protected controller and
    /// ownership state; construction alone establishes no such provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] for sentinel identities or
    /// digests, zero generation, negative time, or an exhausted expiry bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        now_seconds: i64,
        maximum_lease_expiry_seconds: i64,
        node_id: [u8; 16],
        boot_id: [u8; 16],
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        revocation_digest: ObjectDigest,
        expected_request_sequence: u64,
        expected_response_sequence: u64,
    ) -> Result<Self, SourceProviderVerificationError> {
        if now_seconds < 0 || maximum_lease_expiry_seconds <= now_seconds {
            return Err(SourceProviderVerificationError::Bounds);
        }
        require_nonzero("verification node ID", &node_id)?;
        require_nonzero("verification boot ID", &boot_id)?;
        require_nonzero("verification holder authority ID", &holder_authority_id)?;
        require_generation("verification holder", holder_generation)?;
        require_digest(
            "verification holder authority digest",
            holder_authority_digest,
        )?;
        require_digest("verification revocation digest", revocation_digest)?;
        require_generation("expected request sequence", expected_request_sequence)?;
        require_generation("expected response sequence", expected_response_sequence)?;
        Ok(Self {
            now_seconds,
            maximum_lease_expiry_seconds,
            node_id,
            boot_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            revocation_digest,
            expected_request_sequence,
            expected_response_sequence,
        })
    }
}

/// Models exact source-root fields supplied by a future kernel adapter.
///
/// Construction validates field shape only. A production adapter must issue
/// non-forgeable evidence after inspecting the received descriptor; public
/// scalar construction does not prove kernel provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRootObservationV1 {
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    unique_mount_id: u64,
    o_path: bool,
    directory: bool,
    read_only: bool,
}

impl SourceRootObservationV1 {
    /// Returns the observed kernel boot identity.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the observed device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the observed inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the observed kernel-lifetime unique mount identity.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }

    /// Constructs one shaped `O_PATH` directory descriptor observation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] for sentinel observation fields or
    /// a value that does not describe a read-only `O_PATH` directory.
    pub fn new(
        kernel_boot_id: [u8; 16],
        device: u64,
        inode: u64,
        unique_mount_id: u64,
        o_path: bool,
        directory: bool,
        read_only: bool,
    ) -> Result<Self, SourceProviderVerificationError> {
        require_nonzero("source-root boot ID", &kernel_boot_id)?;
        require_generation("source-root device", device)?;
        require_generation("source-root inode", inode)?;
        require_generation("source-root mount ID", unique_mount_id)?;
        if !o_path || !directory || !read_only {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        Ok(Self {
            kernel_boot_id,
            device,
            inode,
            unique_mount_id,
            o_path,
            directory,
            read_only,
        })
    }
}

/// Commits the exact supplied completed-Acquire descriptor observation.
#[must_use]
pub fn source_root_descriptor_commitment_v1(observation: &SourceRootObservationV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-source-provider-descriptor-set-v1\0");
    hasher.update(1u32.to_be_bytes());
    hasher.update([SourceProviderDescriptorRole::SourceRoot as u8]);
    hasher.update([0; 7]);
    hasher.update(observation.kernel_boot_id);
    hasher.update(observation.device.to_be_bytes());
    hasher.update(observation.inode.to_be_bytes());
    hasher.update(observation.unique_mount_id.to_be_bytes());
    hasher.update([u8::from(observation.o_path)
        | (u8::from(observation.directory) << 1)
        | (u8::from(observation.read_only) << 2)]);
    hasher.update([0; 7]);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Proves both direction-local sequence numbers were verified exactly.
///
/// This evidence does not advance or persist either sequence. The caller must
/// perform the required atomic durable compare-and-swap before descriptor use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceProviderSequenceV1 {
    session_binding: ObjectDigest,
    request_sequence: u64,
    response_sequence: u64,
}

impl VerifiedSourceProviderSequenceV1 {
    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }
    /// Returns the verified client request sequence without advancing state.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }
    /// Returns the verified provider response sequence without advancing state.
    #[must_use]
    pub const fn response_sequence(&self) -> u64 {
        self.response_sequence
    }
}

/// Carries a nonconstructible cryptographically verified provider disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceProviderDispositionV1<T> {
    status: SourceProviderStatus,
    result: Option<T>,
    sequence: VerifiedSourceProviderSequenceV1,
}

impl<T> VerifiedSourceProviderDispositionV1<T> {
    /// Returns the authenticated provider status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.status
    }

    /// Returns the opaque completed result, if the authenticated status is Complete.
    #[must_use]
    pub const fn result(&self) -> Option<&T> {
        self.result.as_ref()
    }

    /// Returns the opaque sequencing evidence for caller-owned advancement.
    #[must_use]
    pub const fn sequence(&self) -> &VerifiedSourceProviderSequenceV1 {
        &self.sequence
    }
}

/// Carries one verified Acquire graph over a supplied descriptor observation.
///
/// A future branded kernel adapter must establish the observation's provenance
/// before this result is sufficient for production Mount admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceAcquisitionV1 {
    signed_lease: SignedSourceExportLeaseV1,
    lease_digest: ObjectDigest,
    provider_resource_commitment: ObjectDigest,
    observation: SourceRootObservationV1,
}

impl VerifiedSourceAcquisitionV1 {
    /// Returns the exact signed provider export lease.
    #[must_use]
    pub const fn signed_lease(&self) -> &SignedSourceExportLeaseV1 {
        &self.signed_lease
    }

    /// Returns the digest of the exact signed lease envelope.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the Stage-1-compatible provider resource/proof commitment.
    #[must_use]
    pub const fn provider_resource_commitment(&self) -> ObjectDigest {
        self.provider_resource_commitment
    }

    /// Returns the exact supplied source-root observation fields.
    #[must_use]
    pub const fn observation(&self) -> &SourceRootObservationV1 {
        &self.observation
    }
}

/// Carries one fully verified terminal provider release result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceReleaseV1 {
    lease_digest: ObjectDigest,
    release_generation: u64,
}

impl VerifiedSourceReleaseV1 {
    /// Returns the released exact signed-lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the provider's monotonic release generation.
    #[must_use]
    pub const fn release_generation(&self) -> u64 {
        self.release_generation
    }
}

/// Carries one fully verified provider inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceInventoryV1 {
    signed_inventory: SignedSourceProviderInventoryV1,
}

impl VerifiedSourceInventoryV1 {
    /// Returns the exact verified signed inventory.
    #[must_use]
    pub const fn signed_inventory(&self) -> &SignedSourceProviderInventoryV1 {
        &self.signed_inventory
    }
}

/// Verifies one complete Acquire query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, lease, capability, receipt, descriptor, or
/// cross-object mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_acquire(
    signed_request: &SignedSourceProviderRequestV1,
    response: &AcquireSourceResponseV1,
    session: &SourceProviderSessionV1,
    root_mount_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
    observation: Option<SourceRootObservationV1>,
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Acquire)?;
    verify_request(signed_request, root_mount_trust)?;
    let request = decode_acquire_request(signed_request.subject())?;
    verify_current_session(
        session,
        signed_request,
        root_mount_trust,
        provider_trust,
        route,
        context,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_acquire_bounds(&request, context)?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::AcquireResponse(response.clone()),
        descriptor_roles,
    )?;
    let descriptor_commitment = match (response.status(), observation.as_ref()) {
        (SourceProviderStatus::Complete, Some(observation)) => {
            source_root_descriptor_commitment_v1(observation)
        }
        (SourceProviderStatus::Complete, None) => {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        (_, None) => empty_descriptor_set_commitment_v1(),
        (_, Some(_)) => return Err(SourceProviderVerificationError::CrossLink),
    };
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_receipt(),
        request.request_id(),
        session,
        provider_trust,
        context,
        descriptor_commitment,
    )?;
    if response.status() != SourceProviderStatus::Complete {
        if observation.is_some() {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        return disposition(response.status(), None, sequence);
    }

    let observation = observation.ok_or(SourceProviderVerificationError::CrossLink)?;
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(
        response
            .signed_receipt()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    provider_trust.verify_signer(signed_receipt.signer())?;
    verify_provider_receipt(&signed_receipt, provider_trust.public_key())?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())?;
    provider_trust.verify_signer(signed_lease.signer())?;
    let lease = signed_lease.subject();

    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_acquire_request(&request)
        || receipt.acquisition_id() != request.acquisition_id()
        || receipt.provider_process_instance() != session.provider_hello().process_instance()
        || receipt.kernel_boot_id() != observation.kernel_boot_id
        || observation.kernel_boot_id != request.boot_id()
        || receipt.device() != observation.device
        || receipt.inode() != observation.inode
        || receipt.unique_mount_id() != observation.unique_mount_id
        || !observation.directory
        || !observation.o_path
        || !observation.read_only
        || lease.request_id() != request.request_id()
        || lease.request_digest() != digest_acquire_request(&request)
        || lease.holder_authority_id() != request.holder_authority_id()
        || lease.holder_generation() != request.holder_generation()
        || lease.holder_authority_digest() != request.holder_authority_digest()
        || lease.binding_digest() != request.binding_digest()
        || lease.revocation_digest() != request.revocation_digest()
        || matches!(
            lease.proof(),
            SourceProviderProofV1::LocalLiveExport { proof, .. }
                if proof.consumer_authority_id() != request.holder_authority_id()
                    || proof.consumer_generation() != request.holder_generation()
        )
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    verify_provider_selection(lease, &request, session, provider_trust, route, context)?;
    let lease_digest = digest_signed_export_lease(&signed_lease);
    if receipt.lease_digest() != lease_digest {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    let proof_digest = digest_provider_proof(lease.proof());
    if receipt.observed_proof_digest() != proof_digest {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    let provider_resource_commitment =
        provider_resource_commitment_v1(lease.resource(), proof_digest);
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceAcquisitionV1 {
            signed_lease,
            lease_digest,
            provider_resource_commitment,
            observation,
        }),
        sequence,
    })
}

/// Verifies one complete Release query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, receipt, descriptor, or cross-object mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_release(
    signed_request: &SignedSourceProviderRequestV1,
    response: &ReleaseSourceResponseV1,
    session: &SourceProviderSessionV1,
    root_mount_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceReleaseV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Release)?;
    verify_request(signed_request, root_mount_trust)?;
    let request = decode_release_request(signed_request.subject())?;
    verify_current_session(
        session,
        signed_request,
        root_mount_trust,
        provider_trust,
        route,
        context,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::ReleaseResponse(response.clone()),
        descriptor_roles,
    )?;
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_receipt(),
        request.request_id(),
        session,
        provider_trust,
        context,
        empty_descriptor_set_commitment_v1(),
    )?;
    if response.status() != SourceProviderStatus::Complete {
        return disposition(response.status(), None, sequence);
    }
    let signed_receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(
        response
            .signed_receipt()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    provider_trust.verify_signer(signed_receipt.signer())?;
    verify_release_receipt(&signed_receipt, provider_trust.public_key())?;
    let receipt = signed_receipt.subject();
    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_release_request(&request)
        || receipt.lease_id() != request.lease_id()
        || receipt.lease_digest() != request.lease_digest()
        || receipt.provider_process_instance() != session.provider_hello().process_instance()
        || receipt.released_seconds() > context.now_seconds
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceReleaseV1 {
            lease_digest: receipt.lease_digest(),
            release_generation: receipt.release_generation(),
        }),
        sequence,
    })
}

/// Verifies one complete Inventory query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, snapshot, descriptor, rollback, or cross-object
/// mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_source_inventory(
    signed_request: &SignedSourceProviderRequestV1,
    response: &InventorySourceResponseV1,
    session: &SourceProviderSessionV1,
    root_mount_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Inventory)?;
    verify_request(signed_request, root_mount_trust)?;
    let request = decode_inventory_request(signed_request.subject())?;
    verify_current_session(
        session,
        signed_request,
        root_mount_trust,
        provider_trust,
        route,
        context,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::InventoryResponse(response.clone()),
        descriptor_roles,
    )?;
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_inventory(),
        request.request_id(),
        session,
        provider_trust,
        context,
        empty_descriptor_set_commitment_v1(),
    )?;
    if response.status() != SourceProviderStatus::Complete {
        return disposition(response.status(), None, sequence);
    }
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(
        response
            .signed_inventory()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    provider_trust.verify_signer(signed_inventory.signer())?;
    verify_inventory(&signed_inventory, provider_trust.public_key())?;
    let inventory = signed_inventory.subject();
    if inventory.request_id() != request.request_id()
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != request.holder_authority_id()
        || inventory.holder_generation() != request.holder_generation()
        || inventory.holder_authority_digest() != request.holder_authority_digest()
        || inventory.provider_process_instance() != session.provider_hello().process_instance()
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    if below_floor_or_equivocates(
        inventory.catalog_generation(),
        inventory.catalog_digest(),
        provider_trust.minimum_catalog_generation(),
        provider_trust.minimum_catalog_digest(),
    ) {
        return Err(SourceProviderVerificationError::Rollback);
    }
    for entry in inventory.entries() {
        let resource = entry.resource();
        if resource.resource_namespace_digest() != route.resource_namespace_digest()
            || resource.catalog_generation() != inventory.catalog_generation()
            || resource.catalog_digest() != inventory.catalog_digest()
            || resource_below_floor_or_equivocates(resource, provider_trust)
            || below_floor_or_equivocates(
                resource.selection_generation(),
                resource.selection_digest(),
                provider_trust.minimum_selection_generation(),
                provider_trust.minimum_selection_digest(),
            )
            || entry.proof_class() == 0
            || entry.proof_class() > 4
            || (1 << (entry.proof_class() - 1)) & route.proof_capabilities() == 0
            || (1 << (entry.proof_class() - 1)) & provider_trust.proof_class_capabilities() == 0
            || (1 << (entry.proof_class() - 1))
                & session.provider_hello().proof_class_capabilities()
                == 0
            || entry.resource_commitment()
                != provider_resource_commitment_v1(resource, entry.proof_digest())
        {
            return Err(SourceProviderVerificationError::Rollback);
        }
    }
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceInventoryV1 { signed_inventory }),
        sequence,
    })
}

fn verify_current_session(
    session: &SourceProviderSessionV1,
    signed_request: &SignedSourceProviderRequestV1,
    root_mount_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    verify_hello(session.signed_root_mount_hello(), root_mount_trust)?;
    verify_hello(session.signed_provider_hello(), provider_trust)?;
    route.verify_trust(provider_trust)?;
    let root_hello = session.root_mount_hello();
    let provider_hello = session.provider_hello();
    if session.route() != route
        || session.signed_root_mount_hello().signer() != signed_request.signer()
        || root_hello.expected_peer_signer() != session.signed_provider_hello().signer()
        || provider_hello.expected_peer_signer() != signed_request.signer()
        || root_hello.kernel_boot_id() != context.boot_id
        || provider_hello.kernel_boot_id() != context.boot_id
        || provider_hello.proof_class_capabilities() & route.proof_capabilities() == 0
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn verify_request_session(
    binding: ObjectDigest,
    sequence: u64,
    session: &SourceProviderSessionV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    if binding != session.binding() || sequence != context.expected_request_sequence {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_outer_status(
    signed_request: &SignedSourceProviderRequestV1,
    signed_status: &SignedSourceProviderStatusV1,
    result: Option<&[u8]>,
    request_id: [u8; 16],
    session: &SourceProviderSessionV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_commitment: ObjectDigest,
) -> Result<VerifiedSourceProviderSequenceV1, SourceProviderVerificationError> {
    verify_response_status(signed_status, provider_trust)?;
    let status = signed_status.subject();
    if status.method() != signed_request.method()
        || status.request_id() != request_id
        || status.signed_request_digest() != digest_signed_request(signed_request)
        || status.provider_process_instance() != session.provider_hello().process_instance()
        || status.session_binding() != session.binding()
        || status.response_sequence() != context.expected_response_sequence
        || status.result_digest()
            != response_result_digest_v1(status.method(), status.status(), result)
        || status.descriptor_commitment() != descriptor_commitment
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(VerifiedSourceProviderSequenceV1 {
        session_binding: session.binding(),
        request_sequence: context.expected_request_sequence,
        response_sequence: context.expected_response_sequence,
    })
}

fn verify_acquire_bounds(
    request: &AcquireSourceRequestV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    if request.node_id() != context.node_id
        || request.boot_id() != context.boot_id
        || request.revocation_digest() != context.revocation_digest
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    Ok(())
}

fn verify_request_bounds(
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    deadline_seconds: i64,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    if holder_authority_id != context.holder_authority_id
        || holder_generation != context.holder_generation
        || holder_authority_digest != context.holder_authority_digest
        || context.now_seconds >= deadline_seconds
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    Ok(())
}

fn verify_provider_selection(
    lease: &crate::model::SourceExportLeaseV1,
    request: &AcquireSourceRequestV1,
    session: &SourceProviderSessionV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    let provider_hello = session.provider_hello();
    let resource = lease.resource();
    let proof = lease.proof();
    let duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or(SourceProviderVerificationError::Bounds)?;
    if lease.issued_seconds() > context.now_seconds
        || context.now_seconds >= lease.expires_seconds()
        || lease.expires_seconds() > request.deadline_seconds()
        || lease.expires_seconds() > context.maximum_lease_expiry_seconds
        || duration == 0
        || duration > request.requested_lease_seconds()
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    if resource.resource_namespace_digest() != route.resource_namespace_digest()
        || below_floor_or_equivocates(
            resource.catalog_generation(),
            resource.catalog_digest(),
            provider_trust.minimum_catalog_generation(),
            provider_trust.minimum_catalog_digest(),
        )
        || resource_below_floor_or_equivocates(resource, provider_trust)
        || below_floor_or_equivocates(
            resource.selection_generation(),
            resource.selection_digest(),
            provider_trust.minimum_selection_generation(),
            provider_trust.minimum_selection_digest(),
        )
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    let proof_bit = proof.capability_bit();
    if proof_bit & provider_trust.proof_class_capabilities() == 0
        || proof_bit & route.proof_capabilities() == 0
        || proof_bit & provider_hello.proof_class_capabilities() == 0
        || proof.requires_kernel_coupled() != request.kernel_coupled()
        || (request.kernel_coupled()
            && (!provider_hello.supports_kernel_coupled() || !route.allows_kernel_coupled()))
        || (request.recursive()
            && (!provider_hello.supports_recursive() || !route.allows_recursive()))
        || proof.topology().observed_submounts() > request.requested_maximum_submounts()
        || (!request.recursive() && proof.topology().observed_submounts() != 0)
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn below_floor_or_equivocates(
    generation: u64,
    digest: ObjectDigest,
    floor_generation: u64,
    floor_digest: ObjectDigest,
) -> bool {
    generation < floor_generation || (generation == floor_generation && digest != floor_digest)
}

fn resource_below_floor_or_equivocates(
    resource: &crate::model::SourceResourceV1,
    trust: &SourceProviderTrustAnchorV1,
) -> bool {
    resource.resource_generation() < trust.minimum_resource_generation()
        || (resource.resource_generation() == trust.minimum_resource_generation()
            && (resource.resource_id() != trust.minimum_resource_id()
                || resource.resource_digest() != trust.minimum_resource_digest()))
}

fn require_method(
    request: &SignedSourceProviderRequestV1,
    expected: SourceProviderMethod,
) -> Result<(), SourceProviderVerificationError> {
    if request.method() != expected {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn disposition<T>(
    status: SourceProviderStatus,
    complete: Option<T>,
    sequence: VerifiedSourceProviderSequenceV1,
) -> Result<VerifiedSourceProviderDispositionV1<T>, SourceProviderVerificationError> {
    match (status, complete) {
        (SourceProviderStatus::Complete, Some(value)) => Ok(VerifiedSourceProviderDispositionV1 {
            status,
            result: Some(value),
            sequence,
        }),
        (
            SourceProviderStatus::Pending
            | SourceProviderStatus::Rejected
            | SourceProviderStatus::Unavailable,
            None,
        ) => Ok(VerifiedSourceProviderDispositionV1 {
            status,
            result: None,
            sequence,
        }),
        _ => Err(SourceProviderVerificationError::CrossLink),
    }
}
