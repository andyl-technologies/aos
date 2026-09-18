//! Independent SourceProvider 1.0 wire, signature, and authority-graph vectors.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

const NOW: i64 = 1_800_000_100;
const DEADLINE: i64 = 1_800_001_000;
const LEASE_ISSUED: i64 = 1_800_000_000;
const LEASE_EXPIRES: i64 = 1_800_000_500;

#[derive(Clone, Debug)]
struct SourceProviderTrustAnchorV1 {
    signer: SourceProviderSigningKeyV1,
    public_key: [u8; 32],
    proof_capabilities: u8,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    resource_generation: u64,
    resource_id: [u8; 32],
    resource_digest: ObjectDigest,
    selection_generation: u64,
    selection_digest: ObjectDigest,
    revoked: bool,
    superseded: Option<u64>,
}

impl SourceProviderTrustAnchorV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        public_key: [u8; 32],
        usage: SourceProviderKeyUsageV1,
        proof_capabilities: u8,
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        catalog_generation: u64,
        catalog_digest: ObjectDigest,
        resource_generation: u64,
        resource_id: [u8; 32],
        resource_digest: ObjectDigest,
        selection_generation: u64,
        selection_digest: ObjectDigest,
        revoked: bool,
        superseded: Option<u64>,
    ) -> Result<Self, SourceProviderTrustError> {
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SourceProviderTrustError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(SourceProviderTrustError::InvalidPublicKey);
        }
        if superseded.is_some_and(|generation| generation <= key_generation) {
            return Err(SourceProviderTrustError::InactiveKey);
        }
        let public_key_digest = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
        let signer = SourceProviderSigningKeyV1::new(
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
            usage,
        )?;

        Ok(Self {
            signer,
            public_key,
            proof_capabilities,
            route_id,
            route_generation,
            route_digest,
            catalog_generation,
            catalog_digest,
            resource_generation,
            resource_id,
            resource_digest,
            selection_generation,
            selection_digest,
            revoked,
            superseded,
        })
    }
}

struct FixtureTrust {
    trust_set: SourceProviderTrustSetV1,
    root_current: SourceProviderCurrentAuthorityV1,
    provider_current: SourceProviderCurrentAuthorityV1,
    catalog_floor: ProviderCatalogFloorV1,
}

fn digest(byte: u8) -> ObjectDigest {
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

fn root_signer(key: &SigningKey) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        [31; 16],
        32,
        digest(33),
        [34; 16],
        35,
        SourceProviderKeyUsageV1::RootMountRecord,
        key,
    )
    .unwrap_or_else(|error| panic!("Root Mount signer: {error}"))
}

fn provider_signer(key: &SigningKey) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        [7; 16],
        8,
        digest(9),
        [10; 16],
        11,
        SourceProviderKeyUsageV1::ProviderOutcome,
        key,
    )
    .unwrap_or_else(|error| panic!("provider signer: {error}"))
}

fn provider_authority(key: &SigningKey) -> SourceProviderAuthorityV1 {
    let signer = provider_signer(key);
    SourceProviderAuthorityV1::new(
        signer.authority_id(),
        signer.authority_generation(),
        signer.authority_digest(),
    )
    .unwrap_or_else(|error| panic!("provider authority: {error}"))
}

fn trust_anchor(
    signer: &SourceProviderSigningKeyV1,
    key: &SigningKey,
    proof_capabilities: u8,
    revoked: bool,
    superseded: Option<u64>,
) -> SourceProviderTrustAnchorV1 {
    SourceProviderTrustAnchorV1::new(
        signer.authority_id(),
        signer.authority_generation(),
        signer.authority_digest(),
        signer.key_id(),
        signer.key_generation(),
        *key.verifying_key().as_bytes(),
        signer.usage(),
        proof_capabilities,
        [70; 16],
        71,
        digest(72),
        1,
        digest(201),
        1,
        [24; 32],
        digest(26),
        1,
        digest(202),
        revoked,
        superseded,
    )
    .unwrap_or_else(|error| panic!("trust anchor: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn provider_trust_at_floors(
    key: &SigningKey,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    resource_generation: u64,
    resource_id: [u8; 32],
    resource_digest: ObjectDigest,
    selection_generation: u64,
    selection_digest: ObjectDigest,
) -> SourceProviderTrustAnchorV1 {
    let signer = provider_signer(key);
    SourceProviderTrustAnchorV1::new(
        signer.authority_id(),
        signer.authority_generation(),
        signer.authority_digest(),
        signer.key_id(),
        signer.key_generation(),
        *key.verifying_key().as_bytes(),
        signer.usage(),
        ALL_PROOF_CLASS_CAPABILITIES,
        [70; 16],
        71,
        digest(72),
        catalog_generation,
        catalog_digest,
        resource_generation,
        resource_id,
        resource_digest,
        selection_generation,
        selection_digest,
        false,
        None,
    )
    .unwrap_or_else(|error| panic!("provider floor trust: {error}"))
}

fn route() -> ProtectedSourceProviderRouteV1 {
    route_with([70; 16], 71, digest(72), [7; 16], digest(23))
}

fn route_with(
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    provider_authority_id: [u8; 16],
    resource_namespace_digest: ObjectDigest,
) -> ProtectedSourceProviderRouteV1 {
    ProtectedSourceProviderRouteV1::new(
        route_id,
        route_generation,
        route_digest,
        provider_authority_id,
        resource_namespace_digest,
        ALL_PROOF_CLASS_CAPABILITIES,
        true,
        true,
        1000,
        1001,
        digest(73),
    )
    .unwrap_or_else(|error| panic!("route: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn provider_trust_with_identity_and_route(
    key: &SigningKey,
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
) -> SourceProviderTrustAnchorV1 {
    SourceProviderTrustAnchorV1::new(
        authority_id,
        authority_generation,
        authority_digest,
        key_id,
        key_generation,
        *key.verifying_key().as_bytes(),
        SourceProviderKeyUsageV1::ProviderOutcome,
        ALL_PROOF_CLASS_CAPABILITIES,
        route_id,
        route_generation,
        route_digest,
        1,
        digest(201),
        1,
        [24; 32],
        digest(26),
        1,
        digest(202),
        false,
        None,
    )
    .unwrap_or_else(|error| panic!("current provider trust: {error}"))
}

fn hello_signer(
    anchor: &SourceProviderTrustAnchorV1,
    role: SourceProviderPeerRole,
) -> (SigningKey, SourceProviderSigningKeyV1) {
    let (key_bytes, key_id, key_generation, usage) = match role {
        SourceProviderPeerRole::RootMount => (
            [49; 32],
            [36; 16],
            37,
            SourceProviderKeyUsageV1::RootMountHello,
        ),
        SourceProviderPeerRole::Provider => (
            [41; 32],
            [12; 16],
            13,
            SourceProviderKeyUsageV1::ProviderHello,
        ),
    };
    let key = SigningKey::from_bytes(&key_bytes);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        anchor.signer.authority_id(),
        anchor.signer.authority_generation(),
        anchor.signer.authority_digest(),
        key_id,
        key_generation,
        usage,
        &key,
    )
    .unwrap_or_else(|error| panic!("hello signer: {error}"));

    (key, signer)
}

fn fixture_trust(
    root: &SourceProviderTrustAnchorV1,
    provider: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
) -> Result<FixtureTrust, SourceProviderTrustError> {
    let route_matches = |anchor: &SourceProviderTrustAnchorV1| {
        anchor.route_id == current_route.route_id()
            && anchor.route_generation == current_route.route_generation()
            && anchor.route_digest == current_route.route_digest()
    };
    if !route_matches(root)
        || !route_matches(provider)
        || provider.signer.authority_id() != current_route.provider_authority_id()
    {
        return Err(SourceProviderTrustError::RouteMismatch);
    }

    let (root_hello_key, root_hello_signer) = hello_signer(root, SourceProviderPeerRole::RootMount);
    let (provider_hello_key, provider_hello_signer) =
        hello_signer(provider, SourceProviderPeerRole::Provider);

    let root_authority = SourceProviderAuthorityV1::new(
        root.signer.authority_id(),
        root.signer.authority_generation(),
        root.signer.authority_digest(),
    )?;
    let provider_authority = SourceProviderAuthorityV1::new(
        provider.signer.authority_id(),
        provider.signer.authority_generation(),
        provider.signer.authority_digest(),
    )?;
    let mut authorities = vec![
        SourceProviderAuthorityTrustV1::new(
            root_authority.clone(),
            0,
            i64::MAX,
            SourceProviderAuthorityTrustStateV1::Trusted,
        )?,
        SourceProviderAuthorityTrustV1::new(
            provider_authority.clone(),
            0,
            i64::MAX,
            SourceProviderAuthorityTrustStateV1::Trusted,
        )?,
    ];
    authorities.sort_by_key(|entry| {
        (
            entry.authority().authority_id(),
            entry.authority().authority_generation(),
        )
    });

    let traffic_state = |anchor: &SourceProviderTrustAnchorV1| {
        if anchor.revoked {
            SourceProviderKeyTrustStateV1::Revoked
        } else if anchor.superseded.is_some() {
            SourceProviderKeyTrustStateV1::Superseded
        } else {
            SourceProviderKeyTrustStateV1::Eligible
        }
    };
    let mut keys = vec![
        SourceProviderKeyTrustV1::new(
            root_hello_signer.clone(),
            *root_hello_key.verifying_key().as_bytes(),
            0,
            i64::MAX,
            SourceProviderKeyTrustStateV1::Eligible,
            0,
        )?,
        SourceProviderKeyTrustV1::new(
            root.signer.clone(),
            root.public_key,
            0,
            i64::MAX,
            traffic_state(root),
            root.superseded.unwrap_or(0),
        )?,
        SourceProviderKeyTrustV1::new(
            provider_hello_signer.clone(),
            *provider_hello_key.verifying_key().as_bytes(),
            0,
            i64::MAX,
            SourceProviderKeyTrustStateV1::Eligible,
            0,
        )?,
        SourceProviderKeyTrustV1::new(
            provider.signer.clone(),
            provider.public_key,
            0,
            i64::MAX,
            traffic_state(provider),
            provider.superseded.unwrap_or(0),
        )?,
    ];
    keys.sort_by_key(|entry| {
        let signer = entry.signer();
        (
            signer.authority_id(),
            signer.authority_generation(),
            signer.usage() as u8,
            signer.key_id(),
            signer.key_generation(),
        )
    });

    let trust_generation = 1;
    let revocation_generation = 1;
    let revocation_digest = digest(204);
    let trust_digest = source_provider_trust_set_digest_v1(
        trust_generation,
        revocation_generation,
        revocation_digest,
        &authorities,
        &keys,
    );
    let trust_set = SourceProviderTrustSetV1::new(
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
        authorities,
        keys,
    )?;
    let root_current = SourceProviderCurrentAuthorityV1::new(
        SourceProviderPeerRole::RootMount,
        root_authority,
        root_hello_signer,
        root.signer.clone(),
        ALL_PROOF_CLASS_CAPABILITIES,
        current_route,
        &trust_set,
    )?;
    let provider_current = SourceProviderCurrentAuthorityV1::new(
        SourceProviderPeerRole::Provider,
        provider_authority,
        provider_hello_signer,
        provider.signer.clone(),
        provider.proof_capabilities,
        current_route,
        &trust_set,
    )?;
    let catalog_floor = ProviderCatalogFloorV1::new(
        provider.signer.authority_id(),
        current_route.resource_namespace_digest(),
        provider.catalog_generation,
        provider.catalog_digest,
    )?;

    Ok(FixtureTrust {
        trust_set,
        root_current,
        provider_current,
        catalog_floor,
    })
}

fn verify_hello(
    value: &SignedSourceProviderHelloV1,
    trust: &SourceProviderTrustAnchorV1,
) -> Result<(), SourceProviderSignatureError> {
    if trust.revoked || trust.superseded.is_some() || value.signer() != &trust.signer {
        return Err(SourceProviderSignatureError::SignerMismatch);
    }

    aos_sandbox_source_provider_protocol::verify_hello(value, &trust.public_key)
}

fn verify_request(
    value: &SignedSourceProviderRequestV1,
    trust: &SourceProviderTrustAnchorV1,
) -> Result<(), SourceProviderSignatureError> {
    if trust.revoked || trust.superseded.is_some() || value.signer() != &trust.signer {
        return Err(SourceProviderSignatureError::SignerMismatch);
    }

    aos_sandbox_source_provider_protocol::verify_request(value, &trust.public_key)
}

#[allow(clippy::too_many_arguments)]
fn authenticate_session(
    expected_client_nonce: [u8; 32],
    root_mount_hello: SignedSourceProviderHelloV1,
    provider_hello: SignedSourceProviderHelloV1,
    root_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    connection_peer: SourceProviderProcessIdentityV1,
    nominated_record_subject: SourceProviderProcessIdentityV1,
    current_route: &ProtectedSourceProviderRouteV1,
) -> Result<SourceProviderSessionV1, SourceProviderTrustError> {
    let trust = fixture_trust(root_trust, provider_trust, current_route)?;

    SourceProviderSessionV1::authenticate(
        expected_client_nonce,
        NOW,
        root_mount_hello,
        provider_hello,
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        connection_peer,
        nominated_record_subject,
        current_route,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_acquire(
    signed_request: &SignedSourceProviderRequestV1,
    response: &AcquireSourceResponseV1,
    session: &SourceProviderSessionV1,
    root_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
    observation: Option<SourceRootObservationV1>,
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
    SourceProviderVerificationError,
> {
    let trust = fixture_trust(root_trust, provider_trust, current_route)?;
    let verified = aos_sandbox_source_provider_protocol::verify_acquire(
        signed_request,
        response,
        session,
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        current_route,
        &trust.catalog_floor,
        None,
        context,
        descriptor_roles,
        observation,
    )?;

    if let Some(acquisition) = verified.result() {
        let resource = acquisition.selection_floor().resource();
        let below_resource_floor = resource.resource_generation()
            < provider_trust.resource_generation
            || (resource.resource_generation() == provider_trust.resource_generation
                && (resource.resource_id() != provider_trust.resource_id
                    || resource.resource_digest() != provider_trust.resource_digest));
        let below_selection_floor = resource.selection_generation()
            < provider_trust.selection_generation
            || (resource.selection_generation() == provider_trust.selection_generation
                && resource.selection_digest() != provider_trust.selection_digest);
        if below_resource_floor || below_selection_floor {
            return Err(SourceProviderVerificationError::Rollback);
        }
    }

    Ok(verified)
}

fn release_selection_floor(
    signed_request: &SignedSourceProviderRequestV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
    trust_set: &SourceProviderTrustSetV1,
) -> Result<SourceSelectionFloorV1, SourceProviderVerificationError> {
    let request = decode_release_request(signed_request.subject())?;
    let resource = SourceResourceV1::new(
        current_route.resource_namespace_digest(),
        provider_trust.resource_id,
        provider_trust.resource_generation,
        provider_trust.resource_digest,
        provider_trust.catalog_generation,
        provider_trust.catalog_digest,
        provider_trust.selection_generation,
        provider_trust.selection_digest,
    )?;

    Ok(SourceSelectionFloorV1::new(
        request.acquisition_id(),
        provider_trust.signer.authority_id(),
        current_route.route_id(),
        resource,
        provider_trust.signer.clone(),
        request.lease_id(),
        request.lease_digest(),
        1,
        digest(205),
        digest(206),
        trust_set.trust_generation(),
        trust_set.trust_digest(),
        trust_set.revocation_generation(),
        trust_set.revocation_digest(),
    )?)
}

#[allow(clippy::too_many_arguments)]
fn verify_release(
    signed_request: &SignedSourceProviderRequestV1,
    response: &ReleaseSourceResponseV1,
    session: &SourceProviderSessionV1,
    root_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceReleaseV1>,
    SourceProviderVerificationError,
> {
    let trust = fixture_trust(root_trust, provider_trust, current_route)?;
    let selection_floor = release_selection_floor(
        signed_request,
        provider_trust,
        current_route,
        &trust.trust_set,
    )?;

    aos_sandbox_source_provider_protocol::verify_release(
        signed_request,
        response,
        session,
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        current_route,
        &selection_floor,
        context,
        descriptor_roles,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_source_inventory(
    signed_request: &SignedSourceProviderRequestV1,
    response: &InventorySourceResponseV1,
    session: &SourceProviderSessionV1,
    root_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
    SourceProviderVerificationError,
> {
    let trust = fixture_trust(root_trust, provider_trust, current_route)?;

    let verified = aos_sandbox_source_provider_protocol::verify_source_inventory(
        signed_request,
        response,
        session,
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        current_route,
        &trust.catalog_floor,
        &[],
        context,
        descriptor_roles,
    )?;

    if let Some(inventory) = verified.result() {
        for entry in inventory.signed_inventory().subject().entries() {
            let resource = entry.resource();
            let below_resource_floor = resource.resource_generation()
                < provider_trust.resource_generation
                || (resource.resource_generation() == provider_trust.resource_generation
                    && (resource.resource_id() != provider_trust.resource_id
                        || resource.resource_digest() != provider_trust.resource_digest));
            let below_selection_floor = resource.selection_generation()
                < provider_trust.selection_generation
                || (resource.selection_generation() == provider_trust.selection_generation
                    && resource.selection_digest() != provider_trust.selection_digest);
            if below_resource_floor || below_selection_floor {
                return Err(SourceProviderVerificationError::Rollback);
            }
        }
    }

    Ok(verified)
}

fn process_identity(
    tgid: u32,
    start_time: u64,
    cgroup: ObjectDigest,
) -> SourceProviderProcessIdentityV1 {
    SourceProviderProcessIdentityV1::new(1000, 1001, tgid, start_time, cgroup, true)
        .unwrap_or_else(|error| panic!("process identity: {error}"))
}

fn session(process_instance: [u8; 16]) -> SourceProviderSessionV1 {
    session_with(
        [53; 32],
        [54; 32],
        [5; 16],
        [5; 16],
        ALL_PROOF_CLASS_CAPABILITIES,
        ALL_PROOF_CLASS_CAPABILITIES,
        process_instance,
    )
    .unwrap_or_else(|error| panic!("session: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn session_with(
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    client_boot: [u8; 16],
    server_boot: [u8; 16],
    requested_proofs: u8,
    advertised_proofs: u8,
    process_instance: [u8; 16],
) -> Result<SourceProviderSessionV1, SourceProviderTrustError> {
    session_with_options(
        client_nonce,
        server_nonce,
        client_boot,
        server_boot,
        requested_proofs,
        advertised_proofs,
        true,
        true,
        true,
        true,
        process_instance,
    )
}

#[allow(clippy::too_many_arguments)]
fn session_with_options(
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    client_boot: [u8; 16],
    server_boot: [u8; 16],
    requested_proofs: u8,
    advertised_proofs: u8,
    requested_recursive: bool,
    advertised_recursive: bool,
    requested_kernel_coupled: bool,
    advertised_kernel_coupled: bool,
    process_instance: [u8; 16],
) -> Result<SourceProviderSessionV1, SourceProviderTrustError> {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let root_signer = root_signer(&root_key);
    let provider_signer = provider_signer(&provider_key);
    let root_trust = trust_anchor(&root_signer, &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer,
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );
    let current_route = route();
    let trust = fixture_trust(&root_trust, &provider_trust, &current_route)?;
    let (root_hello_key, root_hello_signer) =
        hello_signer(&root_trust, SourceProviderPeerRole::RootMount);
    let (provider_hello_key, provider_hello_signer) =
        hello_signer(&provider_trust, SourceProviderPeerRole::Provider);
    let root_hello = SourceProviderHelloV1::new(
        SourceProviderPeerRole::RootMount,
        client_nonce,
        [51; 16],
        client_boot,
        root_signer.clone(),
        provider_signer.clone(),
        [70; 16],
        71,
        digest(72),
        None,
        requested_proofs,
        requested_recursive,
        requested_kernel_coupled,
    )
    .unwrap_or_else(|error| panic!("root hello: {error}"));
    let signed_root_hello = sign_hello(root_hello, root_hello_signer, &root_hello_key)
        .unwrap_or_else(|error| panic!("signed root hello: {error}"));
    let provider_hello = SourceProviderHelloV1::new(
        SourceProviderPeerRole::Provider,
        server_nonce,
        process_instance,
        server_boot,
        provider_signer.clone(),
        root_signer.clone(),
        [70; 16],
        71,
        digest(72),
        Some(digest_signed_hello(&signed_root_hello)),
        advertised_proofs,
        advertised_recursive,
        advertised_kernel_coupled,
    )
    .unwrap_or_else(|error| panic!("provider hello: {error}"));
    let signed_provider_hello =
        sign_hello(provider_hello, provider_hello_signer, &provider_hello_key)
            .unwrap_or_else(|error| panic!("signed provider hello: {error}"));
    let identity = process_identity(4000, 5000, digest(73));

    SourceProviderSessionV1::authenticate(
        client_nonce,
        NOW,
        signed_root_hello,
        signed_provider_hello,
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        identity.clone(),
        identity,
        &current_route,
    )
}

fn topology(observed_submounts: u32) -> RecursiveTopologyProofV1 {
    RecursiveTopologyProofV1::new(
        [12; 16],
        13,
        digest(14),
        15,
        16,
        observed_submounts + 1,
        observed_submounts,
    )
    .unwrap_or_else(|error| panic!("topology: {error}"))
}

fn zfs_proof() -> SourceProviderProofV1 {
    SourceProviderProofV1::ZfsHeldSnapshot {
        proof: ZfsHeldSnapshotProofV1::new(
            [41; 32],
            42,
            43,
            44,
            45,
            [46; 16],
            47,
            digest(48),
            digest(49),
            digest(50),
        )
        .unwrap_or_else(|error| panic!("ZFS proof: {error}")),
        topology: topology(2),
    }
}

fn local_proof(export_generation: u64) -> SourceProviderProofV1 {
    local_proof_for_consumer(export_generation, [31; 16], 32)
}

fn local_proof_for_consumer(
    export_generation: u64,
    consumer_authority_id: [u8; 16],
    consumer_generation: u64,
) -> SourceProviderProofV1 {
    SourceProviderProofV1::LocalLiveExport {
        proof: LocalLiveExportProofV1::new(
            digest(61),
            [62; 16],
            [63; 16],
            [64; 16],
            export_generation,
            digest(66),
            digest(67),
            consumer_authority_id,
            consumer_generation,
            digest(68),
            [69; 32],
            digest(70),
        )
        .unwrap_or_else(|error| panic!("local proof: {error}")),
        topology: topology(2),
    }
}

fn immutable_proof() -> SourceProviderProofV1 {
    SourceProviderProofV1::ImmutablePublisherTree {
        proof: ImmutablePublisherTreeProofV1::new(
            digest(81),
            digest(82),
            83,
            digest(84),
            85,
            digest(86),
            [87; 32],
            88,
            digest(89),
            digest(90),
            digest(91),
            digest(92),
            digest(93),
        )
        .unwrap_or_else(|error| panic!("immutable proof: {error}")),
        topology: topology(2),
    }
}

fn replica_proof() -> SourceProviderProofV1 {
    SourceProviderProofV1::BestEffortReplica {
        proof: BestEffortReplicaProofV1::new(
            digest(101),
            [102; 32],
            103,
            digest(104),
            1_799_999_000,
            105,
            digest(106),
            200,
            100,
            digest(107),
            true,
        )
        .unwrap_or_else(|error| panic!("replica proof: {error}")),
        topology: topology(2),
    }
}

fn resource() -> SourceResourceV1 {
    SourceResourceV1::new(
        digest(23),
        [24; 32],
        25,
        digest(26),
        27,
        digest(28),
        29,
        digest(30),
    )
    .unwrap_or_else(|error| panic!("resource: {error}"))
}

fn acquire_with(
    request_id: [u8; 16],
    deadline: i64,
    requested_seconds: u64,
    recursive: bool,
    maximum_submounts: u32,
    kernel_coupled: bool,
) -> AcquireSourceRequestV1 {
    let template = mount_template();
    let template_digest = prospective_mount_apply_template_digest_v1(&template)
        .unwrap_or_else(|error| panic!("template: {error}"));
    let binding = b"binding-v1".to_vec();
    let binding_digest = digest_logical_binding_bytes(&binding);

    AcquireSourceRequestV1::new(
        session([52; 16]).binding(),
        1,
        request_id,
        digest(2),
        template,
        template_digest,
        SourceUseV1::MountCreate,
        [4; 16],
        [5; 16],
        [31; 16],
        32,
        digest(33),
        binding,
        binding_digest,
        deadline,
        requested_seconds,
        digest(90),
        recursive,
        maximum_submounts,
        kernel_coupled,
    )
    .unwrap_or_else(|error| panic!("Acquire request: {error}"))
}

fn acquire() -> AcquireSourceRequestV1 {
    acquire_with([1; 16], DEADLINE, 600, true, 4, true)
}

fn acquire_for_session(binding: ObjectDigest, sequence: u64) -> AcquireSourceRequestV1 {
    let original = acquire();
    AcquireSourceRequestV1::new(
        binding,
        sequence,
        original.request_id(),
        original.acquisition_id(),
        original.prospective_apply_template().to_vec(),
        original.prospective_apply_template_digest(),
        original.source_use(),
        original.node_id(),
        original.boot_id(),
        original.holder_authority_id(),
        original.holder_generation(),
        original.holder_authority_digest(),
        original.binding().to_vec(),
        original.binding_digest(),
        original.deadline_seconds(),
        original.requested_lease_seconds(),
        original.revocation_digest(),
        original.recursive(),
        original.requested_maximum_submounts(),
        original.kernel_coupled(),
    )
    .unwrap_or_else(|error| panic!("session-bound Acquire request: {error}"))
}

fn export_lease(
    key: &SigningKey,
    request: &AcquireSourceRequestV1,
    proof: SourceProviderProofV1,
    issued: i64,
    expires: i64,
) -> SourceExportLeaseV1 {
    SourceExportLeaseV1::new(
        [36; 16],
        request.request_id(),
        digest_acquire_request(request),
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        provider_authority(key),
        resource(),
        proof,
        request.binding_digest(),
        issued,
        expires,
        request.revocation_digest(),
    )
    .unwrap_or_else(|error| panic!("export lease: {error}"))
}

fn signed_request(
    request: &AcquireSourceRequestV1,
    key: &SigningKey,
) -> SignedSourceProviderRequestV1 {
    sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(request),
        root_signer(key),
        key,
    )
    .unwrap_or_else(|error| panic!("signed request: {error}"))
}

fn signed_status(
    request: &SignedSourceProviderRequestV1,
    request_id: [u8; 16],
    status: SourceProviderStatus,
    result: Option<&[u8]>,
    descriptor_commitment: ObjectDigest,
    key: &SigningKey,
) -> SignedSourceProviderStatusV1 {
    let subject = SourceProviderResponseStatusV1::new(
        request.method(),
        request_id,
        digest_signed_request(request),
        status,
        [52; 16],
        session([52; 16]).binding(),
        1,
        response_result_digest_v1(request.method(), status, result),
        descriptor_commitment,
    )
    .unwrap_or_else(|error| panic!("response status: {error}"));
    sign_response_status(subject, provider_signer(key), key)
        .unwrap_or_else(|error| panic!("signed response status: {error}"))
}

fn completed_acquire_response(
    request: &AcquireSourceRequestV1,
    lease: &SourceExportLeaseV1,
    root_observation: &SourceRootObservationV1,
    provider_process_instance: [u8; 16],
    key: &SigningKey,
) -> AcquireSourceResponseV1 {
    assert_eq!(root_observation, &observation());
    completed_acquire_response_with_kernel_facts(
        request,
        lease,
        provider_process_instance,
        [5; 16],
        38,
        39,
        40,
        key,
    )
}

#[allow(clippy::too_many_arguments)]
fn completed_acquire_response_with_kernel_facts(
    request: &AcquireSourceRequestV1,
    lease: &SourceExportLeaseV1,
    provider_process_instance: [u8; 16],
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    unique_mount_id: u64,
    key: &SigningKey,
) -> AcquireSourceResponseV1 {
    let signer = provider_signer(key);
    let signed_lease = sign_export_lease(lease.clone(), signer.clone(), key)
        .unwrap_or_else(|error| panic!("signed lease: {error}"));
    let receipt = SourceProviderReceiptV1::new(
        request.request_id(),
        digest_acquire_request(request),
        request.acquisition_id(),
        provider_process_instance,
        digest_signed_export_lease(&signed_lease),
        signed_lease.to_canonical_bytes(),
        SourceProviderDescriptorRole::SourceRoot,
        kernel_boot_id,
        device,
        inode,
        unique_mount_id,
        digest_provider_proof(lease.proof()),
    )
    .unwrap_or_else(|error| panic!("provider receipt: {error}"));
    let signed_receipt = sign_provider_receipt(receipt, signer, key)
        .unwrap_or_else(|error| panic!("signed receipt: {error}"));
    let result = signed_receipt.to_canonical_bytes();
    let signed_request = signed_request(request, &SigningKey::from_bytes(&[50; 32]));
    let descriptor_observation = SourceRootObservationV1::new(
        kernel_boot_id,
        device,
        inode,
        unique_mount_id,
        true,
        true,
        true,
    )
    .unwrap_or_else(|error| panic!("descriptor observation: {error}"));
    let status = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Acquire,
        request.request_id(),
        digest_signed_request(&signed_request),
        SourceProviderStatus::Complete,
        provider_process_instance,
        request.session_binding(),
        1,
        response_result_digest_v1(
            SourceProviderMethod::Acquire,
            SourceProviderStatus::Complete,
            Some(&result),
        ),
        source_root_descriptor_commitment_v1(&descriptor_observation),
    )
    .unwrap_or_else(|error| panic!("Acquire status: {error}"));
    let signed_status = sign_response_status(status, provider_signer(key), key)
        .unwrap_or_else(|error| panic!("signed Acquire status: {error}"));
    AcquireSourceResponseV1::new(signed_status, Some(result))
        .unwrap_or_else(|error| panic!("Acquire response: {error}"))
}

fn observation() -> SourceRootObservationV1 {
    SourceRootObservationV1::new([5; 16], 38, 39, 40, true, true, true)
        .unwrap_or_else(|error| panic!("source observation: {error}"))
}

fn context(now: i64, maximum_expiry: i64) -> SourceProviderVerificationContextV1 {
    context_sequences(now, maximum_expiry, 1, 1)
}

fn context_sequences(
    now: i64,
    maximum_expiry: i64,
    request_sequence: u64,
    response_sequence: u64,
) -> SourceProviderVerificationContextV1 {
    context_with_boot_and_sequences(
        now,
        maximum_expiry,
        [5; 16],
        request_sequence,
        response_sequence,
    )
}

fn context_with_boot_and_sequences(
    now: i64,
    maximum_expiry: i64,
    boot_id: [u8; 16],
    request_sequence: u64,
    response_sequence: u64,
) -> SourceProviderVerificationContextV1 {
    SourceProviderVerificationContextV1::new(
        now,
        maximum_expiry,
        [4; 16],
        boot_id,
        [31; 16],
        32,
        digest(33),
        digest(90),
        request_sequence,
        response_sequence,
    )
    .unwrap_or_else(|error| panic!("verification context: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[allow(clippy::too_many_arguments)]
fn verifies_current_session_exchange(
    method: SourceProviderMethod,
    status: SourceProviderStatus,
    root_trust: &SourceProviderTrustAnchorV1,
    provider_trust: &SourceProviderTrustAnchorV1,
    current_route: &ProtectedSourceProviderRouteV1,
    current_context: &SourceProviderVerificationContextV1,
) -> bool {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let authenticated_session = session([52; 16]);

    match method {
        SourceProviderMethod::Hello => false,
        SourceProviderMethod::Acquire => {
            let request = acquire();
            let signed_request = signed_request(&request, &root_key);
            let (response, roles, observation) = if status == SourceProviderStatus::Complete {
                let lease = export_lease(
                    &provider_key,
                    &request,
                    local_proof(65),
                    LEASE_ISSUED,
                    LEASE_EXPIRES,
                );
                (
                    completed_acquire_response(
                        &request,
                        &lease,
                        &observation(),
                        [52; 16],
                        &provider_key,
                    ),
                    vec![SourceProviderDescriptorRole::SourceRoot],
                    Some(observation()),
                )
            } else {
                let signed_status = signed_status(
                    &signed_request,
                    request.request_id(),
                    status,
                    None,
                    empty_descriptor_set_commitment_v1(),
                    &provider_key,
                );
                (
                    AcquireSourceResponseV1::new(signed_status, None)
                        .unwrap_or_else(|error| panic!("Acquire disposition: {error}")),
                    Vec::new(),
                    None,
                )
            };

            verify_acquire(
                &signed_request,
                &response,
                &authenticated_session,
                root_trust,
                provider_trust,
                current_route,
                current_context,
                &roles,
                observation,
            )
            .is_ok()
        }
        SourceProviderMethod::Release => {
            let request = ReleaseSourceRequestV1::new(
                authenticated_session.binding(),
                1,
                [91; 16],
                digest(2),
                [31; 16],
                32,
                digest(33),
                [36; 16],
                digest(37),
                DEADLINE,
            )
            .unwrap_or_else(|error| panic!("Release request: {error}"));
            let signed_request = sign_request(
                SourceProviderMethod::Release,
                encode_release_request(&request),
                root_signer(&root_key),
                &root_key,
            )
            .unwrap_or_else(|error| panic!("signed Release request: {error}"));
            let result = if status == SourceProviderStatus::Complete {
                let receipt = SourceReleaseReceiptV1::new(
                    request.request_id(),
                    digest_release_request(&request),
                    request.lease_id(),
                    request.lease_digest(),
                    provider_authority(&provider_key),
                    [52; 16],
                    92,
                    NOW,
                )
                .unwrap_or_else(|error| panic!("Release receipt: {error}"));
                Some(
                    sign_release_receipt(receipt, provider_signer(&provider_key), &provider_key)
                        .unwrap_or_else(|error| panic!("signed Release receipt: {error}"))
                        .to_canonical_bytes(),
                )
            } else {
                None
            };
            let response = ReleaseSourceResponseV1::new(
                signed_status(
                    &signed_request,
                    request.request_id(),
                    status,
                    result.as_deref(),
                    empty_descriptor_set_commitment_v1(),
                    &provider_key,
                ),
                result,
            )
            .unwrap_or_else(|error| panic!("Release response: {error}"));

            verify_release(
                &signed_request,
                &response,
                &authenticated_session,
                root_trust,
                provider_trust,
                current_route,
                current_context,
                &[],
            )
            .is_ok()
        }
        SourceProviderMethod::Inventory => {
            let request = InventorySourceRequestV1::new(
                authenticated_session.binding(),
                1,
                [93; 16],
                [31; 16],
                32,
                digest(33),
                None,
                DEADLINE,
            )
            .unwrap_or_else(|error| panic!("Inventory request: {error}"));
            let signed_request = sign_request(
                SourceProviderMethod::Inventory,
                encode_inventory_request(&request),
                root_signer(&root_key),
                &root_key,
            )
            .unwrap_or_else(|error| panic!("signed Inventory request: {error}"));
            let result = if status == SourceProviderStatus::Complete {
                let inventory = SourceProviderInventoryV1::new(
                    request.request_id(),
                    digest_inventory_request(&request),
                    [31; 16],
                    32,
                    digest(33),
                    provider_authority(&provider_key),
                    [52; 16],
                    27,
                    digest(28),
                    94,
                    Vec::new(),
                )
                .unwrap_or_else(|error| panic!("Inventory result: {error}"));
                Some(
                    sign_inventory(inventory, provider_signer(&provider_key), &provider_key)
                        .unwrap_or_else(|error| panic!("signed Inventory: {error}"))
                        .to_canonical_bytes(),
                )
            } else {
                None
            };
            let response = InventorySourceResponseV1::new(
                signed_status(
                    &signed_request,
                    request.request_id(),
                    status,
                    result.as_deref(),
                    empty_descriptor_set_commitment_v1(),
                    &provider_key,
                ),
                result,
            )
            .unwrap_or_else(|error| panic!("Inventory response: {error}"));

            verify_source_inventory(
                &signed_request,
                &response,
                &authenticated_session,
                root_trust,
                provider_trust,
                current_route,
                current_context,
                &[],
            )
            .is_ok()
        }
    }
}

#[test]
fn every_method_and_status_rechecks_current_session_trust_route_and_boot() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );
    let current_route = route();
    let current_context = context(NOW, DEADLINE);

    let replacement_root_key = SigningKey::from_bytes(&[51; 32]);
    let replacement_root_signer = SourceProviderSigningKeyV1::for_signing_key(
        [31; 16],
        32,
        digest(33),
        [35; 16],
        36,
        SourceProviderKeyUsageV1::RootMountRecord,
        &replacement_root_key,
    )
    .unwrap_or_else(|error| panic!("replacement Root Mount signer: {error}"));
    let replacement_root_trust = trust_anchor(
        &replacement_root_signer,
        &replacement_root_key,
        0,
        false,
        None,
    );

    let replacement_provider_key = SigningKey::from_bytes(&[43; 32]);
    let same_authority_rekey = provider_trust_with_identity_and_route(
        &replacement_provider_key,
        [7; 16],
        8,
        digest(9),
        [11; 16],
        12,
        [70; 16],
        71,
        digest(72),
    );
    let authority_generation_replacement = provider_trust_with_identity_and_route(
        &provider_key,
        [7; 16],
        9,
        digest(10),
        [10; 16],
        11,
        [70; 16],
        71,
        digest(72),
    );
    let authority_digest_replacement = provider_trust_with_identity_and_route(
        &provider_key,
        [7; 16],
        8,
        digest(10),
        [10; 16],
        11,
        [70; 16],
        71,
        digest(72),
    );
    let authority_id_replacement = provider_trust_with_identity_and_route(
        &provider_key,
        [8; 16],
        8,
        digest(9),
        [10; 16],
        11,
        [70; 16],
        71,
        digest(72),
    );
    let authority_id_route = route_with([70; 16], 71, digest(72), [8; 16], digest(23));

    let changed_route_id = route_with([71; 16], 71, digest(72), [7; 16], digest(23));
    let changed_route_id_trust = provider_trust_with_identity_and_route(
        &provider_key,
        [7; 16],
        8,
        digest(9),
        [10; 16],
        11,
        [71; 16],
        71,
        digest(72),
    );
    let changed_route_generation = route_with([70; 16], 72, digest(72), [7; 16], digest(23));
    let changed_route_generation_trust = provider_trust_with_identity_and_route(
        &provider_key,
        [7; 16],
        8,
        digest(9),
        [10; 16],
        11,
        [70; 16],
        72,
        digest(72),
    );
    let changed_route_digest = route_with([70; 16], 71, digest(74), [7; 16], digest(23));
    let changed_route_digest_trust = provider_trust_with_identity_and_route(
        &provider_key,
        [7; 16],
        8,
        digest(9),
        [10; 16],
        11,
        [70; 16],
        71,
        digest(74),
    );
    let changed_resource_namespace = route_with([70; 16], 71, digest(72), [7; 16], digest(24));
    let changed_boot_context = context_with_boot_and_sequences(NOW, DEADLINE, [6; 16], 1, 1);

    let hostile_currentness = [
        (
            &replacement_root_trust,
            &provider_trust,
            &current_route,
            &current_context,
        ),
        (
            &root_trust,
            &same_authority_rekey,
            &current_route,
            &current_context,
        ),
        (
            &root_trust,
            &authority_generation_replacement,
            &current_route,
            &current_context,
        ),
        (
            &root_trust,
            &authority_digest_replacement,
            &current_route,
            &current_context,
        ),
        (
            &root_trust,
            &authority_id_replacement,
            &authority_id_route,
            &current_context,
        ),
        (
            &root_trust,
            &changed_route_id_trust,
            &changed_route_id,
            &current_context,
        ),
        (
            &root_trust,
            &changed_route_generation_trust,
            &changed_route_generation,
            &current_context,
        ),
        (
            &root_trust,
            &changed_route_digest_trust,
            &changed_route_digest,
            &current_context,
        ),
        (
            &root_trust,
            &provider_trust,
            &changed_resource_namespace,
            &current_context,
        ),
        (
            &root_trust,
            &provider_trust,
            &current_route,
            &changed_boot_context,
        ),
    ];

    for method in [
        SourceProviderMethod::Acquire,
        SourceProviderMethod::Release,
        SourceProviderMethod::Inventory,
    ] {
        for status in [
            SourceProviderStatus::Complete,
            SourceProviderStatus::Pending,
            SourceProviderStatus::Rejected,
            SourceProviderStatus::Unavailable,
        ] {
            assert!(verifies_current_session_exchange(
                method,
                status,
                &root_trust,
                &provider_trust,
                &current_route,
                &current_context,
            ));
            for (hostile_root, hostile_provider, hostile_route, hostile_context) in
                hostile_currentness
            {
                assert!(!verifies_current_session_exchange(
                    method,
                    status,
                    hostile_root,
                    hostile_provider,
                    hostile_route,
                    hostile_context,
                ));
            }
        }
    }
}

#[test]
fn typed_acquire_wire_and_independent_golden_are_stable() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let signed = signed_request(&acquire(), &root_key);
    let message = SourceProviderMessageV1::AcquireRequest(signed);
    let bytes = encode_message(&message).unwrap_or_else(|error| panic!("encode: {error}"));

    assert_eq!(decode_message(&bytes), Ok(message));
    assert_eq!(
        sha256(&bytes),
        "12e1f836844b4318179e343848f45e11041ac92d02c0ede690ac6d487411ba95"
    );
}

#[test]
fn typed_frame_unknowns_truncation_trailing_and_oversize_fail_closed() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let message = SourceProviderMessageV1::AcquireRequest(signed_request(&acquire(), &root_key));
    let bytes = encode_message(&message).unwrap_or_else(|error| panic!("encode: {error}"));

    for length in 0..bytes.len() {
        assert!(
            decode_message(&bytes[..length]).is_err(),
            "truncation {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_message(&trailing).is_err());
    for (offset, value) in [(8, 2), (10, 1), (12, 99), (13, 99), (14, 1), (16, 1)] {
        let mut hostile = bytes.clone();
        hostile[offset] = value;
        assert!(decode_message(&hostile).is_err(), "hostile offset {offset}");
    }
    assert!(decode_message(&vec![0; MAXIMUM_FRAME_BYTES + 1]).is_err());

    let mut zero_session = encode_acquire_request(&acquire());
    zero_session[..32].fill(0);
    assert!(decode_acquire_request(&zero_session).is_err());
    let mut zero_sequence = encode_acquire_request(&acquire());
    zero_sequence[32..40].fill(0);
    assert!(decode_acquire_request(&zero_sequence).is_err());
}

#[test]
fn hello_capabilities_and_typed_roles_are_closed() {
    let session = session([52; 16]);
    let signed_server = session.signed_provider_hello().clone();
    let bytes = encode_message(&SourceProviderMessageV1::HelloResponse(
        signed_server.clone(),
    ))
    .unwrap_or_else(|error| panic!("hello frame: {error}"));

    assert_eq!(
        decode_message(&bytes),
        Ok(SourceProviderMessageV1::HelloResponse(
            signed_server.clone()
        ))
    );
    assert!(encode_message(&SourceProviderMessageV1::HelloRequest(signed_server)).is_err());
    assert_eq!(session.root_mount_hello().nonce(), [53; 32]);
    assert_eq!(
        session.provider_hello().client_hello_digest(),
        Some(digest_signed_hello(session.signed_root_mount_hello()))
    );
}

#[test]
fn signed_hello_transcript_is_fresh_exact_and_independently_golden() {
    let session = session([52; 16]);
    let client = session.signed_root_mount_hello().to_canonical_bytes();
    let server = session.signed_provider_hello().to_canonical_bytes();

    assert_eq!(
        sha256(&client),
        "083da572ebc34d5297befc103768c5d55f6aefa49a8860ad47069d303a585ee1"
    );
    assert_eq!(
        sha256(&server),
        "17646a3751557abda9c3fc2d59a149a4265c31cc6bb8d6ba8012ba36e0d8adfc"
    );
    assert_eq!(
        hex::encode(session.binding().as_bytes()),
        "f2938172e6dfbc8a2dc17cc730b95813f5f10975dc42a3fc8c228604bebbfe1b"
    );
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let provider_traffic_signer = provider_signer(&provider_key);
    let provider_trust = trust_anchor(
        &provider_traffic_signer,
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );
    let (provider_hello_key, provider_hello_signer) =
        hello_signer(&provider_trust, SourceProviderPeerRole::Provider);
    assert!(
        SourceProviderHelloV1::new(
            SourceProviderPeerRole::RootMount,
            [0; 32],
            [51; 16],
            [5; 16],
            root_signer(&SigningKey::from_bytes(&[50; 32])),
            provider_traffic_signer.clone(),
            [70; 16],
            71,
            digest(72),
            None,
            1,
            true,
            true,
        )
        .is_err()
    );
    assert!(session_with([53; 32], [53; 32], [5; 16], [5; 16], 1, 1, [52; 16]).is_err());
    assert!(session_with([53; 32], [54; 32], [5; 16], [6; 16], 1, 1, [52; 16]).is_err());
    assert!(session_with([53; 32], [54; 32], [5; 16], [5; 16], 1, 2, [52; 16]).is_err());
    assert!(
        session_with_options(
            [53; 32], [54; 32], [5; 16], [5; 16], 1, 1, false, true, true, true, [52; 16],
        )
        .is_err()
    );
    assert!(
        session_with_options(
            [53; 32], [54; 32], [5; 16], [5; 16], 1, 1, true, true, false, true, [52; 16],
        )
        .is_err()
    );

    let mut changed = server;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let changed = SignedSourceProviderHelloV1::from_canonical_bytes(&changed)
        .unwrap_or_else(|error| panic!("mutated signed hello remains canonical: {error}"));
    assert!(
        verify_hello(
            &changed,
            &trust_anchor(
                &provider_hello_signer,
                &provider_hello_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                false,
                None
            ),
        )
        .is_err()
    );

    let root_key = SigningKey::from_bytes(&[50; 32]);
    let root_signer = root_signer(&root_key);
    let provider_signer = provider_signer(&provider_key);
    let identity = process_identity(4000, 5000, digest(73));
    assert!(
        authenticate_session(
            [53; 32],
            session.signed_root_mount_hello().clone(),
            session.signed_provider_hello().clone(),
            &trust_anchor(&root_signer, &root_key, 0, false, None),
            &trust_anchor(
                &provider_signer,
                &provider_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                true,
                None,
            ),
            identity.clone(),
            identity.clone(),
            &route(),
        )
        .is_err()
    );
    let identity = process_identity(4000, 5000, digest(73));
    assert!(
        authenticate_session(
            [53; 32],
            session.signed_root_mount_hello().clone(),
            session.signed_provider_hello().clone(),
            &trust_anchor(&root_signer, &root_key, 0, false, None),
            &trust_anchor(
                &provider_signer,
                &provider_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                false,
                Some(provider_signer.key_generation() + 1),
            ),
            identity.clone(),
            identity.clone(),
            &route(),
        )
        .is_err()
    );
    assert!(
        authenticate_session(
            [55; 32],
            session.signed_root_mount_hello().clone(),
            session.signed_provider_hello().clone(),
            &trust_anchor(&root_signer, &root_key, 0, false, None),
            &trust_anchor(
                &provider_signer,
                &provider_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                false,
                None,
            ),
            identity.clone(),
            identity,
            &route(),
        )
        .is_err()
    );
    let wrong_server = SourceProviderHelloV1::new(
        SourceProviderPeerRole::Provider,
        [54; 32],
        [52; 16],
        [5; 16],
        provider_signer.clone(),
        root_signer.clone(),
        [70; 16],
        71,
        digest(72),
        Some(digest(244)),
        ALL_PROOF_CLASS_CAPABILITIES,
        true,
        true,
    )
    .unwrap_or_else(|error| panic!("wrong server hello: {error}"));
    let wrong_server = sign_hello(wrong_server, provider_hello_signer, &provider_hello_key)
        .unwrap_or_else(|error| panic!("signed wrong server hello: {error}"));
    let identity = process_identity(4000, 5000, digest(73));
    assert!(
        authenticate_session(
            [53; 32],
            session.signed_root_mount_hello().clone(),
            wrong_server,
            &trust_anchor(&root_signer, &root_key, 0, false, None),
            &trust_anchor(
                &provider_signer,
                &provider_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                false,
                None,
            ),
            identity.clone(),
            identity,
            &route(),
        )
        .is_err()
    );
}

#[test]
fn proof_variants_have_canonical_encodings_and_independent_goldens() {
    let proofs = [
        zfs_proof(),
        local_proof(65),
        immutable_proof(),
        replica_proof(),
    ];
    let expected = [
        "b336267c788f005df9c0055ae170e1e24aee71329714a2ad11041de31a2d0317",
        "df13f61a2cc79ba06dd32be38b16900504fc4c8861303326da496fcad24b203a",
        "dd870d78a260d10ecf5d3f9116b88a71312fb4811670249f97681c637b131db3",
        "a6e1e2c5edf4b51bf8104e8bb959850749914c24872abaaf50aa21907d07c462",
    ];
    let expected_proof_digests = [
        "548989bddd53b3c243925cd912b64189d967adbe2c1dd28fd36a19582121442d",
        "acfeffbf8bc812c9d40522ecd7acb063c0b3263cc6a5434e4bf088a2a24b632d",
        "912f652fa683403d35e5564538bf5ace88c57bc469bd7e0a932380d644984dab",
        "76a984c1cf8f528cfc711e084eca904cb4883b210b066a3c05f2decf61f8e49b",
    ];

    for ((proof, expected_digest), expected_proof_digest) in
        proofs.into_iter().zip(expected).zip(expected_proof_digests)
    {
        let bytes = encode_provider_proof(&proof);
        assert_eq!(decode_provider_proof(&bytes), Ok(proof.clone()));
        assert_eq!(sha256(&bytes), expected_digest);
        assert_eq!(
            hex::encode(digest_provider_proof(&proof).as_bytes()),
            expected_proof_digest
        );

        let mut wrong_class = bytes;
        wrong_class[0] = if proof.class_code() == 4 {
            1
        } else {
            proof.class_code() + 1
        };
        assert!(decode_provider_proof(&wrong_class).is_err());
    }
}

#[test]
fn lease_and_all_typed_response_goldens_are_stable() {
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let signed_lease =
        sign_export_lease(lease.clone(), provider_signer(&provider_key), &provider_key)
            .unwrap_or_else(|error| panic!("signed lease: {error}"));
    let acquire_response =
        completed_acquire_response(&request, &lease, &observation(), [52; 16], &provider_key);
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let release_request = ReleaseSourceRequestV1::new(
        session([52; 16]).binding(),
        1,
        [91; 16],
        request.acquisition_id(),
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        [36; 16],
        digest(37),
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("release request: {error}"));
    let signed_release = sign_request(
        SourceProviderMethod::Release,
        encode_release_request(&release_request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed release: {error}"));
    let release_response = ReleaseSourceResponseV1::new(
        signed_status(
            &signed_release,
            [91; 16],
            SourceProviderStatus::Pending,
            None,
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        None,
    )
    .unwrap_or_else(|error| panic!("release response: {error}"));
    let inventory_request = InventorySourceRequestV1::new(
        session([52; 16]).binding(),
        1,
        [92; 16],
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        None,
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("inventory request: {error}"));
    let signed_inventory_request = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&inventory_request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed inventory request: {error}"));
    let inventory_response = InventorySourceResponseV1::new(
        signed_status(
            &signed_inventory_request,
            [92; 16],
            SourceProviderStatus::Unavailable,
            None,
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        None,
    )
    .unwrap_or_else(|error| panic!("inventory response: {error}"));
    let rejected = signed_status(
        &signed_release,
        [91; 16],
        SourceProviderStatus::Rejected,
        None,
        empty_descriptor_set_commitment_v1(),
        &provider_key,
    );
    let status_vectors = [
        acquire_response.signed_status().to_canonical_bytes(),
        release_response.signed_status().to_canonical_bytes(),
        rejected.to_canonical_bytes(),
        inventory_response.signed_status().to_canonical_bytes(),
    ];
    let status_goldens = [
        "c58ed75e9521389e2998b5601b2933fac65c9329e68eb2f4d9e30c329f784207",
        "bc084bc9deeaf09ed3b0e8f048a7112fb6b710318629fbc574f407b2c56f5089",
        "cf966e9e817651b493c54db7b3b102563f66611acfce86068662c951de94b20a",
        "23e3ff31720b2136800eb451e5164e8ed176f6e0942761caba499ffa1b2a1674",
    ];
    for (bytes, expected) in status_vectors.iter().zip(status_goldens) {
        assert_eq!(sha256(bytes), expected);
    }

    let vectors = [
        encode_export_lease(&lease),
        signed_lease.to_canonical_bytes(),
        encode_message(&SourceProviderMessageV1::AcquireResponse(acquire_response))
            .unwrap_or_else(|error| panic!("Acquire message: {error}")),
        encode_message(&SourceProviderMessageV1::ReleaseResponse(release_response))
            .unwrap_or_else(|error| panic!("Release message: {error}")),
        encode_message(&SourceProviderMessageV1::InventoryResponse(
            inventory_response,
        ))
        .unwrap_or_else(|error| panic!("Inventory message: {error}")),
    ];
    let expected = [
        "b2cc51e72d201b72e98426d7c1673ebb56032bf63b3d0589c1b43e21e35cda7d",
        "3e84ebc9c46f8fbd479d734baf7a79ff76f186e309dc3523e9cb8681ffa6d2c6",
        "6a259d58b2f35e6435d4e3bf2ffe73f5e2eaf67a7fc549f29e9c41f4c98a481d",
        "2d9a58ecccb635638d53835a25d897688bf474a47229dddc2798c06f0a2aa5bf",
        "e7d7d30c10d1d9f128fd659764ad61b5b5700264a3569637514ee22438800e5b",
    ];
    for (bytes, expected_digest) in vectors.into_iter().zip(expected) {
        assert_eq!(sha256(&bytes), expected_digest);
    }
}

#[test]
fn signed_envelope_magic_is_distinct_and_old_spec_magic_is_rejected() {
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let signed = sign_export_lease(lease, provider_signer(&provider_key), &provider_key)
        .unwrap_or_else(|error| panic!("signed lease: {error}"));
    let bytes = signed.to_canonical_bytes();

    assert_eq!(&bytes[..8], b"AOSSPX01");
    let related_repository_magics = [
        *b"AOSSPX01",
        *b"AOSSPV01",
        *b"AOSSPS01",
        *b"AOSSPI01",
        *b"AOSSPA01",
        *b"AOSSPR01",
        *b"AOSSPRC1",
        *b"AOSSPRP1",
    ];
    for (index, magic) in related_repository_magics.iter().enumerate() {
        assert!(!related_repository_magics[..index].contains(magic));
    }
    let mut old_colliding_magic = bytes;
    old_colliding_magic[..8].copy_from_slice(b"AOSSPS01");
    assert!(SignedSourceExportLeaseV1::from_canonical_bytes(&old_colliding_magic).is_err());
}

#[test]
fn request_digest_has_global_holder_method_request_id_scope() {
    let request = acquire_with([1; 16], DEADLINE, 600, true, 4, true);
    let release = ReleaseSourceRequestV1::new(
        request.session_binding(),
        1,
        [1; 16],
        request.acquisition_id(),
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        [36; 16],
        digest(37),
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("Release request: {error}"));
    let inventory = InventorySourceRequestV1::new(
        request.session_binding(),
        1,
        [1; 16],
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        None,
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("Inventory request: {error}"));

    assert_ne!(
        digest_acquire_request(&request),
        digest_release_request(&release)
    );
    assert_ne!(
        digest_acquire_request(&request),
        digest_inventory_request(&inventory)
    );
    assert_ne!(
        digest_release_request(&release),
        digest_inventory_request(&inventory)
    );
}

#[test]
fn request_trust_binds_holder_and_rejects_inactive_or_wrong_keys() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let other_key = SigningKey::from_bytes(&[51; 32]);
    let signer = root_signer(&root_key);
    let signed = signed_request(&acquire(), &root_key);
    let trust = trust_anchor(&signer, &root_key, 0, false, None);

    verify_request(&signed, &trust).unwrap_or_else(|error| panic!("verify: {error}"));
    assert!(verify_request(&signed, &trust_anchor(&signer, &root_key, 0, true, None)).is_err());
    assert!(
        verify_request(
            &signed,
            &trust_anchor(
                &signer,
                &root_key,
                0,
                false,
                Some(signer.key_generation() + 1)
            ),
        )
        .is_err()
    );
    assert!(
        SourceProviderTrustAnchorV1::new(
            signer.authority_id(),
            signer.authority_generation(),
            signer.authority_digest(),
            signer.key_id(),
            signer.key_generation(),
            *other_key.verifying_key().as_bytes(),
            signer.usage(),
            0,
            [70; 16],
            71,
            digest(72),
            1,
            digest(201),
            1,
            [24; 32],
            digest(26),
            1,
            digest(202),
            false,
            None,
        )
        .is_ok()
    );
    let wrong_key_trust = SourceProviderTrustAnchorV1::new(
        signer.authority_id(),
        signer.authority_generation(),
        signer.authority_digest(),
        signer.key_id(),
        signer.key_generation(),
        *other_key.verifying_key().as_bytes(),
        signer.usage(),
        0,
        [70; 16],
        71,
        digest(72),
        1,
        digest(201),
        1,
        [24; 32],
        digest(26),
        1,
        digest(202),
        false,
        None,
    )
    .unwrap_or_else(|error| panic!("wrong-key trust: {error}"));
    assert!(verify_request(&signed, &wrong_key_trust).is_err());

    let original = acquire();
    let wrong_holder = AcquireSourceRequestV1::new(
        original.session_binding(),
        original.sequence(),
        original.request_id(),
        original.acquisition_id(),
        original.prospective_apply_template().to_vec(),
        original.prospective_apply_template_digest(),
        original.source_use(),
        original.node_id(),
        original.boot_id(),
        [30; 16],
        original.holder_generation(),
        original.holder_authority_digest(),
        original.binding().to_vec(),
        original.binding_digest(),
        original.deadline_seconds(),
        original.requested_lease_seconds(),
        original.revocation_digest(),
        original.recursive(),
        original.requested_maximum_submounts(),
        original.kernel_coupled(),
    )
    .unwrap_or_else(|error| panic!("wrong-holder request: {error}"));
    let signed_wrong_holder = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&wrong_holder),
        signer.clone(),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("sign wrong-holder request: {error}"));
    assert!(verify_request(&signed_wrong_holder, &trust).is_err());

    let mut weak_key = [0; 32];
    weak_key[0] = 1;
    assert!(
        SourceProviderTrustAnchorV1::new(
            signer.authority_id(),
            signer.authority_generation(),
            signer.authority_digest(),
            signer.key_id(),
            signer.key_generation(),
            weak_key,
            signer.usage(),
            0,
            [70; 16],
            71,
            digest(72),
            1,
            digest(201),
            1,
            [24; 32],
            digest(26),
            1,
            digest(202),
            false,
            None,
        )
        .is_err()
    );
}

#[test]
fn composite_acquire_authenticates_complete_authority_graph() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let signed = signed_request(&request, &root_key);
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let response =
        completed_acquire_response(&request, &lease, &observation(), [52; 16], &provider_key);
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );

    let verified = verify_acquire(
        &signed,
        &response,
        &session([52; 16]),
        &root_trust,
        &provider_trust,
        &route(),
        &context(NOW, 1_800_000_800),
        &[SourceProviderDescriptorRole::SourceRoot],
        Some(observation()),
    )
    .unwrap_or_else(|error| panic!("composite Acquire: {error}"));
    assert_eq!(verified.status(), SourceProviderStatus::Complete);
    let sequence = verified.sequence();
    let verified = verified
        .result()
        .unwrap_or_else(|| panic!("Acquire was not complete"));
    assert_eq!(sequence.request_sequence(), 1);
    assert_eq!(
        verified.lease_digest(),
        digest_signed_export_lease(verified.signed_lease())
    );
    assert_eq!(verified.observation(), &observation());
    assert_eq!(
        verified.provider_resource_commitment(),
        provider_resource_commitment_v1(
            resource_ref(verified.signed_lease()),
            digest_provider_proof(lease.proof())
        )
    );
}

fn resource_ref(signed: &SignedSourceExportLeaseV1) -> &SourceResourceV1 {
    signed.subject().resource()
}

#[test]
fn composite_acquire_rejects_time_descriptor_session_and_capability_substitutions() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let signed = signed_request(&request, &root_key);
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let response =
        completed_acquire_response(&request, &lease, &observation(), [52; 16], &provider_key);
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        15,
        false,
        None,
    );
    let verify = |session: &SourceProviderSessionV1,
                  context: &SourceProviderVerificationContextV1,
                  roles: &[SourceProviderDescriptorRole],
                  observation: Option<SourceRootObservationV1>| {
        verify_acquire(
            &signed,
            &response,
            session,
            &root_trust,
            &provider_trust,
            &route(),
            context,
            roles,
            observation,
        )
    };

    let other_session = session_with([55; 32], [56; 32], [5; 16], [5; 16], 15, 15, [52; 16])
        .unwrap_or_else(|error| panic!("other session: {error}"));
    let cross_session_request = acquire_for_session(other_session.binding(), 1);
    let signed_cross_session = signed_request(&cross_session_request, &root_key);
    assert!(
        verify_acquire(
            &signed_cross_session,
            &response,
            &session([52; 16]),
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation()),
        )
        .is_err()
    );
    let replayed_sequence_request = acquire_for_session(session([52; 16]).binding(), 2);
    let signed_replayed_sequence = signed_request(&replayed_sequence_request, &root_key);
    assert!(
        verify_acquire(
            &signed_replayed_sequence,
            &response,
            &session([52; 16]),
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation()),
        )
        .is_err()
    );

    let mut changed_result = response
        .signed_receipt()
        .unwrap_or_else(|| panic!("complete response result"))
        .to_vec();
    let last = changed_result.len() - 1;
    changed_result[last] ^= 1;
    assert!(
        AcquireSourceResponseV1::new(response.signed_status().clone(), Some(changed_result),)
            .is_err()
    );

    assert!(
        verify(
            &session([53; 16]),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation())
        )
        .is_err()
    );
    for changed_observation in [
        SourceRootObservationV1::new([6; 16], 38, 39, 40, true, true, true),
        SourceRootObservationV1::new([5; 16], 37, 39, 40, true, true, true),
        SourceRootObservationV1::new([5; 16], 38, 38, 40, true, true, true),
        SourceRootObservationV1::new([5; 16], 38, 39, 41, true, true, true),
    ] {
        assert!(
            verify(
                &session([52; 16]),
                &context(NOW, 1_800_000_800),
                &[SourceProviderDescriptorRole::SourceRoot],
                Some(
                    changed_observation
                        .unwrap_or_else(|error| panic!("changed observation: {error}")),
                )
            )
            .is_err()
        );
    }
    let wrong_boot_response = completed_acquire_response_with_kernel_facts(
        &request,
        &lease,
        [52; 16],
        [6; 16],
        38,
        39,
        40,
        &provider_key,
    );
    let wrong_boot_observation =
        SourceRootObservationV1::new([6; 16], 38, 39, 40, true, true, true)
            .unwrap_or_else(|error| panic!("wrong-boot observation: {error}"));
    assert!(
        verify_acquire(
            &signed,
            &wrong_boot_response,
            &session([52; 16]),
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(wrong_boot_observation),
        )
        .is_err()
    );
    for wrong_consumer_proof in [
        local_proof_for_consumer(65, [30; 16], 32),
        local_proof_for_consumer(65, [31; 16], 33),
    ] {
        let wrong_consumer_lease = export_lease(
            &provider_key,
            &request,
            wrong_consumer_proof,
            LEASE_ISSUED,
            LEASE_EXPIRES,
        );
        let wrong_consumer_response = completed_acquire_response(
            &request,
            &wrong_consumer_lease,
            &observation(),
            [52; 16],
            &provider_key,
        );
        assert!(
            verify_acquire(
                &signed,
                &wrong_consumer_response,
                &session([52; 16]),
                &root_trust,
                &provider_trust,
                &route(),
                &context(NOW, 1_800_000_800),
                &[SourceProviderDescriptorRole::SourceRoot],
                Some(observation()),
            )
            .is_err()
        );
    }
    assert!(
        verify(
            &session([52; 16]),
            &context(LEASE_EXPIRES, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation())
        )
        .is_err()
    );
    assert!(
        verify(
            &session([52; 16]),
            &context(NOW, LEASE_EXPIRES - 1),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation())
        )
        .is_err()
    );
    assert!(
        verify(
            &session([52; 16]),
            &context(NOW, 1_800_000_800),
            &[],
            Some(observation())
        )
        .is_err()
    );
    assert!(
        verify(
            &session([52; 16]),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            None
        )
        .is_err()
    );
    assert!(SourceRootObservationV1::new([5; 16], 38, 39, 40, false, true, true).is_err());
    assert!(SourceRootObservationV1::new([5; 16], 38, 39, 40, true, false, true).is_err());

    let nonrecursive = acquire_with([1; 16], DEADLINE, 600, false, 0, true);
    let nonrecursive_signed = signed_request(&nonrecursive, &root_key);
    let nonrecursive_lease = export_lease(
        &provider_key,
        &nonrecursive,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let nonrecursive_response = completed_acquire_response(
        &nonrecursive,
        &nonrecursive_lease,
        &observation(),
        [52; 16],
        &provider_key,
    );
    assert!(
        verify_acquire(
            &nonrecursive_signed,
            &nonrecursive_response,
            &session([52; 16]),
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation()),
        )
        .is_err()
    );
}

#[test]
fn catalog_resource_and_selection_floor_rollback_or_equivocation_fails_closed() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let signed = signed_request(&request, &root_key);
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let response =
        completed_acquire_response(&request, &lease, &observation(), [52; 16], &provider_key);
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let verify_with = |provider_trust: &SourceProviderTrustAnchorV1| {
        verify_acquire(
            &signed,
            &response,
            &session([52; 16]),
            &root_trust,
            provider_trust,
            &route(),
            &context(NOW, 1_800_000_800),
            &[SourceProviderDescriptorRole::SourceRoot],
            Some(observation()),
        )
    };

    let exact = provider_trust_at_floors(
        &provider_key,
        27,
        digest(28),
        25,
        [24; 32],
        digest(26),
        29,
        digest(30),
    );
    assert!(verify_with(&exact).is_ok());
    let catalog_equivocation = provider_trust_at_floors(
        &provider_key,
        27,
        digest(29),
        25,
        [24; 32],
        digest(26),
        29,
        digest(30),
    );
    assert!(verify_with(&catalog_equivocation).is_err());
    let resource_id_equivocation = provider_trust_at_floors(
        &provider_key,
        27,
        digest(28),
        25,
        [25; 32],
        digest(26),
        29,
        digest(30),
    );
    assert!(verify_with(&resource_id_equivocation).is_err());
    let resource_digest_equivocation = provider_trust_at_floors(
        &provider_key,
        27,
        digest(28),
        25,
        [24; 32],
        digest(27),
        29,
        digest(30),
    );
    assert!(verify_with(&resource_digest_equivocation).is_err());
    let selection_equivocation = provider_trust_at_floors(
        &provider_key,
        27,
        digest(28),
        25,
        [24; 32],
        digest(26),
        29,
        digest(31),
    );
    assert!(verify_with(&selection_equivocation).is_err());
    let rollback = provider_trust_at_floors(
        &provider_key,
        27,
        digest(28),
        26,
        [24; 32],
        digest(26),
        29,
        digest(30),
    );
    assert!(verify_with(&rollback).is_err());
}

#[test]
fn lease_bounds_reject_zero_future_expired_and_over_request_intervals() {
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    assert!(
        SourceExportLeaseV1::new(
            [36; 16],
            request.request_id(),
            digest_acquire_request(&request),
            [31; 16],
            32,
            digest(33),
            provider_authority(&provider_key),
            resource(),
            local_proof(65),
            request.binding_digest(),
            NOW,
            NOW,
            digest(90),
        )
        .is_err()
    );

    for (issued, expires) in [(NOW + 1, NOW + 100), (NOW - 100, NOW), (NOW - 1, NOW + 700)] {
        let lease = export_lease(&provider_key, &request, local_proof(65), issued, expires);
        let response =
            completed_acquire_response(&request, &lease, &observation(), [52; 16], &provider_key);
        let root_key = SigningKey::from_bytes(&[50; 32]);
        assert!(
            verify_acquire(
                &signed_request(&request, &root_key),
                &response,
                &session([52; 16]),
                &trust_anchor(&root_signer(&root_key), &root_key, 0, false, None),
                &trust_anchor(
                    &provider_signer(&provider_key),
                    &provider_key,
                    15,
                    false,
                    None
                ),
                &route(),
                &context(NOW, DEADLINE),
                &[SourceProviderDescriptorRole::SourceRoot],
                Some(observation()),
            )
            .is_err()
        );
    }
}

#[test]
fn provider_resource_commitment_is_sensitive_to_every_committed_field() {
    let proof_digest = digest_provider_proof(&local_proof(65));
    let base = provider_resource_commitment_v1(&resource(), proof_digest);
    let resources = [
        SourceResourceV1::new(
            digest(22),
            [24; 32],
            25,
            digest(26),
            27,
            digest(28),
            29,
            digest(30),
        ),
        SourceResourceV1::new(
            digest(23),
            [25; 32],
            25,
            digest(26),
            27,
            digest(28),
            29,
            digest(30),
        ),
        SourceResourceV1::new(
            digest(23),
            [24; 32],
            26,
            digest(26),
            27,
            digest(28),
            29,
            digest(30),
        ),
        SourceResourceV1::new(
            digest(23),
            [24; 32],
            25,
            digest(27),
            27,
            digest(28),
            29,
            digest(30),
        ),
        SourceResourceV1::new(
            digest(23),
            [24; 32],
            25,
            digest(26),
            27,
            digest(28),
            30,
            digest(30),
        ),
        SourceResourceV1::new(
            digest(23),
            [24; 32],
            25,
            digest(26),
            27,
            digest(28),
            29,
            digest(31),
        ),
    ];
    for changed in resources {
        let changed = changed.unwrap_or_else(|error| panic!("changed resource: {error}"));
        assert_ne!(
            base,
            provider_resource_commitment_v1(&changed, proof_digest)
        );
    }
    assert_ne!(
        base,
        provider_resource_commitment_v1(&resource(), digest(120))
    );
}

#[test]
fn release_and_inventory_composites_verify_complete_and_closed_statuses() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        15,
        false,
        None,
    );
    let session = session([52; 16]);
    let context = context(NOW, DEADLINE);

    let release_request = ReleaseSourceRequestV1::new(
        session.binding(),
        1,
        [91; 16],
        digest(2),
        [31; 16],
        32,
        digest(33),
        [36; 16],
        digest(37),
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("release request: {error}"));
    let signed_release_request = sign_request(
        SourceProviderMethod::Release,
        encode_release_request(&release_request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed release request: {error}"));
    let release_receipt = SourceReleaseReceiptV1::new(
        release_request.request_id(),
        digest_release_request(&release_request),
        release_request.lease_id(),
        release_request.lease_digest(),
        provider_authority(&provider_key),
        [52; 16],
        92,
        NOW,
    )
    .unwrap_or_else(|error| panic!("release receipt: {error}"));
    let signed_release = sign_release_receipt(
        release_receipt,
        provider_signer(&provider_key),
        &provider_key,
    )
    .unwrap_or_else(|error| panic!("signed release receipt: {error}"));
    let signed_release_bytes = signed_release.to_canonical_bytes();
    let release_response = ReleaseSourceResponseV1::new(
        signed_status(
            &signed_release_request,
            release_request.request_id(),
            SourceProviderStatus::Complete,
            Some(&signed_release_bytes),
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        Some(signed_release_bytes),
    )
    .unwrap_or_else(|error| panic!("release response: {error}"));
    let release_message = encode_message(&SourceProviderMessageV1::ReleaseResponse(
        release_response.clone(),
    ))
    .unwrap_or_else(|error| panic!("release response message: {error}"));
    assert_eq!(
        sha256(&release_message),
        "7165205969c98c6746bc0e55d9c61301124305fe2b4a64b8c691ce1f00766d08"
    );
    assert!(matches!(
        verify_release(
            &signed_release_request,
            &release_response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context,
            &[]
        ),
        Ok(disposition) if disposition.status() == SourceProviderStatus::Complete && disposition.result().is_some()
    ));

    let inventory_request = InventorySourceRequestV1::new(
        session.binding(),
        1,
        [93; 16],
        [31; 16],
        32,
        digest(33),
        None,
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("inventory request: {error}"));
    let signed_inventory_request = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&inventory_request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed inventory request: {error}"));
    let proof_digest = digest_provider_proof(&local_proof(65));
    let entry = SourceProviderInventoryEntryV1::new(
        [36; 16],
        digest(37),
        digest(2),
        InventoryLeaseStateV1::Active,
        resource(),
        2,
        proof_digest,
        provider_resource_commitment_v1(&resource(), proof_digest),
    )
    .unwrap_or_else(|error| panic!("inventory entry: {error}"));
    let inventory = SourceProviderInventoryV1::new(
        inventory_request.request_id(),
        digest_inventory_request(&inventory_request),
        [31; 16],
        32,
        digest(33),
        provider_authority(&provider_key),
        [52; 16],
        27,
        digest(28),
        94,
        vec![entry],
    )
    .unwrap_or_else(|error| panic!("inventory: {error}"));
    let signed_inventory = sign_inventory(inventory, provider_signer(&provider_key), &provider_key)
        .unwrap_or_else(|error| panic!("signed inventory: {error}"));
    let signed_inventory_bytes = signed_inventory.to_canonical_bytes();
    let inventory_response = InventorySourceResponseV1::new(
        signed_status(
            &signed_inventory_request,
            inventory_request.request_id(),
            SourceProviderStatus::Complete,
            Some(&signed_inventory_bytes),
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        Some(signed_inventory_bytes),
    )
    .unwrap_or_else(|error| panic!("inventory response: {error}"));
    let inventory_message = encode_message(&SourceProviderMessageV1::InventoryResponse(
        inventory_response.clone(),
    ))
    .unwrap_or_else(|error| panic!("inventory response message: {error}"));
    assert_eq!(
        sha256(&inventory_message),
        "fbf736a037bfcb0b474fa2e46a9f1f4ba216a7371b41f44863e6149677b8e30b"
    );
    assert!(matches!(
        verify_source_inventory(
            &signed_inventory_request,
            &inventory_response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context,
            &[]
        ),
        Ok(disposition) if disposition.status() == SourceProviderStatus::Complete && disposition.result().is_some()
    ));
    for hostile_resource_floor in [
        provider_trust_at_floors(
            &provider_key,
            27,
            digest(28),
            26,
            [24; 32],
            digest(26),
            29,
            digest(30),
        ),
        provider_trust_at_floors(
            &provider_key,
            27,
            digest(28),
            25,
            [25; 32],
            digest(26),
            29,
            digest(30),
        ),
        provider_trust_at_floors(
            &provider_key,
            27,
            digest(28),
            25,
            [24; 32],
            digest(27),
            29,
            digest(30),
        ),
    ] {
        assert!(
            verify_source_inventory(
                &signed_inventory_request,
                &inventory_response,
                &session,
                &root_trust,
                &hostile_resource_floor,
                &route(),
                &context,
                &[],
            )
            .is_err()
        );
    }

    let crossed_resource = SourceResourceV1::new(
        digest(23),
        [24; 32],
        25,
        digest(26),
        28,
        digest(29),
        29,
        digest(30),
    )
    .unwrap_or_else(|error| panic!("crossed resource: {error}"));
    let crossed_entry = SourceProviderInventoryEntryV1::new(
        [36; 16],
        digest(37),
        digest(2),
        InventoryLeaseStateV1::Active,
        crossed_resource.clone(),
        2,
        proof_digest,
        provider_resource_commitment_v1(&crossed_resource, proof_digest),
    )
    .unwrap_or_else(|error| panic!("crossed entry: {error}"));
    let crossed_inventory = SourceProviderInventoryV1::new(
        inventory_request.request_id(),
        digest_inventory_request(&inventory_request),
        [31; 16],
        32,
        digest(33),
        provider_authority(&provider_key),
        [52; 16],
        27,
        digest(28),
        95,
        vec![crossed_entry],
    )
    .unwrap_or_else(|error| panic!("crossed inventory: {error}"));
    let crossed_signed = sign_inventory(
        crossed_inventory,
        provider_signer(&provider_key),
        &provider_key,
    )
    .unwrap_or_else(|error| panic!("crossed signed inventory: {error}"));
    let crossed_bytes = crossed_signed.to_canonical_bytes();
    let crossed_response = InventorySourceResponseV1::new(
        signed_status(
            &signed_inventory_request,
            inventory_request.request_id(),
            SourceProviderStatus::Complete,
            Some(&crossed_bytes),
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        Some(crossed_bytes),
    )
    .unwrap_or_else(|error| panic!("crossed inventory response: {error}"));
    assert!(
        verify_source_inventory(
            &signed_inventory_request,
            &crossed_response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context,
            &[],
        )
        .is_err()
    );

    let pending = ReleaseSourceResponseV1::new(
        signed_status(
            &signed_release_request,
            release_request.request_id(),
            SourceProviderStatus::Pending,
            None,
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        None,
    )
    .unwrap_or_else(|error| panic!("pending response: {error}"));
    assert!(matches!(
        verify_release(
            &signed_release_request,
            &pending,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context,
            &[]
        ),
        Ok(disposition) if disposition.status() == SourceProviderStatus::Pending && disposition.result().is_none()
    ));
}

#[test]
fn provider_restart_changes_process_receipt_not_stable_authority_or_resource() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let lease = export_lease(&key, &request, local_proof(65), LEASE_ISSUED, LEASE_EXPIRES);
    let before = completed_acquire_response(&request, &lease, &observation(), [52; 16], &key);
    let after = completed_acquire_response(&request, &lease, &observation(), [53; 16], &key);

    let before_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(
        before
            .signed_receipt()
            .unwrap_or_else(|| panic!("completed response has a receipt")),
    )
    .unwrap_or_else(|error| panic!("decode pre-restart receipt: {error}"));
    let after_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(
        after
            .signed_receipt()
            .unwrap_or_else(|| panic!("completed response has a receipt")),
    )
    .unwrap_or_else(|error| panic!("decode post-restart receipt: {error}"));
    let before_lease = SignedSourceExportLeaseV1::from_canonical_bytes(
        before_receipt.subject().signed_export_lease(),
    )
    .unwrap_or_else(|error| panic!("decode pre-restart lease: {error}"));
    let after_lease = SignedSourceExportLeaseV1::from_canonical_bytes(
        after_receipt.subject().signed_export_lease(),
    )
    .unwrap_or_else(|error| panic!("decode post-restart lease: {error}"));

    assert_ne!(before.signed_receipt(), after.signed_receipt());
    assert_ne!(
        before_receipt.subject().provider_process_instance(),
        after_receipt.subject().provider_process_instance()
    );
    assert_eq!(before_receipt.signer(), after_receipt.signer());
    assert_eq!(
        before_receipt.subject().lease_digest(),
        after_receipt.subject().lease_digest()
    );
    assert_eq!(lease.provider(), &provider_authority(&key));
    assert_eq!(before_lease.subject().provider(), lease.provider());
    assert_eq!(after_lease.subject().resource(), lease.resource());
}

#[test]
fn message_phase_descriptor_contract_is_exact() {
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let request = acquire();
    let signed_request = signed_request(&request, &root_key);
    let lease = export_lease(
        &provider_key,
        &request,
        local_proof(65),
        LEASE_ISSUED,
        LEASE_EXPIRES,
    );
    let complete = SourceProviderMessageV1::AcquireResponse(completed_acquire_response(
        &request,
        &lease,
        &observation(),
        [52; 16],
        &provider_key,
    ));
    assert_eq!(
        validate_message_descriptor_contract(
            &complete,
            &[SourceProviderDescriptorRole::SourceRoot]
        ),
        Ok(())
    );
    assert!(validate_message_descriptor_contract(&complete, &[]).is_err());

    let no_descriptor = SourceProviderMessageV1::AcquireResponse(
        AcquireSourceResponseV1::new(
            signed_status(
                &signed_request,
                request.request_id(),
                SourceProviderStatus::Pending,
                None,
                empty_descriptor_set_commitment_v1(),
                &provider_key,
            ),
            None,
        )
        .unwrap_or_else(|error| panic!("response: {error}")),
    );
    assert_eq!(
        validate_message_descriptor_contract(&no_descriptor, &[]),
        Ok(())
    );
    assert!(
        validate_message_descriptor_contract(
            &no_descriptor,
            &[SourceProviderDescriptorRole::SourceRoot],
        )
        .is_err()
    );
}

#[test]
fn signed_status_rejects_replay_substitution_and_invalid_shapes() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let session = session([52; 16]);
    let request = ReleaseSourceRequestV1::new(
        session.binding(),
        1,
        [91; 16],
        digest(2),
        [31; 16],
        32,
        digest(33),
        [36; 16],
        digest(37),
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("release request: {error}"));
    let signed_request = sign_request(
        SourceProviderMethod::Release,
        encode_release_request(&request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed release request: {error}"));
    let status = signed_status(
        &signed_request,
        request.request_id(),
        SourceProviderStatus::Pending,
        None,
        empty_descriptor_set_commitment_v1(),
        &provider_key,
    );
    let response = ReleaseSourceResponseV1::new(status.clone(), None)
        .unwrap_or_else(|error| panic!("pending response: {error}"));
    let root_trust = trust_anchor(&root_signer(&root_key), &root_key, 0, false, None);
    let provider_trust = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );
    let verified = verify_release(
        &signed_request,
        &response,
        &session,
        &root_trust,
        &provider_trust,
        &route(),
        &context(NOW, DEADLINE),
        &[],
    )
    .unwrap_or_else(|error| panic!("signed Pending: {error}"));
    assert_eq!(verified.status(), SourceProviderStatus::Pending);
    let sequence = verified.sequence();
    assert_eq!(sequence.response_sequence(), 1);
    for disposition in [
        SourceProviderStatus::Rejected,
        SourceProviderStatus::Unavailable,
    ] {
        let response = ReleaseSourceResponseV1::new(
            signed_status(
                &signed_request,
                request.request_id(),
                disposition,
                None,
                empty_descriptor_set_commitment_v1(),
                &provider_key,
            ),
            None,
        )
        .unwrap_or_else(|error| panic!("signed error disposition: {error}"));
        let verified = verify_release(
            &signed_request,
            &response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, DEADLINE),
            &[],
        )
        .unwrap_or_else(|error| panic!("authenticated error disposition: {error}"));
        assert_eq!(verified.status(), disposition);
        assert!(verified.result().is_none());
    }

    assert!(
        verify_release(
            &signed_request,
            &response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context_sequences(NOW, DEADLINE, 2, 1),
            &[],
        )
        .is_err()
    );
    assert!(
        verify_release(
            &signed_request,
            &response,
            &session_with([55; 32], [56; 32], [5; 16], [5; 16], 15, 15, [52; 16])
                .unwrap_or_else(|error| panic!("other session: {error}")),
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, DEADLINE),
            &[],
        )
        .is_err()
    );

    let mut invalid_signature = status.to_canonical_bytes();
    let last = invalid_signature.len() - 1;
    invalid_signature[last] ^= 1;
    let invalid_signature = SignedSourceProviderStatusV1::from_canonical_bytes(&invalid_signature)
        .unwrap_or_else(|error| panic!("canonical changed signature: {error}"));
    let invalid_response = ReleaseSourceResponseV1::new(invalid_signature, None)
        .unwrap_or_else(|error| panic!("signature is verified only with trust: {error}"));
    assert!(
        verify_release(
            &signed_request,
            &invalid_response,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, DEADLINE),
            &[],
        )
        .is_err()
    );

    let wrong_sequence = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Release,
        request.request_id(),
        digest_signed_request(&signed_request),
        SourceProviderStatus::Pending,
        [52; 16],
        session.binding(),
        2,
        response_result_digest_v1(
            SourceProviderMethod::Release,
            SourceProviderStatus::Pending,
            None,
        ),
        empty_descriptor_set_commitment_v1(),
    )
    .unwrap_or_else(|error| panic!("wrong-sequence status: {error}"));
    let wrong_sequence = ReleaseSourceResponseV1::new(
        sign_response_status(
            wrong_sequence,
            provider_signer(&provider_key),
            &provider_key,
        )
        .unwrap_or_else(|error| panic!("signed wrong sequence: {error}")),
        None,
    )
    .unwrap_or_else(|error| panic!("wrong sequence response: {error}"));
    assert!(
        verify_release(
            &signed_request,
            &wrong_sequence,
            &session,
            &root_trust,
            &provider_trust,
            &route(),
            &context(NOW, DEADLINE),
            &[],
        )
        .is_err()
    );

    for (request_id, request_digest, process, binding) in [
        (
            [92; 16],
            digest_signed_request(&signed_request),
            [52; 16],
            session.binding(),
        ),
        (
            request.request_id(),
            digest(240),
            [52; 16],
            session.binding(),
        ),
        (
            request.request_id(),
            digest_signed_request(&signed_request),
            [53; 16],
            session.binding(),
        ),
        (
            request.request_id(),
            digest_signed_request(&signed_request),
            [52; 16],
            digest(241),
        ),
    ] {
        let substituted = SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Release,
            request_id,
            request_digest,
            SourceProviderStatus::Pending,
            process,
            binding,
            1,
            response_result_digest_v1(
                SourceProviderMethod::Release,
                SourceProviderStatus::Pending,
                None,
            ),
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap_or_else(|error| panic!("substituted status: {error}"));
        let substituted = ReleaseSourceResponseV1::new(
            sign_response_status(substituted, provider_signer(&provider_key), &provider_key)
                .unwrap_or_else(|error| panic!("signed substitution: {error}")),
            None,
        )
        .unwrap_or_else(|error| panic!("substituted response: {error}"));
        assert!(
            verify_release(
                &signed_request,
                &substituted,
                &session,
                &root_trust,
                &provider_trust,
                &route(),
                &context(NOW, DEADLINE),
                &[],
            )
            .is_err()
        );
    }

    let method_swap = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Inventory,
        request.request_id(),
        digest_signed_request(&signed_request),
        SourceProviderStatus::Pending,
        [52; 16],
        session.binding(),
        1,
        response_result_digest_v1(
            SourceProviderMethod::Inventory,
            SourceProviderStatus::Pending,
            None,
        ),
        empty_descriptor_set_commitment_v1(),
    )
    .unwrap_or_else(|error| panic!("method-swap status: {error}"));
    assert!(
        ReleaseSourceResponseV1::new(
            sign_response_status(method_swap, provider_signer(&provider_key), &provider_key)
                .unwrap_or_else(|error| panic!("signed method swap: {error}")),
            None,
        )
        .is_err()
    );

    let nested = vec![1];
    assert!(ReleaseSourceResponseV1::new(status.clone(), Some(nested)).is_err());
    let malformed_complete_result = vec![1];
    let malformed_complete = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Release,
        request.request_id(),
        digest_signed_request(&signed_request),
        SourceProviderStatus::Complete,
        [52; 16],
        session.binding(),
        1,
        response_result_digest_v1(
            SourceProviderMethod::Release,
            SourceProviderStatus::Complete,
            Some(&malformed_complete_result),
        ),
        empty_descriptor_set_commitment_v1(),
    )
    .unwrap_or_else(|error| panic!("malformed complete status: {error}"));
    let malformed_complete = sign_response_status(
        malformed_complete,
        provider_signer(&provider_key),
        &provider_key,
    )
    .unwrap_or_else(|error| panic!("signed malformed complete: {error}"));
    assert!(
        ReleaseSourceResponseV1::new(malformed_complete, Some(malformed_complete_result)).is_err()
    );
    let wrong_descriptors = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Release,
        request.request_id(),
        digest_signed_request(&signed_request),
        SourceProviderStatus::Pending,
        [52; 16],
        session.binding(),
        1,
        response_result_digest_v1(
            SourceProviderMethod::Release,
            SourceProviderStatus::Pending,
            None,
        ),
        digest(250),
    )
    .unwrap_or_else(|error| panic!("wrong-descriptor status: {error}"));
    let wrong_descriptors = sign_response_status(
        wrong_descriptors,
        provider_signer(&provider_key),
        &provider_key,
    )
    .unwrap_or_else(|error| panic!("signed wrong descriptors: {error}"));
    assert!(ReleaseSourceResponseV1::new(wrong_descriptors.clone(), None).is_err());

    let mut hostile_frame = encode_message(&SourceProviderMessageV1::ReleaseResponse(response))
        .unwrap_or_else(|error| panic!("pending frame: {error}"));
    let replacement = wrong_descriptors.to_canonical_bytes();
    let status_length = u32::from_be_bytes(
        hostile_frame[24..28]
            .try_into()
            .unwrap_or_else(|_| panic!("status length field")),
    ) as usize;
    assert_eq!(status_length, replacement.len());
    hostile_frame[28..28 + status_length].copy_from_slice(&replacement);
    assert!(decode_message(&hostile_frame).is_err());
}

#[test]
fn recursive_and_inventory_bounds_fail_before_large_allocation() {
    assert!(RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 0, 0, 0, 0).is_err());
    assert!(RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 1, 0, 0, 0).is_err());
    assert!(RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 1, 0, 1, 1).is_err());
    assert!(RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 2, 0, 3, 1).is_err());
    assert!(RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 2, 0, 2, 0).is_err());
    assert!(
        RecursiveTopologyProofV1::new(
            [1; 16],
            1,
            digest(1),
            MAXIMUM_RECURSIVE_ENTRY_COUNT + 1,
            0,
            0,
            0,
        )
        .is_err()
    );
    assert!(
        RecursiveTopologyProofV1::new(
            [1; 16],
            1,
            digest(1),
            1,
            MAXIMUM_RECURSIVE_BYTE_COUNT + 1,
            0,
            0,
        )
        .is_err()
    );
    assert!(
        RecursiveTopologyProofV1::new([1; 16], 1, digest(1), 1, 0, MAXIMUM_RECURSIVE_DEPTH + 1, 0,)
            .is_err()
    );

    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = InventorySourceRequestV1::new(
        session([52; 16]).binding(),
        1,
        [1; 16],
        [31; 16],
        32,
        digest(33),
        None,
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("inventory request: {error}"));
    let inventory = SourceProviderInventoryV1::new(
        request.request_id(),
        digest_inventory_request(&request),
        [31; 16],
        32,
        digest(33),
        provider_authority(&provider_key),
        [52; 16],
        27,
        digest(28),
        29,
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("inventory: {error}"));
    let mut bytes = encode_inventory(&inventory);
    let count_offset = bytes.len() - 4;
    bytes[count_offset..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_inventory(&bytes).is_err());
}

#[test]
fn maximum_inventory_remains_wire_representable() {
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let request = InventorySourceRequestV1::new(
        session([52; 16]).binding(),
        1,
        [1; 16],
        [31; 16],
        32,
        digest(33),
        None,
        DEADLINE,
    )
    .unwrap_or_else(|error| panic!("inventory request: {error}"));
    let proof_digest = digest_provider_proof(&local_proof(65));
    let resource = resource();
    let resource_commitment = provider_resource_commitment_v1(&resource, proof_digest);
    let mut entries = Vec::with_capacity(MAXIMUM_INVENTORY_ENTRIES);
    for ordinal in 1..=MAXIMUM_INVENTORY_ENTRIES {
        let mut lease_id = [0; 16];
        lease_id[12..].copy_from_slice(&(ordinal as u32).to_be_bytes());
        let mut acquisition_id = [0; 32];
        acquisition_id[28..].copy_from_slice(&(ordinal as u32).to_be_bytes());
        entries.push(
            SourceProviderInventoryEntryV1::new(
                lease_id,
                digest(37),
                ObjectDigest::from_bytes(acquisition_id),
                InventoryLeaseStateV1::Active,
                resource.clone(),
                2,
                proof_digest,
                resource_commitment,
            )
            .unwrap_or_else(|error| panic!("inventory entry: {error}")),
        );
    }
    let inventory = SourceProviderInventoryV1::new(
        request.request_id(),
        digest_inventory_request(&request),
        [31; 16],
        32,
        digest(33),
        provider_authority(&provider_key),
        [52; 16],
        27,
        digest(28),
        29,
        entries,
    )
    .unwrap_or_else(|error| panic!("inventory: {error}"));
    let signed_inventory = sign_inventory(inventory, provider_signer(&provider_key), &provider_key)
        .unwrap_or_else(|error| panic!("signed inventory: {error}"));
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let signed_request = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&request),
        root_signer(&root_key),
        &root_key,
    )
    .unwrap_or_else(|error| panic!("signed inventory request: {error}"));
    let result = signed_inventory.to_canonical_bytes();
    let response = InventorySourceResponseV1::new(
        signed_status(
            &signed_request,
            request.request_id(),
            SourceProviderStatus::Complete,
            Some(&result),
            empty_descriptor_set_commitment_v1(),
            &provider_key,
        ),
        Some(result),
    )
    .unwrap_or_else(|error| panic!("inventory response: {error}"));
    let message = SourceProviderMessageV1::InventoryResponse(response);
    let bytes = encode_message(&message).unwrap_or_else(|error| panic!("inventory wire: {error}"));

    assert!(bytes.len() <= MAXIMUM_FRAME_BYTES);
    assert_eq!(decode_message(&bytes), Ok(message));
}

#[test]
fn nominated_subject_must_equal_the_pinned_provider_session() {
    let valid = session([52; 16]);
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let root_signer = root_signer(&root_key);
    let provider_signer = provider_signer(&provider_key);
    let peer = process_identity(4000, 5000, digest(73));
    let nominated = process_identity(4001, 5000, digest(73));

    assert!(
        authenticate_session(
            [53; 32],
            valid.signed_root_mount_hello().clone(),
            valid.signed_provider_hello().clone(),
            &trust_anchor(&root_signer, &root_key, 0, false, None),
            &trust_anchor(
                &provider_signer,
                &provider_key,
                ALL_PROOF_CLASS_CAPABILITIES,
                false,
                None
            ),
            peer,
            nominated,
            &route(),
        )
        .is_err()
    );
}

#[test]
fn signed_envelopes_reject_every_single_byte_substitution() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = acquire();
    let lease = export_lease(&key, &request, local_proof(65), LEASE_ISSUED, LEASE_EXPIRES);
    let signed = sign_export_lease(lease, provider_signer(&key), &key)
        .unwrap_or_else(|error| panic!("signed lease: {error}"));
    let bytes = signed.to_canonical_bytes();

    for offset in 0..bytes.len() {
        let mut hostile = bytes.clone();
        hostile[offset] ^= 1;
        if let Ok(decoded) = SignedSourceExportLeaseV1::from_canonical_bytes(&hostile) {
            assert!(verify_export_lease(&decoded, key.verifying_key().as_bytes()).is_err());
        }
    }
}
