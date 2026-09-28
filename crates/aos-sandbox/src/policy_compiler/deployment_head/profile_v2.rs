//! Signed deployment input declarations for the explicit V2 compiler profile.
//!
//! The existing `AOSPDH01` head and deployment signing role remain unchanged.
//! Each of its four inputs uses the existing canonical model serializer:
//!
//! ```text
//! u64be(domain-length) || domain || u64be(payload-length) ||
//! canonical-json([[2, head-generation, deployment-signer-generation], typed-data])
//! ```
//!
//! Exact typed reserialization is mandatory; this module never deserializes
//! owner-proof-shaped models from untrusted JSON. Signed Node/Site ceilings are
//! provenance. Backend and catalog declarations do not prove installed
//! enforcement or live catalog currentness. No publication or read is enabled.

use super::*;
use crate::policy_compiler::authority::canonical_endpoint_catalog_v1;
use crate::policy_compiler::namespace::canonical_namespace_catalog_v1;
use aos_sandbox_core::ObjectDescriptor;

const INPUT_DOMAINS: [&[u8]; 4] = [
    b"aos.sandbox.policy-deployment-input.node.v2",
    b"aos.sandbox.policy-deployment-input.site.v2",
    b"aos.sandbox.policy-deployment-input.backend.v2",
    b"aos.sandbox.policy-deployment-input.catalogs.v2",
];

/// Retains closed catalog declarations without current-owner authentication.
#[derive(Clone, Debug)]
pub struct PolicyDeploymentCatalogDeclarationsV2 {
    endpoints: Vec<EndpointCatalogEntryV1>,
    destinations: Vec<NamespaceDestinationV1>,
    endpoint_descriptor: ObjectDescriptor,
    destination_descriptor: ObjectDescriptor,
}

impl PolicyDeploymentCatalogDeclarationsV2 {
    /// Validates declarations using the existing catalog shape and byte codecs.
    ///
    /// # Errors
    ///
    /// Rejects unordered, duplicated, sentinel, or oversized declarations.
    /// This constructor does not produce authenticated compiler catalogs.
    pub fn new(
        endpoints: Vec<EndpointCatalogEntryV1>,
        destinations: Vec<NamespaceDestinationV1>,
    ) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        let (endpoint_descriptor, _) = canonical_endpoint_catalog_v1(&endpoints)
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
        let (destination_descriptor, _) = canonical_namespace_catalog_v1(&destinations)
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
        Ok(Self {
            endpoints,
            destinations,
            endpoint_descriptor,
            destination_descriptor,
        })
    }

    /// Returns declared endpoint bindings, not a live-owner catalog proof.
    #[must_use]
    pub fn endpoints(&self) -> &[EndpointCatalogEntryV1] {
        &self.endpoints
    }

    /// Returns declared destination bindings, not a live-owner catalog proof.
    #[must_use]
    pub fn destinations(&self) -> &[NamespaceDestinationV1] {
        &self.destinations
    }

    /// Returns the exact canonical endpoint-declaration descriptor.
    #[must_use]
    pub const fn endpoint_descriptor(&self) -> &ObjectDescriptor {
        &self.endpoint_descriptor
    }

    /// Returns the exact canonical destination-declaration descriptor.
    #[must_use]
    pub const fn destination_descriptor(&self) -> &ObjectDescriptor {
        &self.destination_descriptor
    }
}

/// Retains explicit normalized inputs for the versioned deployment profile.
///
/// All fields are supplied as existing constructor-validated compiler models.
/// No grant, namespace rule, backend feature, or catalog entry is defaulted.
/// This declaration contains no project/request mapping or live owner proof.
#[derive(Clone, Debug)]
pub struct PolicyDeploymentInputProfileV2 {
    generation: u64,
    signer_generation: u64,
    node: NodePolicyInputV1,
    site: SitePolicyInputV1,
    backend: BackendCapabilitiesV1,
    catalogs: PolicyDeploymentCatalogDeclarationsV2,
}

impl PolicyDeploymentInputProfileV2 {
    /// Constructs explicit typed declarations for one deployment generation.
    ///
    /// # Errors
    ///
    /// Rejects zero generations or any canonical input above the unchanged
    /// 64-KiB per-input bound. Policy constructors retain their own stricter
    /// semantic checks, including rejection of unregistered Profile selectors.
    pub fn new(
        generation: u64,
        signer_generation: u64,
        node: NodePolicyInputV1,
        site: SitePolicyInputV1,
        backend: BackendCapabilitiesV1,
        catalogs: PolicyDeploymentCatalogDeclarationsV2,
    ) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if generation == 0 || signer_generation == 0 {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let profile = Self {
            generation,
            signer_generation,
            node,
            site,
            backend,
            catalogs,
        };
        profile.canonical_inputs()?;
        Ok(profile)
    }

    /// Returns the declared head generation, not a rollback-floor proof.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the signer generation that verification must independently pin.
    #[must_use]
    pub const fn signer_generation(&self) -> u64 {
        self.signer_generation
    }

    /// Returns the complete declared Node ceiling.
    #[must_use]
    pub const fn node(&self) -> &NodePolicyInputV1 {
        &self.node
    }

    /// Returns the complete declared Site ceiling.
    #[must_use]
    pub const fn site(&self) -> &SitePolicyInputV1 {
        &self.site
    }

    /// Returns backend declarations, not installed enforcement evidence.
    #[must_use]
    pub const fn backend(&self) -> &BackendCapabilitiesV1 {
        &self.backend
    }

    /// Returns catalog declarations requiring separate live-owner verification.
    #[must_use]
    pub const fn catalogs(&self) -> &PolicyDeploymentCatalogDeclarationsV2 {
        &self.catalogs
    }

    /// Encodes all four inputs with the existing typed canonical serializer.
    ///
    /// # Errors
    ///
    /// Rejects serialization failure or a per-input bound violation. The bytes
    /// become signed declarations only after the exact deployment head verifies.
    pub fn canonical_inputs(&self) -> Result<[Vec<u8>; 4], PolicyDeploymentHeadErrorV1> {
        let prefix = (2_u16, self.generation, self.signer_generation);
        let inputs = [
            canonical_bytes(INPUT_DOMAINS[0], &(prefix, self.node.layer())),
            canonical_bytes(INPUT_DOMAINS[1], &(prefix, self.site.layer())),
            canonical_bytes(INPUT_DOMAINS[2], &(prefix, &self.backend)),
            canonical_bytes(
                INPUT_DOMAINS[3],
                &(
                    prefix,
                    (
                        &self.catalogs.endpoint_descriptor,
                        &self.catalogs.endpoints,
                        &self.catalogs.destination_descriptor,
                        &self.catalogs.destinations,
                    ),
                ),
            ),
        ];
        let [node, site, backend, catalogs] = inputs.map(|result| {
            let bytes = result.map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
            if bytes.len() > MAXIMUM_INPUT_BYTES {
                return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
            }
            Ok(bytes)
        });
        Ok([node?, site?, backend?, catalogs?])
    }
}

/// Admits a V2-profile head under the existing fixed Root deployment role.
///
/// The key parameter supports verification before opening the journal; it is
/// not a trust nomination. Root independently reads its protected deployment
/// pin and rejects any different key or generation before the shared head CAS.
/// The V1 installer and all public policy gates remain unchanged.
///
/// # Errors
///
/// Rejects malformed or substituted typed bytes, invalid signature/validity,
/// changed role pins, unsafe Root names, held publication, generation conflict,
/// ambiguous append, or failed readback.
pub fn admit_fixed_policy_deployment_profile_v2(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let verified = verify_signed_profile(packet, inputs, profile, verifying_key, now_unix_seconds)?;
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    let (key, generation) = read_deployment_role(&mut journal)?;
    if key != *verifying_key || generation != profile.signer_generation {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let admitted = admit_deployment_head_in_journal(&mut journal, packet, verified, &key)?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    Ok(admitted)
}

/// Verifies exact declarations against a retained fixed Root writer and head.
///
/// This read-only check uses the independently stored deployment pin, not a
/// request-supplied key. The returned existing head is signed provenance only;
/// it cannot replace Root history/floor, live backend/catalog proofs, or the
/// cross-owner compiler/publication barrier.
///
/// # Errors
///
/// Rejects unsafe fixed names, missing/changed pins or head, expiry, invalid
/// signature, legacy profile bytes, or any typed declaration substitution.
pub fn verify_current_policy_deployment_profile_v2(
    journal: &mut Journal,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    let verified = verify_current_profile(journal, packet, inputs, profile, now_unix_seconds)?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    Ok(verified)
}

pub(super) fn verify_current_profile(
    journal: &mut Journal,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let (key, generation) = read_deployment_role(journal)?;
    if generation != profile.signer_generation {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(HEAD_KEY)? != Some(packet) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    verify_signed_profile(packet, inputs, profile, &key, now_unix_seconds)
}

fn read_deployment_role(
    journal: &mut Journal,
) -> Result<(VerifyingKey, u64), PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let pins = authority
        .get(SIGNER_PINS_KEY)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let (deployment_generation, deployment, _, _) = decode_policy_signer_pins_v1(pins)?;
    Ok((deployment, deployment_generation))
}

pub(super) fn verify_signed_profile(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let expected = profile.canonical_inputs()?;
    let provided = [inputs.node, inputs.site, inputs.backend, inputs.catalogs];
    if provided
        .into_iter()
        .zip(&expected)
        .any(|(bytes, exact)| bytes != exact)
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    verify_historical_packet(packet, verifying_key)?;
    let issued_at = read_i64(packet, 16)?;
    let expires_at = read_i64(packet, 24)?;
    if read_u64(packet, 8)? != profile.generation
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let input_digests: [[u8; 32]; 4] = expected
        .each_ref()
        .map(|input| Sha256::digest(input).into());
    for (index, digest) in input_digests.iter().enumerate() {
        if packet.get(32 + index * 32..64 + index * 32) != Some(digest.as_slice()) {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
    }
    Ok(PolicyDeploymentHeadV1 {
        generation: profile.generation,
        expires_at,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
        input_digests,
    })
}

#[cfg(test)]
mod tests;
