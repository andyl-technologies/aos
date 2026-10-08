//! One-shot authentication for dormant AOSSPL version-2 migration plans.
//!
//! The pure ledger planner proves only format and graph facts. This module
//! additionally requires a fixed, signed `AOSSPMG1` provenance manifest whose
//! signer is the exact currently eligible catalog publisher at the protected
//! namespace-41, trust, revocation, and configuration heads. The returned
//! capability is move-only and must be revalidated immediately before install.
//!
//! ```text
//! AOSSPMG1 | version:u16be=1 | reserved[6] | provider[56] |
//! source-root[32] | provenance[32] | prospective-root[32] | plan[32] |
//! policy-generation:u64be | issued:i64be | deadline:i64be |
//! trust-generation:u64be | trust-digest[32] |
//! revocation-generation:u64be | revocation-digest[32] |
//! catalog-head[32] | configuration[32] |
//! source-count:u32be | replacement-count:u32be |
//! source-bytes:u64be | replacement-bytes:u64be |
//! signer-key-id[16] | signer-generation:u64be | signer-key-digest[32] |
//! signature[64]
//! ```

use aos_sandbox::{ProtectedJournalAuthority, ProtectedJournalSnapshot};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::migration::{
    AossplV2ToV3MigrationPlanV1, SupplementalV2MigrationProvenanceV1, plan_aosspl_v2_to_v3,
};
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityTrustStateV1, SourceProviderKeyTrustStateV1, SourceProviderKeyUsageV1,
    SourceProviderSigningKeyV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    ProtectedProviderCustodyV1, RevalidatedProviderConfigurationV1, SourceProviderSecurityError,
    VerifiedCatalogPublicationV1,
};

const MANIFEST_MAGIC: &[u8; 8] = b"AOSSPMG1";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_BYTES: usize = 512;
const SIGNATURE_OFFSET: usize = 448;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-provenance.v1\0";
const PLAN_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-plan.v1\0";
const CONFIGURATION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-configuration.v1\0";
/// Authorizes one exact pure v2-to-v3 plan at protected current heads.
///
/// This capability contains no signing key and is not cloneable. Its only
/// consuming operation revalidates custody, catalog currentness, and the exact
/// namespace-41 snapshot before releasing the already-authenticated plan to
/// the dormant installer.
pub struct AuthorizedV2MigrationPlanV1 {
    plan: AossplV2ToV3MigrationPlanV1,
    configuration: RevalidatedProviderConfigurationV1,
    catalog_publication: VerifiedCatalogPublicationV1,
    journal_snapshot: ProtectedJournalSnapshot,
    configuration_commitment: ObjectDigest,
    manifest_digest: ObjectDigest,
    deadline_seconds: i64,
}

impl core::fmt::Debug for AuthorizedV2MigrationPlanV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedV2MigrationPlanV1([protected one-shot plan])")
    }
}

/// Authenticates one bounded pure migration plan at exact protected heads.
///
/// `canonical_manifest` is the fixed 512-byte `AOSSPMG1` artifact described by
/// this module. It commits the complete supplemental projection, source graph,
/// prospective graph, pure plan, signer identity, policy generation, issuance
/// window, and current trust, revocation, catalog, and configuration heads.
///
/// # Errors
///
/// Returns [`SourceProviderSecurityError`] when the journal is not the sealed
/// namespace-41 authority, custody or catalog is stale, the pure plan is empty
/// or invalid, the manifest differs from any exact plan/current-head fact, the
/// current catalog-publisher key is not eligible, or its signature is invalid.
pub(crate) fn authorize_v2_migration_plan_v1(
    custody: &mut ProtectedProviderCustodyV1,
    journal: &ProtectedJournalAuthority<'_>,
    journal_snapshot: ProtectedJournalSnapshot,
    catalog_publication: VerifiedCatalogPublicationV1,
    provenance: SupplementalV2MigrationProvenanceV1,
    canonical_manifest: &[u8],
) -> Result<AuthorizedV2MigrationPlanV1, SourceProviderSecurityError> {
    journal
        .validate_source_provider_authority_snapshot(&journal_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let configuration = custody.revalidated_configuration()?;
    let configuration_commitment = migration_configuration_commitment(&configuration);
    let plan = plan_aosspl_v2_to_v3(
        journal
            .records()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
        Some(provenance),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let facts = plan_facts(&plan)?;
    let now_seconds = crate::handshake::current_unix_seconds()?;
    let manifest = decode_manifest(canonical_manifest)?;

    let (trust_generation, trust_digest) = configuration.trust_head();
    let (revocation_generation, revocation_digest) = configuration.revocation_head();
    let (valid_from_seconds, valid_until_seconds) = configuration.validity();
    let (publisher_authority_id, publication_generation, _) = catalog_publication.publication();
    let publication_seconds = catalog_publication.issuance().0;
    let publisher_signer = catalog_publication.publisher_signer();
    if manifest.provider != *configuration.provider()
        || catalog_publication.provider() != configuration.provider()
        || catalog_publication.resource_namespace_digest()
            != configuration.resource_namespace_digest()
        || !facts.matches_current_catalog(&configuration, &catalog_publication)
        || manifest.source_graph_digest != facts.source_graph_digest
        || manifest.provenance_digest != facts.provenance_digest
        || manifest.prospective_graph_digest != facts.prospective_graph_digest
        || manifest.plan_digest != facts.plan_digest
        || manifest.policy_generation != publication_generation
        || manifest.trust_head != (trust_generation, trust_digest)
        || manifest.revocation_head != (revocation_generation, revocation_digest)
        || manifest.catalog_head_commitment != facts.catalog_head_commitment
        || manifest.configuration_commitment != configuration_commitment
        || manifest.source_record_count != facts.source_record_count
        || manifest.replacement_record_count != facts.replacement_record_count
        || manifest.source_bytes != facts.source_bytes
        || manifest.replacement_bytes != facts.replacement_bytes
        || manifest.signer_key_id != publisher_signer.key_id()
        || manifest.signer_key_generation != publisher_signer.key_generation()
        || manifest.signer_public_key_digest != publisher_signer.public_key_digest()
        || publisher_signer.authority_id() != publisher_authority_id
        || publisher_signer.usage() != SourceProviderKeyUsageV1::CatalogPublisher
        || manifest.issued_seconds > now_seconds
        || now_seconds >= manifest.deadline_seconds
        || manifest.issued_seconds < publication_seconds.max(valid_from_seconds)
        || manifest.deadline_seconds > valid_until_seconds
        || manifest
            .deadline_seconds
            .checked_sub(manifest.issued_seconds)
            .is_none_or(|duration| duration > 86_400)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    verify_current_publisher_signature(
        &configuration,
        publisher_signer,
        manifest.issued_seconds,
        canonical_manifest,
    )?;
    journal
        .validate_source_provider_authority_snapshot(&journal_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(AuthorizedV2MigrationPlanV1 {
        plan,
        configuration,
        catalog_publication,
        journal_snapshot,
        configuration_commitment,
        manifest_digest: digest_bytes(canonical_manifest),
        deadline_seconds: manifest.deadline_seconds,
    })
}

impl AuthorizedV2MigrationPlanV1 {
    /// Revalidates and releases the authenticated plan to the protected installer.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when time expired, protected
    /// custody changed, the catalog ceased to be the exact current publication,
    /// or the namespace-41 snapshot no longer names the source graph.
    pub(crate) fn consume_for_install(
        self,
        custody: &mut ProtectedProviderCustodyV1,
        journal: &ProtectedJournalAuthority<'_>,
    ) -> Result<AuthorizedV2MigrationInstallPartsV1, SourceProviderSecurityError> {
        let now_seconds = crate::handshake::current_unix_seconds()?;
        if now_seconds >= self.deadline_seconds
            || journal
                .validate_source_provider_authority_snapshot(&self.journal_snapshot)
                .is_err()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let current_configuration = custody.revalidated_configuration()?;
        if migration_configuration_commitment(&current_configuration)
            != self.configuration_commitment
            || migration_configuration_commitment(&self.configuration)
                != self.configuration_commitment
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(AuthorizedV2MigrationInstallPartsV1 {
            plan: self.plan,
            configuration: current_configuration,
            catalog_publication: self.catalog_publication,
            configuration_commitment: self.configuration_commitment,
            manifest_digest: self.manifest_digest,
        })
    }
}

/// Carries authenticated one-shot installer inputs released by security custody.
pub struct AuthorizedV2MigrationInstallPartsV1 {
    plan: AossplV2ToV3MigrationPlanV1,
    configuration: RevalidatedProviderConfigurationV1,
    catalog_publication: VerifiedCatalogPublicationV1,
    configuration_commitment: ObjectDigest,
    manifest_digest: ObjectDigest,
}

impl AuthorizedV2MigrationInstallPartsV1 {
    /// Consumes the parts into their pure plan and exact protected projections.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AossplV2ToV3MigrationPlanV1,
        RevalidatedProviderConfigurationV1,
        VerifiedCatalogPublicationV1,
        ObjectDigest,
        ObjectDigest,
    ) {
        (
            self.plan,
            self.configuration,
            self.catalog_publication,
            self.configuration_commitment,
            self.manifest_digest,
        )
    }
}

struct MigrationManifestV1 {
    provider: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    source_graph_digest: ObjectDigest,
    provenance_digest: ObjectDigest,
    prospective_graph_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    policy_generation: u64,
    issued_seconds: i64,
    deadline_seconds: i64,
    trust_head: (u64, ObjectDigest),
    revocation_head: (u64, ObjectDigest),
    catalog_head_commitment: ObjectDigest,
    configuration_commitment: ObjectDigest,
    source_record_count: u32,
    replacement_record_count: u32,
    source_bytes: u64,
    replacement_bytes: u64,
    signer_key_id: [u8; 16],
    signer_key_generation: u64,
    signer_public_key_digest: ObjectDigest,
}

struct MigrationPlanFactsV1 {
    source_graph_digest: ObjectDigest,
    provenance_digest: ObjectDigest,
    prospective_graph_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    source_record_count: u32,
    replacement_record_count: u32,
    source_bytes: u64,
    replacement_bytes: u64,
    authority: aos_sandbox_source_provider_ledger::ledger::model::AuthorityHeadRecordV1,
    catalog: aos_sandbox_source_provider_ledger::ledger::model::CatalogHeadRecordV1,
    catalog_head_commitment: ObjectDigest,
}

impl MigrationPlanFactsV1 {
    fn matches_current_catalog(
        &self,
        configuration: &RevalidatedProviderConfigurationV1,
        publication: &VerifiedCatalogPublicationV1,
    ) -> bool {
        crate::catalog::configuration_matches_authority(configuration, &self.authority)
            && crate::catalog::publication_matches_catalog(publication, &self.catalog)
    }
}

fn plan_facts(
    plan: &AossplV2ToV3MigrationPlanV1,
) -> Result<MigrationPlanFactsV1, SourceProviderSecurityError> {
    let AossplV2ToV3MigrationPlanV1::Replace {
        source_graph_digest,
        provenance_digest,
        expected_old_records,
        expected_old_heads,
        replacement_records,
        prospective_graph_digest,
    } = plan
    else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    let source_record_count = u32::try_from(expected_old_records.len())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let replacement_record_count = u32::try_from(replacement_records.len())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let source_bytes = sum_legacy_bytes(expected_old_records)?;
    let replacement_bytes = sum_replacement_bytes(replacement_records)?;
    let mut authority = None;
    for record in replacement_records {
        if let aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Authority(
            value,
        ) = aos_sandbox_source_provider_ledger::ledger::format::decode_record(
            record.key(),
            record.value(),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        {
            if authority.replace(value).is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        }
    }
    let authority = authority.ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let mut catalog = None;
    for record in replacement_records {
        if let aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Catalog(value) =
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                record.key(),
                record.value(),
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            && value.catalog_generation == authority.catalog_generation
            && value.catalog_digest == authority.catalog_digest
        {
            if catalog.replace(value).is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        }
    }
    let catalog = catalog.ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let catalog_head_commitment =
        crate::catalog::current_catalog_projection(&catalog).head_commitment();

    let mut hasher = Sha256::new();
    hasher.update(PLAN_DOMAIN);
    hasher.update(source_graph_digest.as_bytes());
    hasher.update(provenance_digest.as_bytes());
    hasher.update(prospective_graph_digest.as_bytes());
    hasher.update(source_record_count.to_be_bytes());
    hasher.update(replacement_record_count.to_be_bytes());
    hasher.update(source_bytes.to_be_bytes());
    hasher.update(replacement_bytes.to_be_bytes());
    hash_legacy_records(&mut hasher, expected_old_records);
    hash_legacy_records(&mut hasher, expected_old_heads);
    for record in replacement_records {
        hasher.update((record.key().len() as u32).to_be_bytes());
        hasher.update(record.key());
        hasher.update((record.value().len() as u32).to_be_bytes());
        hasher.update(record.value());
    }

    Ok(MigrationPlanFactsV1 {
        source_graph_digest: *source_graph_digest,
        provenance_digest: *provenance_digest,
        prospective_graph_digest: *prospective_graph_digest,
        plan_digest: ObjectDigest::from_bytes(hasher.finalize().into()),
        source_record_count,
        replacement_record_count,
        source_bytes,
        replacement_bytes,
        authority,
        catalog,
        catalog_head_commitment,
    })
}

fn verify_current_publisher_signature(
    configuration: &RevalidatedProviderConfigurationV1,
    signer: &SourceProviderSigningKeyV1,
    issued_seconds: i64,
    canonical_manifest: &[u8],
) -> Result<(), SourceProviderSecurityError> {
    let (trust_generation, trust_digest) = configuration.trust_head();
    let (revocation_generation, revocation_digest) = configuration.revocation_head();
    let trusted = configuration
        .historical_public_keys()
        .iter()
        .find(|candidate| candidate.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let (state, _) = trusted.state_and_successor();
    let (_, _, authority_state) = trusted.authority_issuance();
    if state != SourceProviderKeyTrustStateV1::Eligible
        || authority_state != SourceProviderAuthorityTrustStateV1::Trusted
        || trusted.trust_head() != (trust_generation, trust_digest)
        || trusted.revocation_head() != (revocation_generation, revocation_digest)
        || !configuration.authenticates_historical_key_at(
            trusted,
            issued_seconds,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
        )
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let verifying_key = VerifyingKey::from_bytes(trusted.public_key())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let signature = Signature::from_slice(
        canonical_manifest
            .get(SIGNATURE_OFFSET..MANIFEST_BYTES)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNATURE_OFFSET);
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(
        canonical_manifest
            .get(..SIGNATURE_OFFSET)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?,
    );
    verifying_key
        .verify_strict(&signed, &signature)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn decode_manifest(bytes: &[u8]) -> Result<MigrationManifestV1, SourceProviderSecurityError> {
    decode_manifest_with_magic(bytes, MANIFEST_MAGIC)
}

fn decode_manifest_with_magic(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<MigrationManifestV1, SourceProviderSecurityError> {
    if bytes.len() != MANIFEST_BYTES
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(MANIFEST_VERSION.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0_u8; 6].as_slice())
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let provider = aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1::new(
        array(bytes, 16)?,
        u64_at(bytes, 32)?,
        digest_at(bytes, 40)?,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let manifest = MigrationManifestV1 {
        provider,
        source_graph_digest: digest_at(bytes, 72)?,
        provenance_digest: digest_at(bytes, 104)?,
        prospective_graph_digest: digest_at(bytes, 136)?,
        plan_digest: digest_at(bytes, 168)?,
        policy_generation: u64_at(bytes, 200)?,
        issued_seconds: i64_at(bytes, 208)?,
        deadline_seconds: i64_at(bytes, 216)?,
        trust_head: (u64_at(bytes, 224)?, digest_at(bytes, 232)?),
        revocation_head: (u64_at(bytes, 264)?, digest_at(bytes, 272)?),
        catalog_head_commitment: digest_at(bytes, 304)?,
        configuration_commitment: digest_at(bytes, 336)?,
        source_record_count: u32_at(bytes, 368)?,
        replacement_record_count: u32_at(bytes, 372)?,
        source_bytes: u64_at(bytes, 376)?,
        replacement_bytes: u64_at(bytes, 384)?,
        signer_key_id: array(bytes, 392)?,
        signer_key_generation: u64_at(bytes, 408)?,
        signer_public_key_digest: digest_at(bytes, 416)?,
    };
    if manifest.policy_generation == 0
        || manifest.issued_seconds < 0
        || manifest.deadline_seconds <= manifest.issued_seconds
        || manifest.source_record_count == 0
        || manifest.replacement_record_count == 0
        || manifest.source_bytes == 0
        || manifest.replacement_bytes == 0
        || manifest.signer_key_id == [0; 16]
        || manifest.signer_key_generation == 0
        || [
            manifest.source_graph_digest,
            manifest.provenance_digest,
            manifest.prospective_graph_digest,
            manifest.plan_digest,
            manifest.trust_head.1,
            manifest.revocation_head.1,
            manifest.catalog_head_commitment,
            manifest.configuration_commitment,
            manifest.signer_public_key_digest,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(manifest)
}

pub(crate) fn migration_configuration_commitment(
    configuration: &RevalidatedProviderConfigurationV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(CONFIGURATION_DOMAIN);
    hasher.update(configuration.provider().authority_id());
    hasher.update(
        configuration
            .provider()
            .authority_generation()
            .to_be_bytes(),
    );
    hasher.update(configuration.provider().authority_digest().as_bytes());
    let (trust_generation, trust_digest) = configuration.trust_head();
    let (revocation_generation, revocation_digest) = configuration.revocation_head();
    let (route_id, route_generation, route_digest) = configuration.route_head();
    let (valid_from, valid_until) = configuration.validity();
    hasher.update(trust_generation.to_be_bytes());
    hasher.update(trust_digest.as_bytes());
    hasher.update(revocation_generation.to_be_bytes());
    hasher.update(revocation_digest.as_bytes());
    hasher.update(route_id);
    hasher.update(route_generation.to_be_bytes());
    hasher.update(route_digest.as_bytes());
    hasher.update(configuration.resource_namespace_digest().as_bytes());
    hasher.update(valid_from.to_be_bytes());
    hasher.update(valid_until.to_be_bytes());
    hasher.update([
        configuration.proof_class_capabilities(),
        u8::from(configuration.supports_recursive()),
        u8::from(configuration.supports_kernel_coupled()),
        0,
    ]);
    hash_signer(&mut hasher, configuration.provider_hello_signer());
    hash_signer(&mut hasher, configuration.provider_outcome_signer());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn hash_signer(hasher: &mut Sha256, signer: &SourceProviderSigningKeyV1) {
    hasher.update(signer.authority_id());
    hasher.update(signer.authority_generation().to_be_bytes());
    hasher.update(signer.authority_digest().as_bytes());
    hasher.update(signer.key_id());
    hasher.update(signer.key_generation().to_be_bytes());
    hasher.update(signer.public_key_digest().as_bytes());
    hasher.update([signer.usage() as u8]);
}

fn hash_legacy_records(
    hasher: &mut Sha256,
    records: &[aos_sandbox_source_provider_ledger::migration::LegacyRecordExpectationV1],
) {
    hasher.update((records.len() as u32).to_be_bytes());
    for record in records {
        hasher.update((record.key().len() as u32).to_be_bytes());
        hasher.update(record.key());
        hasher.update(record.record_digest().as_bytes());
    }
}

fn sum_legacy_bytes(
    records: &[aos_sandbox_source_provider_ledger::migration::LegacyRecordExpectationV1],
) -> Result<u64, SourceProviderSecurityError> {
    records
        .iter()
        .try_fold(0_u64, |total, record| {
            total
                .checked_add(u64::try_from(record.key().len()).ok()?)
                .and_then(|value| value.checked_add(32))
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn sum_replacement_bytes(
    records: &[aos_sandbox_source_provider_ledger::migration::MigrationReplacementRecordV1],
) -> Result<u64, SourceProviderSecurityError> {
    records
        .iter()
        .try_fold(0_u64, |total, record| {
            total
                .checked_add(u64::try_from(record.key().len()).ok()?)
                .and_then(|value| value.checked_add(u64::try_from(record.value().len()).ok()?))
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, SourceProviderSecurityError> {
    Ok(ObjectDigest::from_bytes(array(bytes, offset)?))
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], SourceProviderSecurityError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, SourceProviderSecurityError> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}

fn i64_at(bytes: &[u8], offset: usize) -> Result<i64, SourceProviderSecurityError> {
    Ok(i64::from_be_bytes(array(bytes, offset)?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, SourceProviderSecurityError> {
    Ok(u32::from_be_bytes(array(bytes, offset)?))
}
