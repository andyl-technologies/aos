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

use aos_sandbox::{
    JournalRecord, JournalTransaction, ProtectedJournalAuthority, ProtectedJournalSnapshot,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceStateMigrationDispositionV2, MountSourceStateMigrationPlanV2,
    plan_mount_source_state_migration_v2,
};
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
    ProtectedCurrentCatalogPublicationV1, ProtectedProviderCustodyV1,
    RevalidatedProviderConfigurationV1, SourceProviderSecurityError, VerifiedCatalogPublicationV1,
};

const MANIFEST_MAGIC: &[u8; 8] = b"AOSSPMG1";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_BYTES: usize = 512;
const SIGNATURE_OFFSET: usize = 448;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-provenance.v1\0";
const PLAN_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-plan.v1\0";
const CONFIGURATION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.migration-configuration.v1\0";
const MOUNT_MANIFEST_MAGIC: &[u8; 8] = b"AOSMSMG1";
const MOUNT_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.mount.source-state-migration.v2\0";
const MOUNT_PLAN_DOMAIN: &[u8] = b"aos.sandbox.mount.source-state-migration-plan.v2\0";
const MOUNT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.mount.source-state-migration-transaction.v2\0";

/// Authorizes one exact nonempty `AOSMSA01` to `AOSMSA02` replacement.
pub struct AuthorizedMountSourceStateMigrationV2 {
    plan: MountSourceStateMigrationPlanV2,
    source_records: Vec<(Vec<u8>, Vec<u8>)>,
    provider_configuration: RevalidatedProviderConfigurationV1,
    catalog_publication: ProtectedCurrentCatalogPublicationV1,
    provider_snapshot: ProtectedJournalSnapshot,
    mount_snapshot: ProtectedJournalSnapshot,
    transaction: JournalTransaction,
    configuration_commitment: ObjectDigest,
    manifest_digest: ObjectDigest,
    deadline_seconds: i64,
}

/// Authenticates one exact nonempty AOSMSA01-to-AOSMSA02 migration plan.
///
/// The fixed `AOSMSMG1` manifest uses the same 512-byte field layout as the
/// provider-ledger migration manifest, but its graph digests cover the exact
/// legacy namespace-40 snapshot, supplemental v2 graph, and canonical
/// replacement plan. Its signature has a distinct domain.
///
/// # Errors
///
/// Returns [`SourceProviderSecurityError`] unless both protected snapshots are
/// current, the pure migration planner returns one nonempty exact replacement,
/// every manifest field matches that plan and the current provider/catalog
/// heads, and the current eligible catalog-publisher key verifies the manifest.
pub(crate) fn authorize_mount_source_state_migration_v2(
    custody: &mut ProtectedProviderCustodyV1,
    provider_journal: &ProtectedJournalAuthority<'_>,
    provider_snapshot: ProtectedJournalSnapshot,
    mount_journal: &aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
    mount_snapshot: ProtectedJournalSnapshot,
    catalog_publication: ProtectedCurrentCatalogPublicationV1,
    supplemental_v2_records: &[(Vec<u8>, Vec<u8>)],
    canonical_manifest: &[u8],
) -> Result<AuthorizedMountSourceStateMigrationV2, SourceProviderSecurityError> {
    provider_journal
        .validate_source_provider_authority_snapshot(&provider_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    mount_journal
        .validate_snapshot(&mount_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if !catalog_publication.validate_current(provider_journal) {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let configuration = custody.revalidated_configuration()?;
    let configuration_commitment = migration_configuration_commitment(&configuration);
    let source_records = collect_mount_migration_records(mount_journal)?;
    let plan =
        match plan_mount_source_state_migration_v2(&source_records, Some(supplemental_v2_records))
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        {
            MountSourceStateMigrationDispositionV2::Ready(plan) if !plan.records().is_empty() => {
                plan
            }
            MountSourceStateMigrationDispositionV2::Ready(_)
            | MountSourceStateMigrationDispositionV2::NeedsProvenance { .. }
            | MountSourceStateMigrationDispositionV2::Unsupported => {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        };
    let facts = mount_migration_plan_facts(&source_records, supplemental_v2_records, &plan)?;
    let manifest = decode_mount_manifest(canonical_manifest)?;
    let projection = catalog_publication.projection();
    let now_seconds = crate::handshake::current_unix_seconds()?;
    let (trust_generation, trust_digest) = configuration.trust_head();
    let (revocation_generation, revocation_digest) = configuration.revocation_head();
    let (valid_from_seconds, valid_until_seconds) = configuration.validity();
    let (publisher_authority_id, publication_generation, _) = projection.publication();
    let (publication_seconds, _, _, _, _) = projection.issuance();
    let signer = projection.publisher_signer();
    if manifest.provider != *configuration.provider()
        || !mount_plan_matches_provider(&plan, &configuration)?
        || projection.scope()
            != (
                configuration.provider(),
                configuration.resource_namespace_digest(),
            )
        || manifest.source_graph_digest != facts.source_graph_digest
        || manifest.provenance_digest != facts.provenance_digest
        || manifest.prospective_graph_digest != facts.prospective_graph_digest
        || manifest.plan_digest != facts.plan_digest
        || manifest.policy_generation != publication_generation
        || manifest.trust_head != (trust_generation, trust_digest)
        || manifest.revocation_head != (revocation_generation, revocation_digest)
        || manifest.catalog_head_commitment != projection.head_commitment()
        || manifest.configuration_commitment != configuration_commitment
        || manifest.source_record_count != facts.source_record_count
        || manifest.replacement_record_count != facts.replacement_record_count
        || manifest.source_bytes != facts.source_bytes
        || manifest.replacement_bytes != facts.replacement_bytes
        || manifest.signer_key_id != signer.key_id()
        || manifest.signer_key_generation != signer.key_generation()
        || manifest.signer_public_key_digest != signer.public_key_digest()
        || signer.authority_id() != publisher_authority_id
        || signer.usage() != SourceProviderKeyUsageV1::CatalogPublisher
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
    verify_mount_migration_signature(
        &configuration,
        signer,
        manifest.issued_seconds,
        canonical_manifest,
    )?;
    let manifest_digest = digest_bytes(canonical_manifest);
    let transaction = mount_migration_transaction(&source_records, &plan, manifest_digest)?;
    provider_journal
        .validate_source_provider_authority_snapshot(&provider_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    mount_journal
        .validate_snapshot(&mount_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(AuthorizedMountSourceStateMigrationV2 {
        plan,
        source_records,
        provider_configuration: configuration,
        catalog_publication,
        provider_snapshot,
        mount_snapshot,
        transaction,
        configuration_commitment,
        manifest_digest,
        deadline_seconds: manifest.deadline_seconds,
    })
}

fn mount_plan_matches_provider(
    plan: &MountSourceStateMigrationPlanV2,
    configuration: &RevalidatedProviderConfigurationV1,
) -> Result<bool, SourceProviderSecurityError> {
    let graph =
        aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            plan.records()
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let provider = configuration.provider();
    Ok(graph
        .acquisitions
        .values()
        .all(|row| row.scope.provider_authority_id == provider.authority_id())
        && graph.provider_heads.values().all(|head| {
            head.scope.provider_authority_id == provider.authority_id()
                && head.provider_authority_generation == provider.authority_generation()
                && head.provider_authority_digest == *provider.authority_digest().as_bytes()
        })
        && graph
            .provider_sessions
            .values()
            .all(|session| session.scope.provider_authority_id == provider.authority_id()))
}

/// Reports an atomic Mount-state migration or retains its one-shot authority.
#[must_use = "migration outcomes retain authenticated authority across ambiguity"]
pub enum MountSourceStateMigrationInstallOutcomeV2 {
    /// The exact replacement transaction is current and durably recorded.
    Success,
    /// The exact source, transaction, and authority remain available for retry.
    RecoveryRequired(MountSourceStateMigrationRecoveryV2),
}

/// Retains exact authenticated migration state after a failed or ambiguous commit.
pub struct MountSourceStateMigrationRecoveryV2 {
    error: SourceProviderSecurityError,
    authorization: AuthorizedMountSourceStateMigrationV2,
}

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

/// Installs or revalidates one exact authenticated Mount-state replacement.
///
/// Security retains the authorization throughout preflight, commit, and
/// readback. Any definite or ambiguous failure returns a move-only recovery
/// value rather than discarding the authority required to prove the outcome.
#[must_use]
pub(crate) fn install_mount_source_state_migration_v2(
    custody: &mut ProtectedProviderCustodyV1,
    provider_journal: &ProtectedJournalAuthority<'_>,
    mount_journal: &mut aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
    authorization: AuthorizedMountSourceStateMigrationV2,
) -> MountSourceStateMigrationInstallOutcomeV2 {
    let result = install_or_revalidate_mount_migration(
        custody,
        provider_journal,
        mount_journal,
        &authorization,
    );
    match result {
        Ok(()) => MountSourceStateMigrationInstallOutcomeV2::Success,
        Err(error) => MountSourceStateMigrationInstallOutcomeV2::RecoveryRequired(
            MountSourceStateMigrationRecoveryV2 {
                error,
                authorization,
            },
        ),
    }
}

/// Retries or resolves one exact ambiguous Mount-state migration.
#[must_use]
pub(crate) fn recover_mount_source_state_migration_v2(
    custody: &mut ProtectedProviderCustodyV1,
    provider_journal: &ProtectedJournalAuthority<'_>,
    mount_journal: &mut aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
    recovery: MountSourceStateMigrationRecoveryV2,
) -> MountSourceStateMigrationInstallOutcomeV2 {
    install_mount_source_state_migration_v2(
        custody,
        provider_journal,
        mount_journal,
        recovery.authorization,
    )
}

impl MountSourceStateMigrationRecoveryV2 {
    /// Returns the fail-closed reason while retaining migration authority.
    #[must_use]
    pub const fn error(&self) -> &SourceProviderSecurityError {
        &self.error
    }
}

fn install_or_revalidate_mount_migration(
    custody: &mut ProtectedProviderCustodyV1,
    provider_journal: &ProtectedJournalAuthority<'_>,
    mount_journal: &mut aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
    authorization: &AuthorizedMountSourceStateMigrationV2,
) -> Result<(), SourceProviderSecurityError> {
    // Exact durable replay resolves independently of the now-expired issuance
    // window; that window gates only a first append.
    if mount_migration_target_is_current(mount_journal, authorization)? {
        return Ok(());
    }
    let now_seconds = crate::handshake::current_unix_seconds()?;
    if now_seconds >= authorization.deadline_seconds
        || provider_journal
            .validate_source_provider_authority_snapshot(&authorization.provider_snapshot)
            .is_err()
        || !authorization
            .catalog_publication
            .validate_current(provider_journal)
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let current_configuration = custody.revalidated_configuration()?;
    if migration_configuration_commitment(&current_configuration)
        != authorization.configuration_commitment
        || migration_configuration_commitment(&authorization.provider_configuration)
            != authorization.configuration_commitment
    {
        return Err(SourceProviderSecurityError::Currentness);
    }

    mount_journal
        .validate_snapshot(&authorization.mount_snapshot)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    if collect_mount_migration_records(mount_journal)? != authorization.source_records {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let preflight = mount_journal
        .preflight(&authorization.transaction)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    mount_journal
        .validate_preflight(&preflight, &authorization.transaction)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    mount_journal
        .commit(&authorization.transaction)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    mount_migration_target_is_current(mount_journal, authorization)?
        .then_some(())
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn mount_migration_target_is_current(
    journal: &aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
    authorization: &AuthorizedMountSourceStateMigrationV2,
) -> Result<bool, SourceProviderSecurityError> {
    let current = collect_mount_migration_records(journal)?;
    if current.as_slice() != authorization.plan.records() {
        return Ok(false);
    }
    aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
        current
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    // Exact equality with the authorized whole target is a materialized
    // migration anchor. Journal compaction may replace the original
    // transaction ID, but cannot change these canonically validated records.
    Ok(true)
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

struct MountMigrationPlanFactsV2 {
    source_graph_digest: ObjectDigest,
    provenance_digest: ObjectDigest,
    prospective_graph_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    source_record_count: u32,
    replacement_record_count: u32,
    source_bytes: u64,
    replacement_bytes: u64,
}

fn collect_mount_migration_records(
    journal: &aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES, MAXIMUM_SOURCE_ACQUISITIONS,
        MAXIMUM_SOURCE_HOLDER_SEQUENCES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
        MAXIMUM_SOURCE_PROVIDER_HEADS, MAXIMUM_SOURCE_PROVIDER_SESSIONS,
    };

    let maximum_records = MAXIMUM_SOURCE_ACQUISITIONS
        + MAXIMUM_SOURCE_HOLDER_SEQUENCES
        + MAXIMUM_SOURCE_PROVIDER_ATTEMPTS
        + MAXIMUM_SOURCE_PROVIDER_HEADS
        + MAXIMUM_SOURCE_PROVIDER_SESSIONS;
    let mut records = Vec::new();
    let mut aggregate_bytes = 0usize;
    for (key, value) in journal
        .records()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
    {
        aggregate_bytes = aggregate_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if records.len() >= maximum_records
            || aggregate_bytes > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        records.push((key.to_vec(), value.to_vec()));
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));
    if records.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(records)
}

fn mount_migration_plan_facts(
    source: &[(Vec<u8>, Vec<u8>)],
    provenance: &[(Vec<u8>, Vec<u8>)],
    plan: &MountSourceStateMigrationPlanV2,
) -> Result<MountMigrationPlanFactsV2, SourceProviderSecurityError> {
    let mut canonical_provenance = provenance.iter().collect::<Vec<_>>();
    canonical_provenance.sort_by(|left, right| left.0.cmp(&right.0));
    if canonical_provenance
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let source_graph_digest = digest_mount_records(source.iter().map(|record| record));
    let provenance_digest = digest_mount_records(canonical_provenance.into_iter());
    let prospective_graph_digest = digest_mount_records(plan.records().iter());
    let source_record_count =
        u32::try_from(source.len()).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let replacement_record_count = u32::try_from(plan.records().len())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let source_bytes = sum_mount_record_bytes(source.iter().map(|record| record))?;
    let replacement_bytes = sum_mount_record_bytes(plan.records().iter())?;

    let mut hasher = Sha256::new();
    hasher.update(MOUNT_PLAN_DOMAIN);
    hasher.update(source_graph_digest.as_bytes());
    hasher.update(provenance_digest.as_bytes());
    hasher.update(prospective_graph_digest.as_bytes());
    hasher.update(source_record_count.to_be_bytes());
    hasher.update(replacement_record_count.to_be_bytes());
    hasher.update(source_bytes.to_be_bytes());
    hasher.update(replacement_bytes.to_be_bytes());
    let plan_digest = ObjectDigest::from_bytes(hasher.finalize().into());
    Ok(MountMigrationPlanFactsV2 {
        source_graph_digest,
        provenance_digest,
        prospective_graph_digest,
        plan_digest,
        source_record_count,
        replacement_record_count,
        source_bytes,
        replacement_bytes,
    })
}

fn digest_mount_records<'a>(records: impl Iterator<Item = &'a (Vec<u8>, Vec<u8>)>) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-state-migration-records.v2\0");
    for (key, value) in records {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn sum_mount_record_bytes<'a>(
    mut records: impl Iterator<Item = &'a (Vec<u8>, Vec<u8>)>,
) -> Result<u64, SourceProviderSecurityError> {
    records
        .try_fold(0_u64, |total, (key, value)| {
            total
                .checked_add(u64::try_from(key.len()).ok()?)
                .and_then(|sum| sum.checked_add(u64::try_from(value.len()).ok()?))
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn mount_migration_transaction(
    source: &[(Vec<u8>, Vec<u8>)],
    plan: &MountSourceStateMigrationPlanV2,
    manifest_digest: ObjectDigest,
) -> Result<JournalTransaction, SourceProviderSecurityError> {
    let mut replacements = std::collections::BTreeMap::new();
    for (key, _) in source {
        replacements.insert(key.clone(), None);
    }
    for (key, value) in plan.records() {
        replacements.insert(key.clone(), Some(value.clone()));
    }
    let records = replacements
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => JournalRecord::put(RecordNamespace::MountSourceAcquisition, key, value),
            None => JournalRecord::delete(RecordNamespace::MountSourceAcquisition, key),
        })
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hasher.update(MOUNT_TRANSACTION_DOMAIN);
    hasher.update(manifest_digest.as_bytes());
    hasher.update(digest_mount_records(source.iter()).as_bytes());
    hasher.update(digest_mount_records(plan.records().iter()).as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let transaction_id = digest[..16]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    JournalTransaction::new(transaction_id, records)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
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

fn verify_mount_migration_signature(
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
    let mut signed = Vec::with_capacity(MOUNT_SIGNATURE_DOMAIN.len() + SIGNATURE_OFFSET);
    signed.extend_from_slice(MOUNT_SIGNATURE_DOMAIN);
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

fn decode_mount_manifest(bytes: &[u8]) -> Result<MigrationManifestV1, SourceProviderSecurityError> {
    decode_manifest_with_magic(bytes, MOUNT_MANIFEST_MAGIC)
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
