//! Protected, source-only installation of an offline AOSSPL v2-to-v3 plan.
//!
//! The pure ledger crate decodes legacy bytes and builds a nonauthorizing
//! replacement. This module authenticates the prospective current authority
//! against freshly revalidated custody, applies one whole-snapshot CAS, and
//! retains an opaque retry token when the append result is ambiguous.

use std::collections::BTreeMap;

use aos_sandbox::{JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::migration::AossplV2ToV3MigrationPlanV1;
use sha2::{Digest as _, Sha256};

use crate::RecoveredProviderLedgerV1;
use crate::state::{ProtectedProviderConfigurationV1, ProviderLedgerV1};
use crate::{ProviderLedgerError, ProviderLedgerLimits};

const MIGRATION_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.ledger.migration-v2-to-v3-transaction.v1\0";

/// Reports a completed protected migration or retains its exact ambiguous append.
#[must_use = "an ambiguous migration must be recovered against a reopened journal"]
pub(crate) enum ProtectedAossplMigrationOutcomeV1<'journal> {
    /// Contains the recovered version-3 provider owner.
    Opened(ProviderLedgerV1<'journal>),
    /// Retains the exact authenticated replacement for ambiguity recovery.
    RecoveryRequired(AossplMigrationRecoveryV1),
}

/// Retains one exact authenticated migration transaction after uncertain durability.
pub(crate) struct AossplMigrationRecoveryV1 {
    transaction: JournalTransaction,
    expected_old: Vec<(Vec<u8>, ObjectDigest)>,
    prospective_graph_digest: ObjectDigest,
    protected_configuration_commitment: ObjectDigest,
}

impl core::fmt::Debug for AossplMigrationRecoveryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AossplMigrationRecoveryV1([protected replacement])")
    }
}

impl AossplMigrationRecoveryV1 {
    fn retained_retry(&self) -> Self {
        Self {
            transaction: self.transaction.clone(),
            expected_old: self.expected_old.clone(),
            prospective_graph_digest: self.prospective_graph_digest,
            protected_configuration_commitment: self.protected_configuration_commitment,
        }
    }
}

impl<'journal> ProviderLedgerV1<'journal> {
    /// Authenticates and atomically installs an offline AOSSPL v2-to-v3 migration.
    ///
    /// The current namespace must be the complete canonical v2 source graph.
    /// Empty state continues to use the separate protected initializer. Every
    /// replacement artifact and current head is validated against fresh custody
    /// and the authenticated catalog publication before any journal append.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for empty state, missing or ambiguous
    /// provenance, a stale source snapshot, invalid prospective authority, or
    /// a failed preflight. An uncertain commit is returned as
    /// [`ProtectedAossplMigrationOutcomeV1::RecoveryRequired`].
    pub(crate) fn migrate_aosspl_v2_to_v3_from_fixed_session(
        mut journal: ProtectedJournalAuthority<'journal>,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        limits: ProviderLedgerLimits,
        authorization: aos_sandbox_source_provider_security::AuthorizedV2MigrationPlanV1,
    ) -> Result<ProtectedAossplMigrationOutcomeV1<'journal>, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        let (
            plan,
            protected_configuration,
            catalog,
            protected_configuration_commitment,
            authorization_manifest_digest,
        ) = session
            .consume_fixed_provider_ledger_migration_v1(authorization, &journal)?
            .into_parts();
        let AossplV2ToV3MigrationPlanV1::Replace {
            source_graph_digest,
            provenance_digest,
            expected_old_records,
            replacement_records,
            prospective_graph_digest,
            ..
        } = plan
        else {
            return Err(ProviderLedgerError::MigrationNeedsProvenance(
                "empty AOSSPL namespace requires protected v3 initialization",
            ));
        };

        let expected_old = expected_old_records
            .into_iter()
            .map(|record| (record.key().to_vec(), record.record_digest()))
            .collect::<Vec<_>>();
        exact_legacy_snapshot(&journal, &expected_old)?;
        let replacement = replacement_records
            .iter()
            .map(|record| (record.key().to_vec(), record.value().to_vec()))
            .collect::<Vec<_>>();
        let configuration = ProtectedProviderConfigurationV1::from_revalidated_projections(
            protected_configuration,
            catalog,
            limits,
        )?;
        crate::recovery::recover_records(
            replacement
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            &configuration,
        )?;

        let transaction = JournalTransaction::new(
            migration_transaction_id(
                source_graph_digest,
                provenance_digest,
                prospective_graph_digest,
                authorization_manifest_digest,
            ),
            replacement
                .into_iter()
                .map(|(key, value)| {
                    JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value)
                })
                .collect(),
        )?;
        let snapshot = journal.snapshot()?;
        let preflight = journal.preflight_transactions(std::slice::from_ref(&transaction))?;
        exact_legacy_snapshot(&journal, &expected_old)?;
        journal.validate_source_provider_authority_snapshot(&snapshot)?;
        let before_digest = configuration.deployment_digest();
        let current_security = session.revalidated_provider_configuration()?;
        if current_security.migration_configuration_commitment_v1()
            != protected_configuration_commitment
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        journal.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        if journal.commit(&transaction).is_err() {
            return Ok(ProtectedAossplMigrationOutcomeV1::RecoveryRequired(
                AossplMigrationRecoveryV1 {
                    transaction,
                    expected_old,
                    prospective_graph_digest,
                    protected_configuration_commitment,
                },
            ));
        }
        let recovered =
            match recover_exact_migration(&journal, &configuration, prospective_graph_digest) {
                Ok(recovered) => recovered,
                Err(_) => {
                    return Ok(ProtectedAossplMigrationOutcomeV1::RecoveryRequired(
                        AossplMigrationRecoveryV1 {
                            transaction,
                            expected_old,
                            prospective_graph_digest,
                            protected_configuration_commitment,
                        },
                    ));
                }
            };
        if configuration.deployment_digest() != before_digest {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let ledger = ProviderLedgerV1::from_validated_recovery(journal, configuration, recovered);
        Ok(ProtectedAossplMigrationOutcomeV1::Opened(ledger))
    }

    /// Resolves an uncertain protected migration against a reopened journal.
    ///
    /// Exact version-3 state is recovered without rewriting. Exact legacy
    /// state retries the same globally stable transaction. Any mixed,
    /// compacted, or superseded snapshot fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when neither exact old nor exact new
    /// state is current, custody/catalog authentication changed, or retry
    /// preflight fails. A second uncertain append returns the same opaque form.
    pub(crate) fn recover_aosspl_v2_to_v3_migration(
        mut journal: ProtectedJournalAuthority<'journal>,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        canonical_catalog_publication: &[u8],
        limits: ProviderLedgerLimits,
        recovery: &AossplMigrationRecoveryV1,
    ) -> Result<ProtectedAossplMigrationOutcomeV1<'journal>, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        let protected = session.revalidated_provider_configuration()?;
        if protected.migration_configuration_commitment_v1()
            != recovery.protected_configuration_commitment
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
            &protected,
            canonical_catalog_publication,
        )?;
        let configuration = ProtectedProviderConfigurationV1::from_revalidated_projections(
            protected, catalog, limits,
        )?;
        if exact_replacement_snapshot(&journal, &recovery.transaction)? {
            let recovered_graph = match recover_exact_migration(
                &journal,
                &configuration,
                recovery.prospective_graph_digest,
            ) {
                Ok(recovered_graph) => recovered_graph,
                Err(_) => {
                    return Ok(ProtectedAossplMigrationOutcomeV1::RecoveryRequired(
                        recovery.retained_retry(),
                    ));
                }
            };
            let ledger =
                ProviderLedgerV1::from_validated_recovery(journal, configuration, recovered_graph);
            return Ok(ProtectedAossplMigrationOutcomeV1::Opened(ledger));
        }
        exact_legacy_snapshot(&journal, &recovery.expected_old)?;
        let snapshot = journal.snapshot()?;
        let preflight =
            journal.preflight_transactions(std::slice::from_ref(&recovery.transaction))?;
        journal.validate_source_provider_authority_snapshot(&snapshot)?;
        journal.validate_preflight_for_effect(
            &preflight,
            std::slice::from_ref(&recovery.transaction),
        )?;
        if journal.commit(&recovery.transaction).is_err() {
            return Ok(ProtectedAossplMigrationOutcomeV1::RecoveryRequired(
                recovery.retained_retry(),
            ));
        }
        let recovered_graph = match recover_exact_migration(
            &journal,
            &configuration,
            recovery.prospective_graph_digest,
        ) {
            Ok(recovered_graph) => recovered_graph,
            Err(_) => {
                return Ok(ProtectedAossplMigrationOutcomeV1::RecoveryRequired(
                    recovery.retained_retry(),
                ));
            }
        };
        let ledger =
            ProviderLedgerV1::from_validated_recovery(journal, configuration, recovered_graph);
        Ok(ProtectedAossplMigrationOutcomeV1::Opened(ledger))
    }
}

fn recover_exact_migration(
    journal: &ProtectedJournalAuthority<'_>,
    configuration: &ProtectedProviderConfigurationV1,
    expected_graph_digest: ObjectDigest,
) -> Result<RecoveredProviderLedgerV1, ProviderLedgerError> {
    journal.validate_source_provider_authority()?;
    let graph =
        aos_sandbox_source_provider_ledger::validate_prospective_records(journal.records()?)?;
    if graph.graph_digest() != expected_graph_digest {
        return Err(ProviderLedgerError::Corrupt(
            "installed migration graph commitment differs",
        ));
    }
    crate::recovery::recover(journal, configuration)
}

fn exact_legacy_snapshot(
    journal: &ProtectedJournalAuthority<'_>,
    expected: &[(Vec<u8>, ObjectDigest)],
) -> Result<(), ProviderLedgerError> {
    let current = journal
        .records()?
        .map(|(key, value)| (key.to_vec(), digest_bytes(value)))
        .collect::<BTreeMap<_, _>>();
    let expected = expected.iter().cloned().collect::<BTreeMap<_, _>>();
    if current != expected {
        return Err(ProviderLedgerError::InvalidTransition(
            "legacy migration snapshot changed",
        ));
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    ObjectDigest::from_bytes(digest)
}

fn exact_replacement_snapshot(
    journal: &ProtectedJournalAuthority<'_>,
    transaction: &JournalTransaction,
) -> Result<bool, ProviderLedgerError> {
    let current = journal
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<BTreeMap<_, _>>();
    let replacement = transaction
        .records()
        .iter()
        .filter_map(|record| {
            record
                .value()
                .map(|value| (record.key().to_vec(), value.to_vec()))
        })
        .collect::<BTreeMap<_, _>>();
    Ok(current == replacement && replacement.len() == transaction.records().len())
}

fn migration_transaction_id(
    source_graph_digest: ObjectDigest,
    provenance_digest: ObjectDigest,
    prospective_graph_digest: ObjectDigest,
    authorization_manifest_digest: ObjectDigest,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_TRANSACTION_DOMAIN);
    hasher.update(source_graph_digest.as_bytes());
    hasher.update(provenance_digest.as_bytes());
    hasher.update(prospective_graph_digest.as_bytes());
    hasher.update(authorization_manifest_digest.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}
