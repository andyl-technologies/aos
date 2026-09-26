//! Pure canonical AOSSPL ledger codec and structural reducer.
//!
//! This crate is the acyclic data boundary shared by protected security
//! custody and the dormant SourceProvider runtime. It owns no journal, key,
//! socket, file descriptor, kernel observation, backend execution, signature,
//! or send authority. Its inputs and outputs are canonical bytes and opaque,
//! nonauthorizing validation seals only.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

pub use aos_sandbox_source_provider_protocol::{
    MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES, NormalizedAcquisitionIntentV1,
};

/// Defines pure deterministic durable identity derivations.
pub mod identity;
pub mod ledger;
/// Defines format-level AOSSPL hard ceilings without runtime configuration.
pub mod limits;
/// Defines a dormant, nonauthorizing AOSSPL v2-to-v3 migration planner.
pub mod migration;

pub use ledger::LedgerFormatErrorV1;
pub use ledger::completion::{
    AcquireCompletionPatchV1, AcquireCompletionPlanV1, AcquireStatusCompletionPlanV1,
    FinalizedCompletionV1, InventoryCompletionPlanV1, InventoryStatusCompletionPlanV1,
    ReleaseCompletionPatchV1, ReleaseCompletionPlanV1, ReleaseRecoveryCompletionPlanV1,
    ReleaseStatusCompletionPlanV1,
};
pub use ledger::evidence::{BackendEvidenceClassV1, BackendEvidenceStateV1, BackendEvidenceV1};
pub use ledger::model::{
    ProviderAcquisitionStateV1, ProviderAttemptStateV1, ProviderAuthorityStateV1,
    ProviderReleaseStateV1, SourceRootIdentityV1,
};
pub use ledger::reopen::ReopenIdentityV1;

/// Proves that one complete prospective record set passed pure structural validation.
pub struct ValidatedProspectiveLedgerV1 {
    graph_digest: ObjectDigest,
}

impl core::fmt::Debug for ValidatedProspectiveLedgerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ValidatedProspectiveLedgerV1([redacted])")
    }
}

impl ValidatedProspectiveLedgerV1 {
    /// Returns the stable commitment to the sorted canonical graph.
    #[must_use]
    pub const fn graph_digest(&self) -> ObjectDigest {
        self.graph_digest
    }
}

/// Validates a whole current-to-prospective AOSSPL transition.
///
/// Existing immutable catalog and historical records remain byte exact. The
/// provider identity, namespace, route, capabilities, and validity start remain
/// frozen; equal-generation heads remain digest-identical and mutable heads may
/// only advance monotonically. Both graphs independently pass the same complete
/// structural validator used by protected recovery.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for malformed graphs, deletion of retained
/// evidence, immutable-history rewrites, or discontinuous authority heads.
pub fn validate_prospective_transition<'current, 'prospective>(
    current_records: impl IntoIterator<Item = (&'current [u8], &'current [u8])>,
    prospective_records: impl IntoIterator<Item = (&'prospective [u8], &'prospective [u8])>,
) -> Result<ValidatedProspectiveLedgerV1, LedgerFormatErrorV1> {
    use ledger::model::DecodedRecordV1;

    let current = collect_bounded_records(current_records)?;
    let prospective = collect_bounded_records(prospective_records)?;
    if current.is_empty() {
        return validate_prospective_records(
            prospective
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        );
    }
    validate_prospective_records(
        current
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    let validated = validate_prospective_records(
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;

    let current_authority = current
        .iter()
        .find_map(
            |(key, value)| match ledger::format::decode_record(key, value).ok()? {
                DecodedRecordV1::Authority(authority) => Some(authority),
                _ => None,
            },
        )
        .ok_or(LedgerFormatErrorV1::Corrupt("missing current authority"))?;
    let prospective_authority = prospective
        .iter()
        .find_map(
            |(key, value)| match ledger::format::decode_record(key, value).ok()? {
                DecodedRecordV1::Authority(authority) => Some(authority),
                _ => None,
            },
        )
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "missing prospective authority",
        ))?;
    if current_authority.provider.authority_id() != prospective_authority.provider.authority_id()
        || current_authority.route_id != prospective_authority.route_id
        || current_authority.route_generation != prospective_authority.route_generation
        || current_authority.route_digest != prospective_authority.route_digest
        || current_authority.resource_namespace_digest
            != prospective_authority.resource_namespace_digest
        || current_authority.proof_class_capabilities
            != prospective_authority.proof_class_capabilities
        || current_authority.supports_recursive != prospective_authority.supports_recursive
        || current_authority.supports_kernel_coupled
            != prospective_authority.supports_kernel_coupled
        || current_authority.valid_from_seconds != prospective_authority.valid_from_seconds
        || prospective_authority.provider.authority_generation()
            < current_authority.provider.authority_generation()
        || (prospective_authority.provider.authority_generation()
            == current_authority.provider.authority_generation()
            && prospective_authority.provider.authority_digest()
                != current_authority.provider.authority_digest())
        || prospective_authority.trust_generation < current_authority.trust_generation
        || (prospective_authority.trust_generation == current_authority.trust_generation
            && prospective_authority.trust_digest != current_authority.trust_digest)
        || prospective_authority.revocation_generation < current_authority.revocation_generation
        || (prospective_authority.revocation_generation == current_authority.revocation_generation
            && prospective_authority.revocation_digest != current_authority.revocation_digest)
        || prospective_authority.catalog_generation < current_authority.catalog_generation
        || (prospective_authority.catalog_generation == current_authority.catalog_generation
            && prospective_authority.catalog_digest != current_authority.catalog_digest)
        || prospective_authority.inventory_generation < current_authority.inventory_generation
        || prospective_authority.last_lease_issue_generation
            < current_authority.last_lease_issue_generation
        || prospective_authority.last_release_generation < current_authority.last_release_generation
        || prospective_authority.revision < current_authority.revision
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "discontinuous protected authority transition",
        ));
    }

    let current_catalog = current
        .iter()
        .find_map(
            |(key, value)| match ledger::format::decode_record(key, value).ok()? {
                DecodedRecordV1::Catalog(catalog)
                    if catalog.catalog_generation == current_authority.catalog_generation =>
                {
                    Some(catalog)
                }
                _ => None,
            },
        )
        .ok_or(LedgerFormatErrorV1::Corrupt("missing current catalog"))?;
    let prospective_catalog = prospective
        .iter()
        .find_map(
            |(key, value)| match ledger::format::decode_record(key, value).ok()? {
                DecodedRecordV1::Catalog(catalog)
                    if catalog.catalog_generation == prospective_authority.catalog_generation =>
                {
                    Some(catalog)
                }
                _ => None,
            },
        )
        .ok_or(LedgerFormatErrorV1::Corrupt("missing prospective catalog"))?;
    if prospective_catalog.catalog_generation > current_catalog.catalog_generation
        && (prospective_catalog.publication_seconds < current_catalog.publication_seconds
            || prospective_catalog.publication_generation <= current_catalog.publication_generation
            || prospective_catalog.publisher_authority_id != current_catalog.publisher_authority_id
            || prospective_catalog.publisher_signer.authority_id()
                != current_catalog.publisher_signer.authority_id()
            || (prospective_catalog.publisher_signer != current_catalog.publisher_signer
                && prospective_catalog.publisher_signer.key_generation()
                    <= current_catalog.publisher_signer.key_generation()))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "discontinuous catalog publication transition",
        ));
    }

    for (key, current_value) in &current {
        let DecodedRecordV1::Session(current_session) =
            ledger::format::decode_record(key, current_value)?
        else {
            continue;
        };
        let prospective_session = prospective
            .get(key)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "holder sequence head was deleted",
            ))
            .and_then(|value| ledger::format::decode_record(key, value))?;
        let DecodedRecordV1::Session(prospective_session) = prospective_session else {
            return Err(LedgerFormatErrorV1::Corrupt(
                "holder sequence head kind changed",
            ));
        };
        if prospective_session.provider.authority_id() != current_session.provider.authority_id()
            || prospective_session.holder.authority_id() != current_session.holder.authority_id()
            || prospective_session.session_generation < current_session.session_generation
            || (prospective_session.holder.authority_generation()
                == current_session.holder.authority_generation()
                && prospective_session.holder.authority_digest()
                    != current_session.holder.authority_digest())
            || prospective_session.holder.authority_generation()
                < current_session.holder.authority_generation()
            || prospective_session.acquisition_sequence_floor
                < current_session.acquisition_sequence_floor
            || prospective_session.next_acquisition_sequence
                < current_session.next_acquisition_sequence
            || prospective_session.acquisition_sequence_floor
                > prospective_session.next_acquisition_sequence
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "holder acquisition sequence head regressed",
            ));
        }
    }

    for (key, current_value) in &current {
        let decoded = ledger::format::decode_record(key, current_value)?;
        match decoded {
            DecodedRecordV1::Catalog(catalog) if prospective.get(key) != Some(current_value) => {
                let rewritten = prospective.contains_key(key);
                let still_referenced =
                    prospective.iter().any(|(candidate_key, candidate_value)| {
                        match ledger::format::decode_record(candidate_key, candidate_value) {
                            Ok(DecodedRecordV1::Attempt(attempt)) => {
                                attempt.response_catalog_generation == catalog.catalog_generation
                                    && attempt.response_catalog_digest == catalog.catalog_digest
                            }
                            Ok(DecodedRecordV1::Acquisition(acquisition)) => {
                                acquisition.catalog_generation == catalog.catalog_generation
                                    && acquisition.catalog_digest == catalog.catalog_digest
                            }
                            _ => false,
                        }
                    });
                if rewritten
                    || catalog.catalog_generation >= prospective_catalog.catalog_floor_generation
                    || still_referenced
                {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "referenced AOSSPL catalog history was rewritten",
                    ));
                }
            }
            DecodedRecordV1::SessionHistory(history)
                if prospective.get(key) != Some(current_value) =>
            {
                let was_current = current.iter().any(|(candidate_key, candidate_value)| {
                    matches!(
                        ledger::format::decode_record(candidate_key, candidate_value),
                        Ok(DecodedRecordV1::Session(ref session))
                            if session.provider == history.provider
                                && session.holder == history.holder
                                && session.session_binding == history.session_binding
                    )
                });
                if !was_current {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "finalized AOSSPL session history was rewritten",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(validated)
}

/// Validates and re-encodes a complete prospective AOSSPL record graph.
///
/// This pure check is the structural half of protected recovery. Callers still
/// authenticate signatures, protected configuration, journal currentness, and
/// backend observations, while this function rejects duplicate identities,
/// malformed or noncanonical bytes, disconnected catalog/session/attempt
/// histories, and invalid acquisition/release reducer shapes.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for malformed, duplicate, noncanonical, or
/// structurally disconnected records and for graph-size overflow.
pub fn validate_prospective_records<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<ValidatedProspectiveLedgerV1, LedgerFormatErrorV1> {
    use ledger::model::{DecodedRecordV1, ProviderAttemptStateV1};

    let mut canonical = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut decoded = Vec::new();
    let mut aggregate_bytes = 0_usize;
    let mut record_count = 0_usize;
    let mut authority_count = 0_usize;
    let mut provider_id = None;
    let mut catalog_generations = BTreeSet::new();
    let mut session_identities = BTreeSet::new();
    let mut attempt_digests = BTreeSet::new();
    let mut acquisition_ids = BTreeSet::new();
    let mut acquisition_sequences = BTreeSet::new();
    let mut release_ids = BTreeSet::new();

    for (key, value) in records {
        record_count = record_count
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger record count",
            ))?;
        aggregate_bytes = aggregate_bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger aggregate bytes",
            ))?;
        if record_count > limits::MAXIMUM_LEDGER_RECORDS
            || aggregate_bytes > limits::MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger aggregate bounds",
            ));
        }
        if canonical.contains_key(key) {
            return Err(LedgerFormatErrorV1::Corrupt("duplicate AOSSPL key"));
        }
        canonical.insert(key.to_vec(), value.to_vec());
        let record = ledger::format::decode_record(key, value)?;
        if ledger::format::encode_decoded_record(&record) != value {
            return Err(LedgerFormatErrorV1::Corrupt("noncanonical AOSSPL record"));
        }
        match &record {
            DecodedRecordV1::Authority(authority) => {
                authority_count = authority_count
                    .checked_add(1)
                    .ok_or(LedgerFormatErrorV1::LimitExceeded("authority head count"))?;
                provider_id = Some(authority.provider.authority_id());
            }
            DecodedRecordV1::Catalog(catalog) => {
                if !catalog_generations.insert(catalog.catalog_generation) {
                    return Err(LedgerFormatErrorV1::Corrupt("duplicate catalog generation"));
                }
            }
            DecodedRecordV1::Session(session) | DecodedRecordV1::SessionHistory(session) => {
                if !session_identities.insert((
                    session.provider.authority_id(),
                    session.holder.authority_id(),
                    session.session_binding,
                    matches!(&record, DecodedRecordV1::SessionHistory(_)),
                )) {
                    return Err(LedgerFormatErrorV1::Corrupt("duplicate session identity"));
                }
            }
            DecodedRecordV1::Attempt(attempt) => {
                if !attempt_digests.insert(attempt.attempt_digest) {
                    return Err(LedgerFormatErrorV1::Corrupt("duplicate attempt digest"));
                }
            }
            DecodedRecordV1::Acquisition(acquisition) => {
                if !acquisition_ids.insert(acquisition.acquisition_id) {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "duplicate acquisition identity",
                    ));
                }
                if !acquisition_sequences.insert((
                    acquisition.holder.authority_id(),
                    acquisition.acquisition_sequence,
                )) {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "duplicate holder acquisition sequence",
                    ));
                }
            }
            DecodedRecordV1::Release(release) => {
                if !release_ids.insert(release.acquisition_id) {
                    return Err(LedgerFormatErrorV1::Corrupt("duplicate release identity"));
                }
            }
        }
        decoded.push(record);
    }
    if authority_count != 1 || catalog_generations.is_empty() {
        return Err(LedgerFormatErrorV1::Corrupt(
            "one authority and retained catalog are required",
        ));
    }
    let current_session_count = decoded
        .iter()
        .filter(|record| matches!(record, DecodedRecordV1::Session(_)))
        .count();
    let historical_session_count = decoded
        .iter()
        .filter(|record| matches!(record, DecodedRecordV1::SessionHistory(_)))
        .count();
    if current_session_count > limits::MAXIMUM_HOLDERS
        || historical_session_count > limits::MAXIMUM_RETAINED_IDENTITIES
        || catalog_generations.len() > limits::MAXIMUM_RETAINED_CATALOG_HEADS
        || attempt_digests
            .len()
            .saturating_add(acquisition_ids.len())
            .saturating_add(release_ids.len())
            > limits::MAXIMUM_RETAINED_IDENTITIES
    {
        return Err(LedgerFormatErrorV1::LimitExceeded(
            "prospective ledger identity count",
        ));
    }
    let provider_id =
        provider_id.ok_or(LedgerFormatErrorV1::Corrupt("missing provider authority"))?;
    for record in &decoded {
        let record_provider = match record {
            DecodedRecordV1::Authority(value) => value.provider.authority_id(),
            DecodedRecordV1::Catalog(value) => value.provider.authority_id(),
            DecodedRecordV1::Session(value) | DecodedRecordV1::SessionHistory(value) => {
                value.provider.authority_id()
            }
            DecodedRecordV1::Attempt(value) => value.provider.authority_id(),
            DecodedRecordV1::Acquisition(value) => value.provider.authority_id(),
            DecodedRecordV1::Release(value) => value.provider.authority_id(),
        };
        if record_provider != provider_id {
            return Err(LedgerFormatErrorV1::Corrupt("foreign provider record"));
        }
    }
    let attempts: Vec<_> = decoded
        .iter()
        .filter_map(|record| match record {
            DecodedRecordV1::Attempt(value) => Some(value),
            _ => None,
        })
        .collect();
    let authority = decoded
        .iter()
        .find_map(|record| match record {
            DecodedRecordV1::Authority(value) => Some(value),
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("missing authority"))?;
    let current_catalog = decoded.iter().find_map(|record| match record {
        DecodedRecordV1::Catalog(value)
            if value.catalog_generation == authority.catalog_generation =>
        {
            Some(value)
        }
        _ => None,
    });
    if current_catalog.is_none_or(|value| value.catalog_digest != authority.catalog_digest) {
        return Err(LedgerFormatErrorV1::Corrupt("authority catalog head"));
    }
    let current_catalog =
        current_catalog.ok_or(LedgerFormatErrorV1::Corrupt("missing current catalog"))?;
    let mut reachable_catalogs = BTreeSet::new();
    let mut cursor = current_catalog;
    loop {
        if !reachable_catalogs.insert(cursor.catalog_generation) {
            return Err(LedgerFormatErrorV1::Corrupt("catalog cycle"));
        }
        if cursor.catalog_generation == cursor.catalog_floor_generation {
            if cursor.catalog_digest != cursor.catalog_floor_digest {
                return Err(LedgerFormatErrorV1::Corrupt("catalog floor anchor"));
            }
            break;
        }
        let predecessor = decoded
            .iter()
            .find_map(|record| match record {
                DecodedRecordV1::Catalog(value)
                    if value.catalog_generation == cursor.predecessor_catalog_generation
                        && value.catalog_digest == cursor.predecessor_catalog_digest =>
                {
                    Some(value)
                }
                _ => None,
            })
            .ok_or(LedgerFormatErrorV1::Corrupt("catalog predecessor"))?;
        if predecessor.catalog_generation >= cursor.catalog_generation
            || predecessor.publication_seconds > cursor.publication_seconds
            || predecessor.publication_generation >= cursor.publication_generation
            || predecessor.publisher_authority_id != cursor.publisher_authority_id
            || predecessor.publisher_signer.authority_id() != cursor.publisher_signer.authority_id()
            || (predecessor.publisher_signer != cursor.publisher_signer
                && predecessor.publisher_signer.key_generation()
                    >= cursor.publisher_signer.key_generation())
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "catalog publication continuity",
            ));
        }
        cursor = predecessor;
    }
    if decoded.iter().any(|record| match record {
        DecodedRecordV1::Catalog(value) => {
            value.catalog_generation >= current_catalog.catalog_floor_generation
                && !reachable_catalogs.contains(&value.catalog_generation)
        }
        _ => false,
    }) {
        return Err(LedgerFormatErrorV1::Corrupt("catalog branch"));
    }
    let sessions: Vec<_> = decoded
        .iter()
        .filter_map(|record| match record {
            DecodedRecordV1::Session(value) | DecodedRecordV1::SessionHistory(value) => Some(value),
            _ => None,
        })
        .collect();
    for current in decoded.iter().filter_map(|record| match record {
        DecodedRecordV1::Session(value) => Some(value),
        _ => None,
    }) {
        let history = decoded.iter().find_map(|record| match record {
            DecodedRecordV1::SessionHistory(value)
                if value.provider == current.provider
                    && value.holder == current.holder
                    && value.session_binding == current.session_binding =>
            {
                Some(value)
            }
            _ => None,
        });
        if history != Some(current) {
            return Err(LedgerFormatErrorV1::Corrupt(
                "current session/history head mismatch",
            ));
        }
    }
    for attempt in &attempts {
        let session = sessions.iter().copied().find(|session| {
            session.provider == attempt.provider
                && session.holder == attempt.holder
                && session.session_binding == attempt.session_binding
                && session.signers[1] == attempt.root_record_signer
                && session.signer_set_commitment == attempt.signer_set_commitment
        });
        if session.is_none_or(|session| {
            attempt.request_sequence < session.request_sequence_floor
                || attempt.request_sequence >= session.next_request_sequence
                || attempt.response_sequence.is_some_and(|sequence| {
                    sequence < session.response_sequence_floor
                        || sequence >= session.next_response_sequence
                })
        }) {
            return Err(LedgerFormatErrorV1::Corrupt("attempt session join"));
        }
        if attempt
            .recovery_predecessor_attempt_digest
            .is_some_and(|predecessor| {
                !attempts
                    .iter()
                    .any(|candidate| candidate.attempt_digest == predecessor)
            })
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "missing recovery predecessor attempt",
            ));
        }
    }
    let acquisitions: Vec<_> = decoded
        .iter()
        .filter_map(|record| match record {
            DecodedRecordV1::Acquisition(value) => Some(value),
            _ => None,
        })
        .collect();
    let releases: Vec<_> = decoded
        .iter()
        .filter_map(|record| match record {
            DecodedRecordV1::Release(value) => Some(value),
            _ => None,
        })
        .collect();
    for attempt in &attempts {
        let Some(predecessor_digest) = attempt.recovery_predecessor_attempt_digest else {
            continue;
        };
        let predecessor = attempts
            .iter()
            .copied()
            .find(|candidate| candidate.attempt_digest == predecessor_digest)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "missing recovery predecessor attempt",
            ))?;
        let predecessor_session_binding =
            attempt
                .recovery_predecessor_session_binding
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "missing recovery predecessor session",
                ))?;
        let current_session = sessions.iter().copied().find(|session| {
            session.provider == attempt.provider
                && session.holder == attempt.holder
                && session.session_binding == attempt.session_binding
        });
        let predecessor_session = sessions.iter().copied().find(|session| {
            session.provider == predecessor.provider
                && session.holder == predecessor.holder
                && session.session_binding == predecessor_session_binding
        });
        let session_fence_matches = current_session.is_some_and(|session| {
            session.revocation_generation == attempt.recovery_revocation_generation
                && session.revocation_digest == attempt.recovery_revocation_digest
        }) && predecessor_session.is_some();
        let pending_fence_matches = attempt.recovery_fence_class != 3
            || (predecessor.state == ProviderAttemptStateV1::Completed
                && predecessor.status
                    == Some(aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending)
                && predecessor.descriptor_commitment
                    == aos_sandbox_source_provider_protocol::empty_descriptor_set_commitment_v1());
        if attempt.method == aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory {
            let holder_succeeds = predecessor.holder == attempt.holder
                || (predecessor.holder.authority_id() == attempt.holder.authority_id()
                    && attempt.holder.authority_generation()
                        > predecessor.holder.authority_generation()
                    && attempt.holder.authority_digest() != predecessor.holder.authority_digest());
            if predecessor.method
                != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
                || predecessor.provider != attempt.provider
                || predecessor.session_binding != predecessor_session_binding
                || predecessor.acquisition_sequence != 0
                || attempt.acquisition_sequence != 0
                || !holder_succeeds
                || !session_fence_matches
                || !pending_fence_matches
            {
                return Err(LedgerFormatErrorV1::Corrupt(
                    "Inventory recovery-session bridge",
                ));
            }
            continue;
        }
        let acquisition = acquisitions
            .iter()
            .copied()
            .find(|acquisition| {
                acquisition.current_attempt_digest == attempt.attempt_digest
                    && acquisition.provider == attempt.provider
                    && acquisition.acquisition_sequence == attempt.acquisition_sequence
            })
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "recovery attempt acquisition join",
            ))?;
        let release_effect_predecessor = releases.iter().any(|release| {
            release.acquisition_id == acquisition.acquisition_id
                && release.effect_attempt_digest == predecessor_digest
        });
        let predecessor_owns_lineage = predecessor.provider == acquisition.provider
            && predecessor.holder == acquisition.holder
            && predecessor.session_binding == predecessor_session_binding
            && predecessor.acquisition_sequence == acquisition.acquisition_sequence
            && (acquisition.effect_attempt_digest == predecessor_digest
                || acquisition.lease_attempt_digest == Some(predecessor_digest)
                || release_effect_predecessor);
        let holder_lineage_matches =
            ledger::reducer::attempt_owns_holder_lineage(&acquisition.holder, attempt);
        if !predecessor_owns_lineage
            || !holder_lineage_matches
            || !session_fence_matches
            || !pending_fence_matches
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "recovery holder-lineage bridge",
            ));
        }
    }
    let mut effect_ids = BTreeSet::new();
    let mut lease_ids = BTreeSet::new();
    let mut lease_generations = BTreeSet::new();
    for acquisition in &acquisitions {
        let holder_head = decoded
            .iter()
            .find_map(|record| match record {
                DecodedRecordV1::Session(session)
                    if session.provider.authority_id() == acquisition.provider.authority_id()
                        && session.holder.authority_id() == acquisition.holder.authority_id() =>
                {
                    Some(session)
                }
                _ => None,
            })
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "acquisition without holder identity floor",
            ))?;
        if !effect_ids.insert(acquisition.effect_id)
            || acquisition
                .lease_id
                .is_some_and(|value| !lease_ids.insert(value))
            || (acquisition.lease_issue_generation > 0
                && !lease_generations.insert(acquisition.lease_issue_generation))
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "duplicate acquisition lineage",
            ));
        }
        if identity::acquire_effect_id_v1(
            acquisition.acquisition_id,
            acquisition.effect_attempt_digest,
        ) != Some(acquisition.effect_id)
            || identity::acquire_backend_plan_id_v1(
                acquisition.normalized_intent.digest(),
                acquisition.catalog_generation,
                acquisition.catalog_digest,
            ) != acquisition.backend_id
            || acquisition.lease_history.iter().any(|lineage| {
                identity::lease_id_v1(
                    acquisition.acquisition_id,
                    lineage.issue_generation,
                    acquisition.backend_id,
                ) != Some(lineage.lease_id)
            })
            || acquisition
                .lease_id
                .zip(
                    (acquisition.lease_issue_generation > 0)
                        .then_some(acquisition.lease_issue_generation),
                )
                .is_some_and(|(lease_id, generation)| {
                    identity::lease_id_v1(
                        acquisition.acquisition_id,
                        generation,
                        acquisition.backend_id,
                    ) != Some(lease_id)
                })
        {
            return Err(LedgerFormatErrorV1::Corrupt("derived acquisition identity"));
        }
        if acquisition.acquisition_sequence < holder_head.acquisition_sequence_floor
            || acquisition.acquisition_sequence >= holder_head.next_acquisition_sequence
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "acquisition outside holder identity floor",
            ));
        }
    }
    let mut release_effect_ids = BTreeSet::new();
    let mut release_generations = BTreeSet::new();
    for release in &releases {
        if !release_effect_ids.insert(release.effect_id)
            || !release_generations.insert(release.release_generation)
            || identity::release_effect_id_v1(
                release.acquisition_id,
                release.effect_attempt_digest,
                release.release_generation,
            ) != Some(release.effect_id)
        {
            return Err(LedgerFormatErrorV1::Corrupt("duplicate Release lineage"));
        }
    }
    if lease_generations.iter().next_back().copied().unwrap_or(0)
        != authority.last_lease_issue_generation
        || release_generations.iter().next_back().copied().unwrap_or(0)
            != authority.last_release_generation
    {
        return Err(LedgerFormatErrorV1::Corrupt("authority generation head"));
    }
    let active_count = acquisitions
        .iter()
        .filter(|value| {
            matches!(
                value.state,
                ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing
            )
        })
        .count() as u64;
    let mut active_by_holder = std::collections::BTreeMap::<[u8; 16], usize>::new();
    for acquisition in &acquisitions {
        if matches!(
            acquisition.state,
            ProviderAcquisitionStateV1::Pending
                | ProviderAcquisitionStateV1::Active
                | ProviderAcquisitionStateV1::Releasing
        ) {
            *active_by_holder
                .entry(acquisition.holder.authority_id())
                .or_default() += 1;
        }
    }
    if active_by_holder
        .values()
        .any(|count| *count > limits::MAXIMUM_ACTIVE_ACQUISITIONS_PER_HOLDER)
    {
        return Err(LedgerFormatErrorV1::LimitExceeded(
            "active acquisitions per holder",
        ));
    }
    if active_count != authority.active_lease_count {
        return Err(LedgerFormatErrorV1::Corrupt("authority active lease count"));
    }
    let (inventory_digest, inventory_count) = ledger::reducer::inventory_state_digest(
        provider_id,
        authority.catalog_generation,
        authority.catalog_digest,
        canonical
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
    )?;
    if inventory_digest != authority.inventory_state_digest || inventory_count != active_count {
        return Err(LedgerFormatErrorV1::Corrupt(
            "authority inventory projection",
        ));
    }
    for record in &decoded {
        match record {
            DecodedRecordV1::Acquisition(acquisition) => {
                let attempt = attempts
                    .iter()
                    .copied()
                    .find(|attempt| attempt.attempt_digest == acquisition.current_attempt_digest)
                    .ok_or(LedgerFormatErrorV1::Corrupt("acquisition attempt join"))?;
                ledger::reducer::validate_acquisition_join(acquisition, attempt)?;
                if acquisition.state == ProviderAcquisitionStateV1::Faulted
                    && acquisition.lease_id.is_some()
                {
                    let lease_attempt_digest =
                        acquisition
                            .lease_attempt_digest
                            .ok_or(LedgerFormatErrorV1::Corrupt(
                                "Faulted acquisition lease attempt",
                            ))?;
                    let lease_attempt = attempts
                        .iter()
                        .copied()
                        .find(|attempt| attempt.attempt_digest == lease_attempt_digest)
                        .ok_or(LedgerFormatErrorV1::Corrupt(
                            "Faulted acquisition lease attempt",
                        ))?;
                    ledger::reducer::validate_retained_lease(acquisition, lease_attempt)?;
                }
            }
            DecodedRecordV1::Release(release) => {
                let acquisition = decoded
                    .iter()
                    .find_map(|record| match record {
                        DecodedRecordV1::Acquisition(value)
                            if value.acquisition_id == release.acquisition_id =>
                        {
                            Some(value)
                        }
                        _ => None,
                    })
                    .ok_or(LedgerFormatErrorV1::Corrupt("orphan release"))?;
                let attempt = attempts
                    .iter()
                    .copied()
                    .find(|attempt| attempt.attempt_digest == release.attempt_digest)
                    .ok_or(LedgerFormatErrorV1::Corrupt("release attempt join"))?;
                ledger::reducer::validate_release_join(acquisition, release, attempt)?;
                if release.state == ProviderReleaseStateV1::Tombstone {
                    let key = ledger::format::acquisition_key(&ledger::model::AcquisitionKeyV1 {
                        provider_id: release.provider.authority_id(),
                        holder_id: release.holder.authority_id(),
                        acquisition_id: release.acquisition_id,
                    });
                    let digest = canonical
                        .get(&key)
                        .ok_or(LedgerFormatErrorV1::Corrupt("Release acquisition bytes"))
                        .and_then(|bytes| ledger::format::record_digest(bytes))?;
                    if release.acquisition_record_digest != digest {
                        return Err(LedgerFormatErrorV1::Corrupt(
                            "Release acquisition-record digest",
                        ));
                    }
                }
            }
            DecodedRecordV1::Session(session) => {
                if session.acquisition_sequence_floor == 0
                    || session.next_acquisition_sequence < session.acquisition_sequence_floor
                {
                    return Err(LedgerFormatErrorV1::Corrupt(
                        "session acquisition sequence floor",
                    ));
                }
                let pending = attempts.iter().filter(|attempt| {
                    attempt.session_binding == session.session_binding
                        && attempt.state == ProviderAttemptStateV1::Reserved
                });
                let pending: Vec<_> = pending.map(|attempt| attempt.attempt_digest).collect();
                if !matches!(
                    (session.pending_attempt_digest, pending.as_slice()),
                    (None, []) | (Some(_), [_])
                ) || session
                    .pending_attempt_digest
                    .zip(pending.first().copied())
                    .is_some_and(|(expected, actual)| expected != actual)
                {
                    return Err(LedgerFormatErrorV1::Corrupt("session pending join"));
                }
                if session.last_completed_attempt_digest.is_some_and(|digest| {
                    !attempts.iter().any(|attempt| {
                        attempt.attempt_digest == digest
                            && attempt.session_binding == session.session_binding
                            && matches!(
                                attempt.state,
                                ProviderAttemptStateV1::Completed | ProviderAttemptStateV1::Retired
                            )
                    })
                }) || attempts.iter().any(|attempt| {
                    attempt.session_binding == session.session_binding
                        && (attempt.request_sequence >= session.next_request_sequence
                            || attempt
                                .response_sequence
                                .is_some_and(|value| value >= session.next_response_sequence))
                }) {
                    return Err(LedgerFormatErrorV1::Corrupt("session sequence head"));
                }
            }
            _ => {}
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.ledger.validated-graph.v1\0");
    for (key, value) in canonical {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value);
    }
    Ok(ValidatedProspectiveLedgerV1 {
        graph_digest: ObjectDigest::from_bytes(hasher.finalize().into()),
    })
}

/// Collects a canonical-ledger candidate under the global count and byte ceilings.
///
/// Bounds are checked before each key or value is cloned into the returned map.
/// This helper performs no decoding and grants no mutation authority.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for count or aggregate-byte overflow, or a
/// duplicate exact key.
pub fn collect_bounded_records<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, LedgerFormatErrorV1> {
    let mut collected = BTreeMap::new();
    let mut aggregate_bytes = 0_usize;
    let mut record_count = 0_usize;

    for (key, value) in records {
        record_count = record_count
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger record count",
            ))?;
        aggregate_bytes = aggregate_bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger aggregate bytes",
            ))?;
        if record_count > limits::MAXIMUM_LEDGER_RECORDS
            || aggregate_bytes > limits::MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(LedgerFormatErrorV1::LimitExceeded(
                "prospective ledger aggregate bounds",
            ));
        }
        if collected.contains_key(key) {
            return Err(LedgerFormatErrorV1::Corrupt("duplicate AOSSPL key"));
        }
        collected.insert(key.to_vec(), value.to_vec());
    }
    Ok(collected)
}
