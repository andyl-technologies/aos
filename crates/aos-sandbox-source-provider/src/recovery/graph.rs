//! Bidirectional attempt, acquisition, release, and artifact graph validation.

use super::*;

pub(super) fn validate_graph(
    configuration: &ProtectedProviderConfigurationV1,
    authority: &crate::model::AuthorityHeadRecordV1,
    catalog: &crate::model::CatalogHeadRecordV1,
    catalog_history: &BTreeMap<u64, crate::model::CatalogHeadRecordV1>,
    session_history: &BTreeMap<
        ([u8; 16], [u8; 16], ObjectDigest),
        crate::model::HolderSessionHeadRecordV1,
    >,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, crate::model::ReleaseRecordV1>,
) -> Result<(), ProviderLedgerError> {
    let mut attempt_digests = BTreeSet::new();
    let mut lease_ids = BTreeSet::new();
    let mut acquisition_ids = BTreeSet::new();
    let mut lease_generations = BTreeSet::new();
    let mut effect_ids = BTreeSet::new();
    let mut release_generations = BTreeSet::new();
    let mut acquisition_sequences = BTreeSet::new();

    for attempt in attempts.values() {
        if !attempt_digests.insert(attempt.attempt_digest) {
            return Err(ProviderLedgerError::Corrupt("duplicate attempt digest"));
        }
    }
    for acquisition in acquisitions.values() {
        if !acquisition_ids.insert(acquisition.acquisition_id) {
            return Err(ProviderLedgerError::Corrupt(
                "globally duplicate acquisition ID",
            ));
        }
        if !acquisition_sequences.insert((
            acquisition.holder.authority_id(),
            acquisition.acquisition_sequence,
        )) || acquisition.acquisition_sequence
            != acquisition.normalized_intent.acquisition_sequence()
        {
            return Err(ProviderLedgerError::Corrupt(
                "duplicate or mismatched acquisition sequence",
            ));
        }
        let holder_head = sessions
            .get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
            ))
            .ok_or(ProviderLedgerError::Corrupt(
                "acquisition without current holder floor",
            ))?;
        if acquisition.acquisition_sequence < holder_head.acquisition_sequence_floor
            || acquisition.acquisition_sequence >= holder_head.next_acquisition_sequence
        {
            return Err(ProviderLedgerError::Corrupt(
                "acquisition outside holder identity floor",
            ));
        }
        if !effect_ids.insert(acquisition.effect_id) {
            return Err(ProviderLedgerError::Corrupt("duplicate acquire effect ID"));
        }
        let attempt = attempts
            .values()
            .find(|attempt| attempt.attempt_digest == acquisition.current_attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("acquisition attempt link"))?;
        if attempt.provider != acquisition.provider || attempt.holder != acquisition.holder {
            return Err(ProviderLedgerError::Corrupt(
                "acquisition attempt authority",
            ));
        }
        let effect_attempt = attempts
            .values()
            .find(|candidate| candidate.attempt_digest == acquisition.effect_attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("acquisition effect attempt"))?;
        if effect_attempt.method != SourceProviderMethod::Acquire
            || effect_attempt.provider != acquisition.provider
            || effect_attempt.holder != acquisition.holder
            || effect_attempt.operation_intent_digest != acquisition.normalized_intent.digest()
            || acquisition.normalized_intent.provider() != &acquisition.provider
            || acquisition.normalized_intent.holder() != &acquisition.holder
            || acquisition.normalized_intent.acquisition_id() != acquisition.acquisition_id
            || effect_attempt.acquisition_sequence != acquisition.acquisition_sequence
            || acquisition.normalized_intent.resource_namespace_digest()
                != acquisition.resource_namespace_digest
            || crate::acquire::derive_acquire_effect_id(
                acquisition.acquisition_id,
                effect_attempt.attempt_digest,
            )? != acquisition.effect_id
            || crate::acquire::derive_backend_plan_id(
                acquisition.normalized_intent.digest(),
                acquisition.catalog_generation,
                acquisition.catalog_digest,
            ) != acquisition.backend_id
        {
            return Err(ProviderLedgerError::Corrupt(
                "acquisition effect-attempt lineage",
            ));
        }
        let acquire_plan = crate::AcquirePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: effect_attempt.session_binding,
            attempt_digest: effect_attempt.attempt_digest,
            acquisition_id: acquisition.acquisition_id,
            effect_id: acquisition.effect_id,
            normalized_intent_digest: acquisition.normalized_intent.digest(),
            backend_id: acquisition.backend_id,
        };
        if acquire_plan.lineage_digest() != acquisition.backend_lineage_digest {
            return Err(ProviderLedgerError::Corrupt(
                "acquisition backend lineage commitment",
            ));
        }
        crate::ledger::reducer::validate_acquisition_join(acquisition, attempt)?;
        let retained_catalog = catalog_history.get(&acquisition.catalog_generation);
        if acquisition.catalog_generation < configuration.catalog_floor_generation()
            || acquisition.catalog_generation > catalog.catalog_generation
            || retained_catalog
                .is_none_or(|retained| retained.catalog_digest != acquisition.catalog_digest)
        {
            return Err(ProviderLedgerError::Corrupt("acquisition catalog floor"));
        }
        match acquisition.state {
            ProviderAcquisitionStateV1::Applying
                if attempt.state == ProviderAttemptStateV1::Reserved
                    && attempt.method == SourceProviderMethod::Acquire
                    && attempt.operation_intent_digest
                        == acquisition.normalized_intent.digest() => {}
            ProviderAcquisitionStateV1::Pending
                if attempt.state == ProviderAttemptStateV1::Completed
                    && attempt.method == SourceProviderMethod::Acquire
                    && attempt.operation_intent_digest
                        == acquisition.normalized_intent.digest() => {}
            ProviderAcquisitionStateV1::Active
                if attempt.state == ProviderAttemptStateV1::Completed => {}
            ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Released => {
                let release = releases
                    .get(&ReleaseKeyV1 {
                        provider_id: acquisition.provider.authority_id(),
                        holder_id: acquisition.holder.authority_id(),
                        acquisition_id: acquisition.acquisition_id,
                    })
                    .ok_or(ProviderLedgerError::Corrupt("missing release lineage"))?;
                let expected = match acquisition.state {
                    ProviderAcquisitionStateV1::Releasing => ProviderReleaseStateV1::Intent,
                    ProviderAcquisitionStateV1::Released => ProviderReleaseStateV1::Tombstone,
                    _ => return Err(ProviderLedgerError::Corrupt("release state")),
                };
                if release.state != expected
                    || acquisition.release_effect_id != Some(release.effect_id)
                    || acquisition.lease_id != Some(release.lease_id)
                    || acquisition.lease_digest != Some(release.lease_digest)
                {
                    return Err(ProviderLedgerError::Corrupt("release lineage mismatch"));
                }
            }
            ProviderAcquisitionStateV1::Faulted => {}
            _ => return Err(ProviderLedgerError::Corrupt("acquisition transition graph")),
        }
        validate_acquisition_artifacts(configuration, acquisition, attempts)?;
        let mut prior_issue_generation = 0;
        if acquisition.lease_history.is_empty() {
            if let (Some(lease_id), generation) =
                (acquisition.lease_id, acquisition.lease_issue_generation)
            {
                if generation == 0
                    || !lease_ids.insert(lease_id)
                    || !lease_generations.insert(generation)
                {
                    return Err(ProviderLedgerError::Corrupt(
                        "compacted current lease lineage",
                    ));
                }
            }
        }
        for lineage in &acquisition.lease_history {
            if !lease_ids.insert(lineage.lease_id)
                || !lease_generations.insert(lineage.issue_generation)
                || lineage.issue_generation <= prior_issue_generation
                || crate::acquire::derive_lease_id(
                    acquisition.acquisition_id,
                    lineage.issue_generation,
                    acquisition.backend_id,
                )? != lineage.lease_id
            {
                return Err(ProviderLedgerError::Corrupt("duplicate lease lineage"));
            }
            prior_issue_generation = lineage.issue_generation;
            let lease_attempt = attempts
                .values()
                .find(|candidate| candidate.attempt_digest == lineage.attempt_digest)
                .ok_or(ProviderLedgerError::Corrupt("lease-history attempt"))?;
            if lease_attempt.method != SourceProviderMethod::Acquire
                || lease_attempt.state != ProviderAttemptStateV1::Completed
                || lease_attempt.status != Some(SourceProviderStatus::Complete)
                || lease_attempt.provider != acquisition.provider
                || lease_attempt.holder != acquisition.holder
                || lease_attempt.operation_intent_digest != acquisition.normalized_intent.digest()
            {
                return Err(ProviderLedgerError::Corrupt("lease-history lineage"));
            }
            let response = decode_acquire_response(&lease_attempt.completed_response)
                .map_err(|_| ProviderLedgerError::Corrupt("lease-history response"))?;
            let receipt_bytes = response
                .signed_receipt()
                .ok_or(ProviderLedgerError::Corrupt("lease-history receipt"))?;
            let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(receipt_bytes)
                .map_err(|_| ProviderLedgerError::Corrupt("lease-history receipt"))?;
            let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
                receipt.subject().signed_export_lease(),
            )
            .map_err(|_| ProviderLedgerError::Corrupt("lease-history lease"))?;
            if lease.subject().lease_id() != lineage.lease_id
                || aos_sandbox_source_provider_protocol::digest_signed_export_lease(&lease)
                    != lineage.lease_digest
                || receipt.subject().lease_digest() != lineage.lease_digest
            {
                return Err(ProviderLedgerError::Corrupt(
                    "lease-history artifact cross-link",
                ));
            }
        }
        if !acquisition.lease_history.is_empty()
            && acquisition.lease_history.last().is_none_or(|lineage| {
                Some(lineage.lease_id) != acquisition.lease_id
                    || Some(lineage.lease_digest) != acquisition.lease_digest
                    || lineage.issue_generation != acquisition.lease_issue_generation
                    || Some(lineage.attempt_digest) != acquisition.lease_attempt_digest
            })
        {
            return Err(ProviderLedgerError::Corrupt(
                "current lease does not reach its predecessor chain",
            ));
        }
    }
    for release in releases.values() {
        if !effect_ids.insert(release.effect_id)
            || !release_generations.insert(release.release_generation)
        {
            return Err(ProviderLedgerError::Corrupt("duplicate release lineage"));
        }
        let acquisition = acquisitions
            .get(&AcquisitionKeyV1 {
                provider_id: release.provider.authority_id(),
                holder_id: release.holder.authority_id(),
                acquisition_id: release.acquisition_id,
            })
            .ok_or(ProviderLedgerError::Corrupt("orphan release"))?;
        if acquisition.release_effect_id != Some(release.effect_id) {
            return Err(ProviderLedgerError::Corrupt("release effect link"));
        }
        let effect_attempt = attempts
            .values()
            .find(|attempt| attempt.attempt_digest == release.effect_attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("release effect-attempt link"))?;
        let attempt = attempts
            .values()
            .find(|attempt| attempt.attempt_digest == release.attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("release current-attempt link"))?;
        if release.backend_id != acquisition.backend_id
            || crate::release::derive_release_effect_id(
                release.acquisition_id,
                release.effect_attempt_digest,
                release.release_generation,
            )? != release.effect_id
        {
            return Err(ProviderLedgerError::Corrupt(
                "release effect or backend identity",
            ));
        }
        let release_plan = crate::ReleasePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: effect_attempt.session_binding,
            attempt_digest: effect_attempt.attempt_digest,
            acquisition_id: acquisition.acquisition_id,
            effect_id: release.effect_id,
            lease_id: release.lease_id,
            lease_digest: release.lease_digest,
            backend_id: release.backend_id,
        };
        if release_plan.lineage_digest() != release.backend_lineage_digest {
            return Err(ProviderLedgerError::Corrupt(
                "release backend lineage commitment",
            ));
        }
        if effect_attempt.method != SourceProviderMethod::Release
            || effect_attempt.provider != release.provider
            || effect_attempt.holder != release.holder
            || effect_attempt.operation_intent_digest != attempt.operation_intent_digest
        {
            return Err(ProviderLedgerError::Corrupt(
                "release effect/current attempt lineage",
            ));
        }
        crate::ledger::reducer::validate_release_join(acquisition, release, attempt)?;
        validate_release_artifacts(
            configuration,
            acquisition,
            release,
            attempts,
            session_history,
        )?;
    }
    let maximum_lease_generation = lease_generations.last().copied().unwrap_or(0);
    let maximum_release_generation = releases
        .values()
        .map(|record| record.release_generation)
        .max()
        .unwrap_or(0);
    if authority.last_lease_issue_generation != maximum_lease_generation
        || authority.last_release_generation != maximum_release_generation
        || lease_generations.iter().any(|generation| *generation == 0)
        || !contiguous_from_one(&release_generations)
    {
        return Err(ProviderLedgerError::Corrupt("authority generation head"));
    }
    validate_attempt_reverse_joins(attempts, acquisitions, releases)?;
    Ok(())
}

pub(super) fn validate_attempt_reverse_joins(
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, crate::model::ReleaseRecordV1>,
) -> Result<(), ProviderLedgerError> {
    for attempt in attempts.values() {
        let acquire_matches = acquisitions
            .values()
            .filter(|record| {
                record.provider == attempt.provider
                    && record.holder == attempt.holder
                    && record.normalized_intent.digest() == attempt.operation_intent_digest
            })
            .count();
        let release_matches = releases
            .values()
            .filter(|record| {
                record.attempt_digest == attempt.attempt_digest
                    || record.effect_attempt_digest == attempt.attempt_digest
            })
            .count();
        let valid = match (attempt.method, attempt.state, attempt.status) {
            (SourceProviderMethod::Acquire, ProviderAttemptStateV1::Reserved, None) => {
                acquire_matches == 1
            }
            (
                SourceProviderMethod::Acquire,
                ProviderAttemptStateV1::Completed,
                Some(SourceProviderStatus::Complete | SourceProviderStatus::Pending),
            ) => acquire_matches == 1,
            (
                SourceProviderMethod::Acquire,
                ProviderAttemptStateV1::Completed,
                Some(SourceProviderStatus::Rejected | SourceProviderStatus::Unavailable),
            ) => acquire_matches == 1,
            (SourceProviderMethod::Release, ProviderAttemptStateV1::Reserved, None) => {
                release_matches == 1
            }
            (
                SourceProviderMethod::Release,
                ProviderAttemptStateV1::Completed,
                Some(
                    SourceProviderStatus::Complete
                    | SourceProviderStatus::Pending
                    | SourceProviderStatus::Unavailable,
                ),
            ) => release_matches == 1,
            (
                SourceProviderMethod::Inventory,
                ProviderAttemptStateV1::Reserved | ProviderAttemptStateV1::Completed,
                _,
            ) => true,
            (_, ProviderAttemptStateV1::Retired, _) => true,
            _ => false,
        };
        if !valid {
            return Err(ProviderLedgerError::Corrupt("attempt reverse lineage"));
        }
    }
    Ok(())
}

pub(super) fn validate_acquisition_artifacts(
    configuration: &ProtectedProviderConfigurationV1,
    acquisition: &crate::model::AcquisitionRecordV1,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
) -> Result<(), ProviderLedgerError> {
    if acquisition.state == ProviderAcquisitionStateV1::Released
        && acquisition.signed_lease.is_empty()
        && acquisition.lease_history.is_empty()
        && acquisition.reopen_identity.is_none()
    {
        return Ok(());
    }
    let retains_lease_artifacts = matches!(
        acquisition.state,
        ProviderAcquisitionStateV1::Active
            | ProviderAcquisitionStateV1::Releasing
            | ProviderAcquisitionStateV1::Released
    ) || (acquisition.state == ProviderAcquisitionStateV1::Faulted
        && !acquisition.signed_lease.is_empty());
    if !retains_lease_artifacts {
        return Ok(());
    }
    let source_root = acquisition
        .source_root
        .ok_or(ProviderLedgerError::Corrupt("active source root"))?;
    let current_attempt = attempts
        .values()
        .find(|attempt| Some(attempt.attempt_digest) == acquisition.lease_attempt_digest)
        .ok_or(ProviderLedgerError::Corrupt(
            "active current Acquire attempt",
        ))?;
    let mut matching = attempts.values().filter(|attempt| {
        if attempt.method != SourceProviderMethod::Acquire
            || Some(attempt.attempt_digest) != acquisition.lease_attempt_digest
            || attempt.state != ProviderAttemptStateV1::Completed
            || attempt.status != Some(SourceProviderStatus::Complete)
            || attempt.operation_intent_digest != acquisition.normalized_intent.digest()
        {
            return false;
        }
        let Ok(response) = decode_acquire_response(&attempt.completed_response) else {
            return false;
        };
        let Some(receipt_bytes) = response.signed_receipt() else {
            return false;
        };
        let Ok(receipt) = SignedSourceProviderReceiptV1::from_canonical_bytes(receipt_bytes) else {
            return false;
        };
        let subject = receipt.subject();
        subject.request_id() == attempt.request_id
            && subject.request_digest() == attempt.typed_request_digest
            && subject.acquisition_id() == acquisition.acquisition_id
            && subject.provider_process_instance() == attempt.provider_process_instance
            && Some(subject.lease_digest()) == acquisition.lease_digest
            && subject.signed_export_lease() == acquisition.signed_lease
            && subject.descriptor_role()
                == aos_sandbox_source_provider_protocol::SourceProviderDescriptorRole::SourceRoot
            && subject.kernel_boot_id() == source_root.kernel_boot_id()
            && subject.device() == source_root.device()
            && subject.inode() == source_root.inode()
            && subject.unique_mount_id() == source_root.unique_mount_id()
            && subject.observed_proof_digest() == acquisition.proof_digest
    });
    if matching.next().is_none() || matching.next().is_some() {
        return Err(ProviderLedgerError::Corrupt(
            "active Acquire receipt lineage",
        ));
    }
    Ok(())
}

pub(super) fn validate_release_artifacts(
    configuration: &ProtectedProviderConfigurationV1,
    acquisition: &crate::model::AcquisitionRecordV1,
    release: &crate::model::ReleaseRecordV1,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    session_history: &BTreeMap<
        ([u8; 16], [u8; 16], ObjectDigest),
        crate::model::HolderSessionHeadRecordV1,
    >,
) -> Result<(), ProviderLedgerError> {
    if record_digest(&encode_acquisition(acquisition))? != release.acquisition_record_digest {
        return Err(ProviderLedgerError::Corrupt(
            "release acquisition-record link",
        ));
    }
    let attempt = attempts
        .values()
        .find(|attempt| attempt.attempt_digest == release.attempt_digest)
        .ok_or(ProviderLedgerError::Corrupt("release attempt link"))?;
    if attempt.method != SourceProviderMethod::Release {
        return Err(ProviderLedgerError::Corrupt("release attempt method"));
    }
    if release.state == ProviderReleaseStateV1::Tombstone {
        let acquired_evidence = acquisition
            .backend_evidence
            .as_ref()
            .ok_or(ProviderLedgerError::Corrupt("missing acquired evidence"))?;
        let released_evidence = release
            .backend_evidence
            .as_ref()
            .ok_or(ProviderLedgerError::Corrupt("missing released evidence"))?;
        if attempt.state != ProviderAttemptStateV1::Completed
            || !matches!(
                attempt.status,
                Some(
                    SourceProviderStatus::Complete
                        | SourceProviderStatus::Pending
                        | SourceProviderStatus::Unavailable
                )
            )
            || released_evidence.class() != acquired_evidence.class()
            || released_evidence.backend_authority_id() != acquired_evidence.backend_authority_id()
            || released_evidence.backend_generation() != acquired_evidence.backend_generation()
            || released_evidence.backend_digest() != acquired_evidence.backend_digest()
            || released_evidence.predecessor_observation_generation()?
                != acquired_evidence.observation_generation()
            || released_evidence.predecessor_observation_digest()?
                != acquired_evidence.observation_digest()
            || release.release_observation_digest != Some(released_evidence.observation_digest())
        {
            return Err(ProviderLedgerError::Corrupt("release completion attempt"));
        }
        let response = decode_release_response(&attempt.completed_response)
            .map_err(|_| ProviderLedgerError::Corrupt("retained Release response"))?;
        let receipt_bytes = match attempt.status {
            Some(SourceProviderStatus::Complete) => response
                .signed_receipt()
                .ok_or(ProviderLedgerError::Corrupt("release tombstone receipt"))?,
            Some(SourceProviderStatus::Pending | SourceProviderStatus::Unavailable)
                if response.signed_receipt().is_none() =>
            {
                release.signed_receipt.as_slice()
            }
            _ => {
                return Err(ProviderLedgerError::Corrupt(
                    "release tombstone response shape",
                ));
            }
        };
        let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(receipt_bytes)
            .map_err(|_| ProviderLedgerError::Corrupt("signed release receipt"))?;
        let session = session_history
            .get(&(
                attempt.provider.authority_id(),
                attempt.holder.authority_id(),
                attempt.session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt(
                "release receipt session floor",
            ))?;
        let receipt_key = configuration
            .historical_public_key_for(
                receipt.signer(),
                receipt.subject().released_seconds(),
                session.trust_generation,
                session.trust_digest,
                session.revocation_generation,
                session.revocation_digest,
            )
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        verify_release_receipt(&receipt, receipt_key)
            .map_err(|_| ProviderLedgerError::Corrupt("release receipt signature"))?;
        if receipt.subject().request_id() != attempt.request_id
            || receipt.subject().request_digest() != attempt.typed_request_digest
            || receipt.subject().lease_id() != release.lease_id
            || receipt.subject().lease_digest() != release.lease_digest
            || receipt.subject().provider() != &release.provider
            || receipt.subject().provider_process_instance() != attempt.provider_process_instance
            || receipt.subject().release_generation() != release.release_generation
            || Some(receipt.subject().released_seconds()) != release.released_seconds
            || receipt.subject().released_seconds() < attempt.verified_at_seconds
            || receipt.subject().released_seconds() >= attempt.current_valid_until_seconds
            || release.receipt_digest != Some(digest_signed_release_receipt(&receipt))
            || release.signed_receipt != receipt.to_canonical_bytes()
            || receipt_bytes != release.signed_receipt
        {
            return Err(ProviderLedgerError::Corrupt("release receipt cross-link"));
        }
    }
    Ok(())
}
