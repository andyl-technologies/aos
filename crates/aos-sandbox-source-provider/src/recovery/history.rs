//! Historical signature, catalog-chain, and retained-count validation.

use super::*;

pub(super) fn validate_historical_signatures(
    configuration: &ProtectedProviderConfigurationV1,
    authority: &crate::model::AuthorityHeadRecordV1,
    catalog_history: &BTreeMap<u64, crate::model::CatalogHeadRecordV1>,
    session_history: &BTreeMap<
        ([u8; 16], [u8; 16], ObjectDigest),
        crate::model::HolderSessionHeadRecordV1,
    >,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, crate::model::ReleaseRecordV1>,
) -> Result<(), ProviderLedgerError> {
    for session in session_history.values() {
        let session_issuance_seconds = attempts
            .values()
            .filter(|attempt| {
                attempt.provider == session.provider
                    && attempt.holder == session.holder
                    && attempt.session_binding == session.session_binding
            })
            .map(|attempt| attempt.verified_at_seconds)
            .min()
            .ok_or(ProviderLedgerError::Corrupt(
                "historical session has no issuance attempt",
            ))?;
        for (bytes, expected_signer, expected_digest) in [
            (
                &session.root_hello,
                &session.signers[0],
                session.root_hello_digest,
            ),
            (
                &session.provider_hello,
                &session.signers[2],
                session.provider_hello_digest,
            ),
        ] {
            let hello = SignedSourceProviderHelloV1::from_canonical_bytes(bytes)
                .map_err(|_| ProviderLedgerError::Corrupt("historical signed hello"))?;
            let key = configuration
                .historical_public_key_for(
                    hello.signer(),
                    session_issuance_seconds,
                    session.trust_generation,
                    session.trust_digest,
                    session.revocation_generation,
                    session.revocation_digest,
                )
                .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
            if hello.signer() != expected_signer
                || aos_sandbox_source_provider_protocol::digest_signed_hello(&hello)
                    != expected_digest
            {
                return Err(ProviderLedgerError::Corrupt("historical hello cross-link"));
            }
            verify_hello(&hello, key)
                .map_err(|_| ProviderLedgerError::Corrupt("historical hello signature"))?;
        }
    }
    for attempt in attempts.values() {
        let session = session_history
            .get(&(
                attempt.provider.authority_id(),
                attempt.holder.authority_id(),
                attempt.session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt("historical attempt session"))?;
        let key_at = |signer: &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
                      issued_seconds: i64| {
            configuration.historical_public_key_for(
                signer,
                issued_seconds,
                session.trust_generation,
                session.trust_digest,
                session.revocation_generation,
                session.revocation_digest,
            )
        };
        if attempt.method == SourceProviderMethod::Inventory
            && attempt.state == ProviderAttemptStateV1::Completed
            && !catalog_history
                .get(&attempt.response_catalog_generation)
                .is_some_and(|catalog| catalog.catalog_digest == attempt.response_catalog_digest)
        {
            return Err(ProviderLedgerError::Corrupt(
                "Inventory response catalog is not retained",
            ));
        }
        if !attempt.signed_request.is_empty() {
            let signed =
                SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
                    .map_err(|_| ProviderLedgerError::Corrupt("historical signed request"))?;
            let key = key_at(signed.signer(), attempt.verified_at_seconds)
                .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
            verify_request(&signed, key)
                .map_err(|_| ProviderLedgerError::Corrupt("historical request signature"))?;
        }
        if attempt.state != ProviderAttemptStateV1::Completed {
            continue;
        }
        let signed_status = completed_status(attempt)?;
        let status_key = key_at(signed_status.signer(), attempt.verified_at_seconds)
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        verify_response_status(&signed_status, status_key)
            .map_err(|_| ProviderLedgerError::Corrupt("historical status signature"))?;
        match attempt.method {
            SourceProviderMethod::Acquire => {
                let response = decode_acquire_response(&attempt.completed_response)
                    .map_err(|_| ProviderLedgerError::Corrupt("historical Acquire response"))?;
                if let Some(bytes) = response.signed_receipt() {
                    let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Corrupt("historical Acquire receipt"))?;
                    let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
                        receipt.subject().signed_export_lease(),
                    )
                    .map_err(|_| ProviderLedgerError::Corrupt("historical export lease"))?;
                    let receipt_key = key_at(receipt.signer(), attempt.verified_at_seconds)
                        .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
                    let lease_key = key_at(lease.signer(), lease.subject().issued_seconds())
                        .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
                    verify_provider_receipt_and_lease(&receipt, receipt_key, lease_key).map_err(
                        |_| ProviderLedgerError::Corrupt("historical Acquire signature graph"),
                    )?;
                    validate_historical_acquire_receipt(&receipt, &lease, attempt, acquisitions)?;
                }
            }
            SourceProviderMethod::Release => {
                let response = decode_release_response(&attempt.completed_response)
                    .map_err(|_| ProviderLedgerError::Corrupt("historical Release response"))?;
                if let Some(bytes) = response.signed_receipt() {
                    let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Corrupt("historical Release receipt"))?;
                    let key = key_at(receipt.signer(), receipt.subject().released_seconds())
                        .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
                    verify_release_receipt(&receipt, key).map_err(|_| {
                        ProviderLedgerError::Corrupt("historical Release signature")
                    })?;
                }
            }
            SourceProviderMethod::Inventory => {
                let response = decode_inventory_response(&attempt.completed_response)
                    .map_err(|_| ProviderLedgerError::Corrupt("historical Inventory response"))?;
                if let Some(bytes) = response.signed_inventory() {
                    let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Corrupt("historical Inventory"))?;
                    let key = key_at(inventory.signer(), attempt.verified_at_seconds)
                        .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
                    verify_inventory(&inventory, key).map_err(|_| {
                        ProviderLedgerError::Corrupt("historical Inventory signature")
                    })?;
                    validate_historical_inventory(
                        inventory.subject(),
                        attempt,
                        authority,
                        catalog_history,
                        acquisitions,
                    )?;
                }
            }
            SourceProviderMethod::Hello => {
                return Err(ProviderLedgerError::Corrupt("historical Hello attempt"));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_historical_acquire_receipt(
    receipt: &SignedSourceProviderReceiptV1,
    lease: &SignedSourceExportLeaseV1,
    attempt: &crate::model::AttemptRecordV1,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
) -> Result<(), ProviderLedgerError> {
    let acquisition = acquisitions
        .values()
        .find(|record| {
            record.provider == attempt.provider
                && record.holder == attempt.holder
                && record.normalized_intent.digest() == attempt.operation_intent_digest
        })
        .ok_or(ProviderLedgerError::Corrupt(
            "historical Acquire acquisition",
        ))?;
    let receipt_subject = receipt.subject();
    let lease_subject = lease.subject();
    let source_root = acquisition.source_root.ok_or(ProviderLedgerError::Corrupt(
        "historical Acquire source root",
    ))?;
    let resource = lease_subject.resource();
    let lease_duration = lease_subject
        .expires_seconds()
        .checked_sub(lease_subject.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok());
    if attempt.status != Some(SourceProviderStatus::Complete)
        || receipt_subject.request_id() != attempt.request_id
        || receipt_subject.request_digest() != attempt.typed_request_digest
        || receipt_subject.acquisition_id() != acquisition.acquisition_id
        || receipt_subject.provider_process_instance() != attempt.provider_process_instance
        || lease_subject.request_id() != attempt.request_id
        || lease_subject.request_digest() != attempt.typed_request_digest
        || lease_subject.holder_authority_id() != acquisition.holder.authority_id()
        || lease_subject.holder_generation() != acquisition.holder.authority_generation()
        || lease_subject.holder_authority_digest() != acquisition.holder.authority_digest()
        || lease_subject.provider() != &acquisition.provider
        || lease_duration.is_none_or(|duration| {
            duration == 0 || duration > acquisition.normalized_intent.requested_lease_seconds()
        })
        || lease_subject.issued_seconds() < attempt.verified_at_seconds
        || lease_subject.issued_seconds() >= attempt.current_valid_until_seconds
        || lease_subject.expires_seconds() > attempt.deadline_seconds
        || lease_subject.expires_seconds() > attempt.current_valid_until_seconds
        || lease_subject.binding_digest() != acquisition.normalized_intent.binding_digest()
        || lease_subject.revocation_digest()
            != acquisition.normalized_intent.holder_revocation_digest()
        || resource.resource_namespace_digest() != acquisition.resource_namespace_digest
        || resource.resource_id() != acquisition.resource_id
        || resource.resource_generation() != acquisition.resource_generation
        || resource.resource_digest() != acquisition.resource_digest
        || resource.catalog_generation() != acquisition.catalog_generation
        || resource.catalog_digest() != acquisition.catalog_digest
        || resource.selection_generation() != acquisition.selection_generation
        || resource.selection_digest() != acquisition.selection_digest
        || aos_sandbox_source_provider_protocol::digest_provider_proof(lease_subject.proof())
            != acquisition.proof_digest
        || receipt_subject.observed_proof_digest() != acquisition.proof_digest
        || receipt_subject.kernel_boot_id() != source_root.kernel_boot_id()
        || receipt_subject.device() != source_root.device()
        || receipt_subject.inode() != source_root.inode()
        || receipt_subject.unique_mount_id() != source_root.unique_mount_id()
    {
        return Err(ProviderLedgerError::Corrupt(
            "historical Acquire artifact cross-link",
        ));
    }
    Ok(())
}

pub(super) fn validate_historical_inventory(
    inventory: &SourceProviderInventoryV1,
    attempt: &crate::model::AttemptRecordV1,
    authority: &crate::model::AuthorityHeadRecordV1,
    catalog_history: &BTreeMap<u64, crate::model::CatalogHeadRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
) -> Result<(), ProviderLedgerError> {
    let catalog = catalog_history
        .get(&inventory.catalog_generation())
        .ok_or(ProviderLedgerError::Corrupt("historical Inventory catalog"))?;
    if inventory.request_id() != attempt.request_id
        || inventory.request_digest() != attempt.typed_request_digest
        || inventory.holder_authority_id() != attempt.holder.authority_id()
        || inventory.holder_generation() != attempt.holder.authority_generation()
        || inventory.holder_authority_digest() != attempt.holder.authority_digest()
        || inventory.provider() != &attempt.provider
        || inventory.provider_process_instance() != attempt.provider_process_instance
        || inventory.catalog_digest() != catalog.catalog_digest
        || inventory.inventory_generation() > authority.inventory_generation
    {
        return Err(ProviderLedgerError::Corrupt(
            "historical Inventory subject cross-link",
        ));
    }

    let mut prior_lease_id = None;
    let mut acquisition_ids = BTreeSet::new();
    for entry in inventory.entries() {
        if prior_lease_id.is_some_and(|prior| prior >= entry.lease_id())
            || !acquisition_ids.insert(entry.acquisition_id())
        {
            return Err(ProviderLedgerError::Corrupt(
                "historical Inventory ordering",
            ));
        }
        prior_lease_id = Some(entry.lease_id());

        let acquisition = acquisitions
            .get(&AcquisitionKeyV1 {
                provider_id: attempt.provider.authority_id(),
                holder_id: attempt.holder.authority_id(),
                acquisition_id: entry.acquisition_id(),
            })
            .ok_or(ProviderLedgerError::Corrupt(
                "historical Inventory acquisition",
            ))?;
        let resource = entry.resource();
        if acquisition.lease_id != Some(entry.lease_id())
            || acquisition.lease_digest != Some(entry.lease_digest())
            || acquisition.resource_namespace_digest != resource.resource_namespace_digest()
            || acquisition.resource_id != resource.resource_id()
            || acquisition.resource_generation != resource.resource_generation()
            || acquisition.resource_digest != resource.resource_digest()
            || acquisition.catalog_generation != resource.catalog_generation()
            || acquisition.catalog_digest != resource.catalog_digest()
            || acquisition.selection_generation != resource.selection_generation()
            || acquisition.selection_digest != resource.selection_digest()
            || acquisition.proof_class != entry.proof_class()
            || acquisition.proof_digest != entry.proof_digest()
            || acquisition.resource_commitment != entry.resource_commitment()
            || !historical_inventory_state_can_advance(entry.state(), acquisition.state)
        {
            return Err(ProviderLedgerError::Corrupt(
                "historical Inventory entry cross-link",
            ));
        }
    }
    Ok(())
}

pub(super) fn historical_inventory_state_can_advance(
    historical: aos_sandbox_source_provider_protocol::InventoryLeaseStateV1,
    current: ProviderAcquisitionStateV1,
) -> bool {
    use aos_sandbox_source_provider_protocol::InventoryLeaseStateV1;

    match historical {
        InventoryLeaseStateV1::Active => matches!(
            current,
            ProviderAcquisitionStateV1::Active
                | ProviderAcquisitionStateV1::Releasing
                | ProviderAcquisitionStateV1::Released
                | ProviderAcquisitionStateV1::Faulted
        ),
        InventoryLeaseStateV1::Reaping => matches!(
            current,
            ProviderAcquisitionStateV1::Releasing
                | ProviderAcquisitionStateV1::Released
                | ProviderAcquisitionStateV1::Faulted
        ),
        InventoryLeaseStateV1::Released => current == ProviderAcquisitionStateV1::Released,
    }
}

pub(super) fn validate_catalog_history(
    configuration: &ProtectedProviderConfigurationV1,
    authority: &crate::model::AuthorityHeadRecordV1,
    catalogs: &BTreeMap<u64, crate::model::CatalogHeadRecordV1>,
) -> Result<(), ProviderLedgerError> {
    for (generation, catalog) in catalogs {
        let publisher_key = configuration
            .historical_key_projection_for(&catalog.publisher_signer)
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        let publication =
            aos_sandbox_source_provider_security::verify_retained_catalog_publication(
                configuration.trust_history(),
                publisher_key,
                &catalog.canonical_publication,
            )?;
        let (
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
        ) = publication.issuance();
        let (publisher_id, publication_generation, publication_receipt_digest) =
            publication.publication();
        let (predecessor_generation, predecessor_digest) = publication.predecessor();
        let (floor_generation, floor_digest) = publication.catalog_floor();
        if *generation != catalog.catalog_generation
            || publication.provider() != &catalog.provider
            || publication.resource_namespace_digest() != catalog.resource_namespace_digest
            || publication.catalog_head() != (catalog.catalog_generation, catalog.catalog_digest)
            || (
                publisher_id,
                publication_generation,
                publication_receipt_digest,
            ) != (
                catalog.publisher_authority_id,
                catalog.publication_generation,
                catalog.publication_receipt_digest,
            )
            || (predecessor_generation, predecessor_digest)
                != (
                    catalog.predecessor_catalog_generation,
                    catalog.predecessor_catalog_digest,
                )
            || (floor_generation, floor_digest)
                != (
                    catalog.catalog_floor_generation,
                    catalog.catalog_floor_digest,
                )
            || (
                publication_seconds,
                publication_trust_generation,
                publication_trust_digest,
                publication_revocation_generation,
                publication_revocation_digest,
            ) != (
                catalog.publication_seconds,
                catalog.publication_trust_generation,
                catalog.publication_trust_digest,
                catalog.publication_revocation_generation,
                catalog.publication_revocation_digest,
            )
            || publication.publisher_signer() != &catalog.publisher_signer
            || catalog.provider.authority_id() != authority.provider.authority_id()
            || catalog.resource_namespace_digest != authority.resource_namespace_digest
            || catalog.catalog_floor_generation > *generation
            || (*generation == configuration.catalog_floor_generation()
                && catalog.catalog_digest != configuration.catalog_floor_digest())
        {
            return Err(ProviderLedgerError::Corrupt(
                "catalog history identity or floor",
            ));
        }
        if *generation < configuration.catalog_floor_generation() {
            // An authenticated, unreachable record below the current floor is
            // staged GC residue. It is never part of the authoritative chain.
            continue;
        } else if *generation == configuration.catalog_floor_generation() {
            // The exact configured floor digest is the authenticated anchor;
            // its predecessor may have been atomically collected.
        } else if catalog.predecessor_catalog_generation == 0 {
            if *generation != configuration.catalog_floor_generation() {
                return Err(ProviderLedgerError::Corrupt(
                    "catalog history discontinuity",
                ));
            }
        } else if catalog.predecessor_catalog_generation >= configuration.catalog_floor_generation()
        {
            let predecessor = catalogs
                .get(&catalog.predecessor_catalog_generation)
                .ok_or(ProviderLedgerError::Corrupt("missing catalog predecessor"))?;
            if catalog.predecessor_catalog_generation >= *generation
                || predecessor.catalog_digest != catalog.predecessor_catalog_digest
            {
                return Err(ProviderLedgerError::Corrupt("catalog predecessor mismatch"));
            }
        } else {
            return Err(ProviderLedgerError::Corrupt(
                "catalog predecessor is below retained floor",
            ));
        }
    }
    let mut reachable = BTreeSet::new();
    let mut generation = authority.catalog_generation;
    loop {
        let catalog = catalogs
            .get(&generation)
            .ok_or(ProviderLedgerError::Corrupt("catalog head chain gap"))?;
        if !reachable.insert(generation) {
            return Err(ProviderLedgerError::Corrupt("catalog head chain cycle"));
        }
        if generation == configuration.catalog_floor_generation() {
            break;
        }
        let predecessor = catalogs
            .get(&catalog.predecessor_catalog_generation)
            .ok_or(ProviderLedgerError::Corrupt("missing catalog predecessor"))?;
        if predecessor.catalog_digest != catalog.predecessor_catalog_digest
            || !authorized_catalog_publisher_successor(predecessor, catalog)
            || predecessor.publication_generation >= catalog.publication_generation
            || predecessor.publication_seconds > catalog.publication_seconds
        {
            return Err(ProviderLedgerError::Corrupt(
                "catalog publisher continuity or publication order",
            ));
        }
        generation = predecessor.catalog_generation;
    }
    if catalogs
        .keys()
        .filter(|generation| **generation >= configuration.catalog_floor_generation())
        .any(|generation| !reachable.contains(generation))
    {
        return Err(ProviderLedgerError::Corrupt(
            "branched or unreachable catalog history",
        ));
    }
    let floor = catalogs
        .get(&configuration.catalog_floor_generation())
        .ok_or(ProviderLedgerError::Corrupt("missing catalog floor anchor"))?;
    let mut residue_reachable = BTreeSet::new();
    let mut predecessor_generation = floor.predecessor_catalog_generation;
    let mut predecessor_digest = floor.predecessor_catalog_digest;
    while predecessor_generation > 0
        && predecessor_generation < configuration.catalog_floor_generation()
    {
        let Some(predecessor) = catalogs.get(&predecessor_generation) else {
            break;
        };
        if predecessor.catalog_digest != predecessor_digest
            || !residue_reachable.insert(predecessor_generation)
        {
            return Err(ProviderLedgerError::Corrupt("catalog GC residue chain"));
        }
        predecessor_generation = predecessor.predecessor_catalog_generation;
        predecessor_digest = predecessor.predecessor_catalog_digest;
    }
    if catalogs
        .keys()
        .filter(|generation| **generation < configuration.catalog_floor_generation())
        .any(|generation| !residue_reachable.contains(generation))
    {
        return Err(ProviderLedgerError::Corrupt("branched catalog GC residue"));
    }
    Ok(())
}

pub(super) fn authorized_catalog_publisher_successor(
    predecessor: &crate::model::CatalogHeadRecordV1,
    successor: &crate::model::CatalogHeadRecordV1,
) -> bool {
    predecessor.publisher_authority_id == successor.publisher_authority_id
        && predecessor.publisher_signer.authority_id() == successor.publisher_signer.authority_id()
        && (predecessor.publisher_signer == successor.publisher_signer
            || (successor.publication_trust_generation > predecessor.publication_trust_generation
                && successor.publisher_signer.key_generation()
                    > predecessor.publisher_signer.key_generation()))
}

pub(super) fn enforce_count_limits(
    configuration: &ProtectedProviderConfigurationV1,
    sessions: &BTreeMap<([u8; 16], [u8; 16]), crate::model::HolderSessionHeadRecordV1>,
    session_history: &BTreeMap<
        ([u8; 16], [u8; 16], ObjectDigest),
        crate::model::HolderSessionHeadRecordV1,
    >,
    attempts: &BTreeMap<AttemptKeyV1, crate::model::AttemptRecordV1>,
    acquisitions: &BTreeMap<AcquisitionKeyV1, crate::model::AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, crate::model::ReleaseRecordV1>,
) -> Result<(), ProviderLedgerError> {
    let limits = configuration.limits();
    let retained_identities = attempts
        .len()
        .checked_add(acquisitions.len())
        .and_then(|count| count.checked_add(releases.len()))
        .ok_or(ProviderLedgerError::LimitExceeded(
            "recovered identity count",
        ))?;
    if sessions.len() > limits.maximum_holders()
        || retained_identities > limits.maximum_retained_identities()
        || session_history.len() > limits.maximum_retained_identities()
    {
        return Err(ProviderLedgerError::LimitExceeded(
            "recovered identity count",
        ));
    }
    let mut active_by_holder = BTreeMap::<[u8; 16], usize>::new();
    for acquisition in acquisitions.values() {
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
        .any(|count| *count > limits.maximum_active_acquisitions_per_holder())
    {
        return Err(ProviderLedgerError::LimitExceeded(
            "active acquisitions per holder",
        ));
    }
    Ok(())
}
