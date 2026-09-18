//! Focused AOSMSA01 domain, initial-head, and Create-projection tests.

use aos_sandbox::journal::JournalLimits;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventorySourceRequestV1, ProviderAuthorityV1, SourceProviderInventoryEntryV1,
    SourceProviderInventoryV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderSigningKeyV1, SourceResourceV1, encode_inventory_request, sign_inventory,
    sign_request,
};
use ed25519_dalek::SigningKey;
use sha2::Digest as _;

use super::checkpoint::{checkpoint_sequences_are_paired, validate_root_query_signer};
use super::history::{validate_global_provider_and_head_history, validate_global_provider_history};
use super::inventory::{
    inventory_floor_proves_terminal_release, inventory_observation_postdates_release,
    inventory_release_ordinals_are_ordered, reconcile_inventory, released_inventory_is_terminal,
    validate_recovered_inventory_projection,
};
use super::validation::validate_checkpoint_sequence_history;
use super::*;

fn pristine_head() -> SourceProviderHeadV1 {
    SourceProviderHeadV1 {
        holder_authority_id: [1; 16],
        holder_generation: 1,
        holder_authority_digest: [2; 32],
        provider_authority_id: [3; 16],
        provider_authority_generation: 1,
        provider_authority_digest: [4; 32],
        session_binding: [5; 32],
        kernel_boot_id: [6; 16],
        next_request_sequence: 1,
        next_response_sequence: 1,
        route_id: [12; 16],
        route_generation: 1,
        route_digest: [7; 32],
        provider_key_generation: 1,
        provider_key_id: [8; 16],
        provider_public_key_digest: [9; 32],
        resource_namespace_digest: [10; 32],
        revocation_digest: [11; 32],
        inventory_observation_ordinal: 0,
        pending_query: None,
        inventory_generation: None,
        inventory_digest: None,
        signed_inventory_digest: None,
        signed_inventory: Vec::new(),
        catalog_generation: None,
        catalog_digest: None,
        last_inventory_checkpoint: None,
        has_untracked_inventory_residuals: false,
        has_inventory_authority_conflicts: false,
    }
}

fn pending_history_row(
    acquisition_id: [u8; 32],
    provider: SourceProviderContextSnapshotV1,
) -> SourceAcquisitionRowV1 {
    SourceAcquisitionRowV1 {
        acquisition_id,
        revision: 1,
        phase: SourceAcquisitionPhaseV1::PendingQuery,
        acquire: SourceAcquisitionOperationV1 {
            operation_id: [1; 16],
            request_digest: [2; 32],
        },
        mount_acquire_request: Vec::new(),
        release: None,
        mount_release_request: None,
        release_authority: None,
        release_provider: None,
        release_inventory_observation_floor: None,
        assignment: SourceAcquisitionAssignmentV1 {
            sandbox_id: [3; 16],
            incarnation_id: [4; 16],
            assignment_epoch: 1,
            desired_generation: 1,
            assignment_digest: [5; 32],
            namespace_generation: 1,
        },
        prospective_mount_template: Vec::new(),
        prospective_mount_template_digest: [6; 32],
        source_binding: Vec::new(),
        source_binding_digest: [7; 32],
        mount_plan_digest: [8; 32],
        ownership_lease_digest: [9; 32],
        provider,
        provider_acquire_request: Vec::new(),
        provider_acquire_request_digest: [10; 32],
        acquire_checkpoint: None,
        acquire_history: Vec::new(),
        evidence: None,
        descriptor_custody_digest: None,
        positive_custody_digest: None,
        consumed_source_pin_record_digest: None,
        consumed_create_effect_record_digest: None,
        consumed_create_operation_record_digest: None,
        provider_release_request: None,
        provider_release_request_digest: None,
        initial_provider_release_request: None,
        initial_provider_release_request_digest: None,
        release_checkpoint: None,
        release_history: Vec::new(),
        release_generation: None,
        provider_inventory_digest: None,
        provider_inventory_observation_ordinal: None,
        negative_custody_digest: None,
        faulted_from: None,
        fault_digest: None,
        retained_faulted_from: None,
        retained_fault_digest: None,
        record_digest: [11; 32],
    }
}

fn provider_context(head: &SourceProviderHeadV1) -> SourceProviderContextSnapshotV1 {
    SourceProviderContextSnapshotV1 {
        holder_authority_id: head.holder_authority_id,
        holder_generation: head.holder_generation,
        holder_authority_digest: head.holder_authority_digest,
        node_id: [13; 16],
        kernel_boot_id: head.kernel_boot_id,
        revocation_digest: head.revocation_digest,
        provider_route_id: head.route_id,
        provider_route_generation: head.route_generation,
        provider_route_digest: head.route_digest,
        provider_authority_id: head.provider_authority_id,
        provider_authority_generation: head.provider_authority_generation,
        provider_authority_digest: head.provider_authority_digest,
        provider_key_id: head.provider_key_id,
        provider_key_generation: head.provider_key_generation,
        provider_public_key_digest: head.provider_public_key_digest,
        resource_namespace_digest: head.resource_namespace_digest,
        session_binding: head.session_binding,
    }
}

fn install_empty_signed_inventory(head: &mut SourceProviderHeadV1, observation_ordinal: u64) {
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        head.provider_authority_id,
        head.provider_authority_generation,
        ObjectDigest::from_bytes(head.provider_authority_digest),
        head.provider_key_id,
        head.provider_key_generation,
        SourceProviderKeyUsageV1::ProviderReceipt,
        &signing_key,
    )
    .expect("valid provider signer");
    head.provider_public_key_digest = *signer.public_key_digest().as_bytes();
    let provider = ProviderAuthorityV1::new(
        head.provider_authority_id,
        head.provider_authority_generation,
        ObjectDigest::from_bytes(head.provider_authority_digest),
        head.provider_key_id,
        head.provider_key_generation,
        ObjectDigest::from_bytes(head.provider_public_key_digest),
    )
    .expect("valid provider authority");
    let inventory = SourceProviderInventoryV1::new(
        [32; 16],
        ObjectDigest::from_bytes([33; 32]),
        head.holder_authority_id,
        head.holder_generation,
        ObjectDigest::from_bytes(head.holder_authority_digest),
        provider,
        [34; 16],
        1,
        ObjectDigest::from_bytes([35; 32]),
        1,
        Vec::new(),
    )
    .expect("valid empty inventory");
    let inventory_digest = *digest_inventory(&inventory).as_bytes();
    let signed = sign_inventory(inventory, signer, &signing_key)
        .expect("signed inventory")
        .to_canonical_bytes();

    head.inventory_generation = Some(1);
    head.inventory_digest = Some(inventory_digest);
    head.signed_inventory_digest = Some(Sha256::digest(&signed).into());
    head.signed_inventory = signed;
    head.catalog_generation = Some(1);
    head.catalog_digest = Some([35; 32]);
    head.inventory_observation_ordinal = observation_ordinal;
}

fn matching_inventory_entry(
    acquisition_id: [u8; 32],
    state: InventoryLeaseStateV1,
) -> (SourceProviderInventoryEntryV1, SourceAcquisitionEvidenceV1) {
    let resource = SourceResourceV1::new(
        ObjectDigest::from_bytes([42; 32]),
        [43; 32],
        1,
        ObjectDigest::from_bytes([44; 32]),
        1,
        ObjectDigest::from_bytes([45; 32]),
        1,
        ObjectDigest::from_bytes([46; 32]),
    )
    .expect("valid provider resource");
    let entry = SourceProviderInventoryEntryV1::new(
        [47; 16],
        ObjectDigest::from_bytes([48; 32]),
        ObjectDigest::from_bytes(acquisition_id),
        state,
        resource,
        2,
        ObjectDigest::from_bytes([49; 32]),
        ObjectDigest::from_bytes([50; 32]),
    )
    .expect("valid provider inventory entry");
    let evidence = SourceAcquisitionEvidenceV1 {
        provider_resource_id: [43; 32],
        provider_resource_generation: 1,
        provider_resource_digest: [50; 32],
        provider_catalog_generation: 1,
        provider_catalog_digest: [45; 32],
        provider_selection_generation: 1,
        provider_selection_digest: [46; 32],
        proof_class: SourceAcquisitionProofClassV1::LocalLive,
        provider_proof_digest: [49; 32],
        lease_id: [47; 16],
        signed_lease_digest: [48; 32],
        lease_issued_seconds: 1,
        lease_expires_seconds: 2,
        source_realization_handle: [51; 32],
        source_physical_proof_digest: [52; 32],
        source_kernel_boot_id: [53; 16],
        source_device: 1,
        source_inode: 2,
        source_unique_mount_id: 3,
        descriptor_commitment: [54; 32],
    };
    (entry, evidence)
}

fn inventory_with_entries(
    head: &SourceProviderHeadV1,
    entries: Vec<SourceProviderInventoryEntryV1>,
) -> SourceProviderInventoryV1 {
    let provider = ProviderAuthorityV1::new(
        head.provider_authority_id,
        head.provider_authority_generation,
        ObjectDigest::from_bytes(head.provider_authority_digest),
        head.provider_key_id,
        head.provider_key_generation,
        ObjectDigest::from_bytes(head.provider_public_key_digest),
    )
    .expect("valid provider authority");
    SourceProviderInventoryV1::new(
        [55; 16],
        ObjectDigest::from_bytes([56; 32]),
        head.holder_authority_id,
        head.holder_generation,
        ObjectDigest::from_bytes(head.holder_authority_digest),
        provider,
        [57; 16],
        1,
        ObjectDigest::from_bytes([58; 32]),
        2,
        entries,
    )
    .expect("valid provider inventory")
}

fn query_signer(
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: [u8; 32],
    usage: SourceProviderKeyUsageV1,
) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        authority_id,
        authority_generation,
        ObjectDigest::from_bytes(authority_digest),
        [21; 16],
        1,
        usage,
        &SigningKey::from_bytes(&[22; 32]),
    )
    .expect("valid test signer")
}

fn historical_inventory_checkpoint(session_binding: [u8; 32]) -> ProviderDispositionCheckpointV1 {
    let authority_id = [1; 16];
    let authority_generation = 2;
    let authority_digest = [3; 32];
    let signing_key = SigningKey::from_bytes(&[22; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        authority_id,
        authority_generation,
        ObjectDigest::from_bytes(authority_digest),
        [21; 16],
        1,
        SourceProviderKeyUsageV1::RootMountQuery,
        &signing_key,
    )
    .expect("valid test signer");
    let query = InventorySourceRequestV1::new(
        ObjectDigest::from_bytes(session_binding),
        1,
        [23; 16],
        authority_id,
        authority_generation,
        ObjectDigest::from_bytes(authority_digest),
        None,
        1,
    )
    .expect("valid Inventory query");
    let signed = sign_request(
        SourceProviderMethod::Inventory,
        encode_inventory_request(&query),
        signer,
        &signing_key,
    )
    .expect("signed Inventory query")
    .to_canonical_bytes();

    ProviderDispositionCheckpointV1 {
        method: ProviderMethodV1::Inventory,
        status: ProviderStatusV1::Pending,
        request_sequence: 1,
        response_sequence: 1,
        signed_request_digest: Sha256::digest(&signed).into(),
        signed_status_digest: [24; 32],
        result_digest: [25; 32],
        signed_request: signed,
        signed_status: Vec::new(),
        signed_result: Vec::new(),
    }
}

#[test]
fn maximum_inventory_uses_one_bounded_durable_byte_copy() {
    const MAXIMUM_SIGNED_INVENTORY_BYTES: usize = 768 * 1024;

    let signed_inventory = vec![u8::MAX; MAXIMUM_SIGNED_INVENTORY_BYTES];
    let mut head = pristine_head();
    let mut checkpoint = historical_inventory_checkpoint([28; 32]);
    checkpoint.status = ProviderStatusV1::Complete;
    checkpoint.signed_result.clear();
    head.signed_inventory_digest = Some(Sha256::digest(&signed_inventory).into());
    head.signed_inventory = signed_inventory.clone();
    head.last_inventory_checkpoint = Some(checkpoint.clone());

    let single_copy = serde_json::to_vec(&StoredEnvelopeV1 {
        schema: SCHEMA.to_owned(),
        version: FORMAT_VERSION,
        record: StoredRecordV1::ProviderHead { head: head.clone() },
    })
    .expect("serializable maximum Inventory head");
    assert!(single_copy.len() <= MAXIMUM_VALUE_BYTES);

    checkpoint.signed_result = signed_inventory;
    head.last_inventory_checkpoint = Some(checkpoint);
    let duplicated = serde_json::to_vec(&StoredEnvelopeV1 {
        schema: SCHEMA.to_owned(),
        version: FORMAT_VERSION,
        record: StoredRecordV1::ProviderHead { head },
    })
    .expect("serializable duplicated Inventory head");
    assert!(duplicated.len() > MAXIMUM_VALUE_BYTES);
}

#[test]
fn inventory_reservation_preflights_one_maximum_head_replacement() {
    let head = pristine_head();
    let key_bytes = provider_head_key(head.holder_authority_id, head.provider_authority_id).len();
    assert_eq!(key_bytes, 66);
    assert_eq!(7 + key_bytes + MAXIMUM_VALUE_BYTES, 4_194_377);
    let reservation = JournalTransaction::new(
        provider_head_transaction_id(&head),
        vec![put_provider_head(&head).expect("valid provider head")],
    )
    .expect("valid reservation transaction");

    let directory = tempfile::tempdir().expect("temporary journal directory");
    let path = directory.path().join("capacity.journal");
    let mut exact_limits = JournalLimits::default();
    exact_limits.maximum_materialized_bytes = key_bytes + MAXIMUM_VALUE_BYTES;
    let (journal, _) = Journal::open(&path, exact_limits).expect("bounded journal");
    assert!(preflight_inventory_completion_capacity(&journal, &reservation, &head).is_ok());
    assert!(journal.is_materialized_empty());

    let short_directory = tempfile::tempdir().expect("short journal directory");
    let short_path = short_directory.path().join("capacity.journal");
    let mut short_limits = JournalLimits::default();
    short_limits.maximum_materialized_bytes = key_bytes + MAXIMUM_VALUE_BYTES - 1;
    let (short_journal, _) =
        Journal::open(&short_path, short_limits).expect("short bounded journal");
    assert!(preflight_inventory_completion_capacity(&short_journal, &reservation, &head).is_err());
    assert!(short_journal.is_materialized_empty());
}

#[test]
fn initial_provider_head_rejects_sequence_and_floor_seeding() {
    let baseline = pristine_head();
    assert!(pristine_provider_head(&baseline));

    let mut sequence_seeded = baseline.clone();
    sequence_seeded.next_request_sequence = 9;
    assert!(!pristine_provider_head(&sequence_seeded));

    let mut observation_seeded = baseline.clone();
    observation_seeded.inventory_observation_ordinal = 1;
    assert!(!pristine_provider_head(&observation_seeded));

    let mut floor_seeded = baseline;
    floor_seeded.inventory_generation = Some(1);
    floor_seeded.inventory_digest = Some([12; 32]);
    assert!(!pristine_provider_head(&floor_seeded));

    let mut conflict_seeded = pristine_head();
    conflict_seeded.has_inventory_authority_conflicts = true;
    assert!(!pristine_provider_head(&conflict_seeded));
}

#[test]
fn pending_admission_history_rejects_cross_head_authority_and_route_equivocation() {
    let first = provider_context(&pristine_head());
    let mut rows = BTreeMap::from([([1; 32], pending_history_row([1; 32], first))]);
    assert!(validate_global_provider_history(&rows).is_ok());

    let mut changed_holder = first;
    changed_holder.provider_authority_id = [14; 16];
    changed_holder.provider_route_id = [15; 16];
    changed_holder.holder_authority_digest[0] ^= 1;
    rows.insert([2; 32], pending_history_row([2; 32], changed_holder));
    assert!(validate_global_provider_history(&rows).is_err());

    let mut changed_provider = first;
    changed_provider.holder_authority_id = [16; 16];
    changed_provider.provider_route_id = [17; 16];
    changed_provider.provider_authority_digest[0] ^= 1;
    rows.insert([2; 32], pending_history_row([2; 32], changed_provider));
    assert!(validate_global_provider_history(&rows).is_err());

    let mut changed_route_scope = first;
    changed_route_scope.holder_authority_id = [18; 16];
    changed_route_scope.provider_authority_id = [19; 16];
    changed_route_scope.provider_authority_digest = [20; 32];
    changed_route_scope.resource_namespace_digest[0] ^= 1;
    rows.insert([2; 32], pending_history_row([2; 32], changed_route_scope));
    assert!(validate_global_provider_history(&rows).is_err());

    rows.insert([2; 32], pending_history_row([2; 32], first));
    assert!(validate_global_provider_history(&rows).is_ok());
}

#[test]
fn provider_head_rejects_unreachable_direction_arithmetic() {
    let mut idle = pristine_head();
    assert!(idle.validate().is_ok());

    idle.next_response_sequence = 2;
    assert!(idle.validate().is_err());

    let mut impossible_lead = pristine_head();
    impossible_lead.next_request_sequence = 3;
    assert!(impossible_lead.validate().is_err());
}

#[test]
fn live_session_changes_reject_current_and_historical_binding_reuse() {
    let first = pristine_head();
    let mut duplicate = pristine_head();
    duplicate.holder_authority_id = [26; 16];
    duplicate.provider_authority_id = [27; 16];
    let duplicate_heads = BTreeMap::from([
        (
            (first.holder_authority_id, first.provider_authority_id),
            first.clone(),
        ),
        (
            (
                duplicate.holder_authority_id,
                duplicate.provider_authority_id,
            ),
            duplicate,
        ),
    ]);
    assert!(validate_checkpoint_sequence_history(&BTreeMap::new(), &duplicate_heads).is_err());

    let historical_binding = [28; 32];
    let mut historical_row = pending_history_row([1; 32], provider_context(&first));
    historical_row.acquire_history = vec![historical_inventory_checkpoint(historical_binding)];
    let rows = BTreeMap::from([([1; 32], historical_row)]);
    let mut replacement = first;
    replacement.session_binding = historical_binding;
    let replacement_heads = BTreeMap::from([(
        (
            replacement.holder_authority_id,
            replacement.provider_authority_id,
        ),
        replacement.clone(),
    )]);
    assert!(validate_checkpoint_sequence_history(&rows, &replacement_heads).is_err());

    replacement.session_binding = [29; 32];
    let fresh_heads = BTreeMap::from([(
        (
            replacement.holder_authority_id,
            replacement.provider_authority_id,
        ),
        replacement,
    )]);
    assert!(validate_checkpoint_sequence_history(&rows, &fresh_heads).is_ok());
}

#[test]
fn current_heads_participate_in_global_provider_history() {
    let first = pristine_head();
    let mut conflicting = pristine_head();
    conflicting.holder_authority_id = [30; 16];
    conflicting.route_id = [31; 16];
    conflicting.provider_authority_digest[0] ^= 1;
    let mut heads = BTreeMap::from([(
        (first.holder_authority_id, first.provider_authority_id),
        first,
    )]);
    heads.insert(
        (
            conflicting.holder_authority_id,
            conflicting.provider_authority_id,
        ),
        conflicting,
    );
    assert!(validate_global_provider_and_head_history(&BTreeMap::new(), &heads).is_err());

    let first = pristine_head();
    let mut conflicting_route = pristine_head();
    conflicting_route.holder_authority_id = [32; 16];
    conflicting_route.provider_authority_id = [33; 16];
    conflicting_route.provider_authority_digest = [34; 32];
    conflicting_route.resource_namespace_digest[0] ^= 1;
    let heads = BTreeMap::from([
        (
            (first.holder_authority_id, first.provider_authority_id),
            first,
        ),
        (
            (
                conflicting_route.holder_authority_id,
                conflicting_route.provider_authority_id,
            ),
            conflicting_route,
        ),
    ]);
    assert!(validate_global_provider_and_head_history(&BTreeMap::new(), &heads).is_err());
}

#[test]
fn provider_disposition_coordinates_are_lockstep() {
    assert!(checkpoint_sequences_are_paired(1, 1));
    assert!(!checkpoint_sequences_are_paired(2, 1));
    assert!(!checkpoint_sequences_are_paired(1, 2));
}

#[test]
fn every_reserved_query_reproduces_root_mount_signer_authority() {
    let authority_id = [1; 16];
    let authority_generation = 2;
    let authority_digest = [3; 32];
    let signer = query_signer(
        authority_id,
        authority_generation,
        authority_digest,
        SourceProviderKeyUsageV1::RootMountQuery,
    );
    assert!(
        validate_root_query_signer(
            &signer,
            authority_id,
            authority_generation,
            authority_digest
        )
        .is_ok()
    );

    let wrong_id = query_signer(
        [4; 16],
        authority_generation,
        authority_digest,
        SourceProviderKeyUsageV1::RootMountQuery,
    );
    assert!(
        validate_root_query_signer(
            &wrong_id,
            authority_id,
            authority_generation,
            authority_digest
        )
        .is_err()
    );

    let wrong_generation = query_signer(
        authority_id,
        authority_generation + 1,
        authority_digest,
        SourceProviderKeyUsageV1::RootMountQuery,
    );
    assert!(
        validate_root_query_signer(
            &wrong_generation,
            authority_id,
            authority_generation,
            authority_digest
        )
        .is_err()
    );

    let wrong_digest = query_signer(
        authority_id,
        authority_generation,
        [5; 32],
        SourceProviderKeyUsageV1::RootMountQuery,
    );
    assert!(
        validate_root_query_signer(
            &wrong_digest,
            authority_id,
            authority_generation,
            authority_digest
        )
        .is_err()
    );

    let wrong_usage = query_signer(
        authority_id,
        authority_generation,
        authority_digest,
        SourceProviderKeyUsageV1::ProviderReceipt,
    );
    assert!(
        validate_root_query_signer(
            &wrong_usage,
            authority_id,
            authority_generation,
            authority_digest
        )
        .is_err()
    );
}

#[test]
fn session_replacement_rejects_generation_rollback_and_equal_equivocation() {
    let current = pristine_head();
    let mut next = current.clone();
    next.session_binding = [42; 32];
    assert!(provider_session_replacement_is_monotonic(&current, &next));

    next.route_generation = 0;
    assert!(!provider_session_replacement_is_monotonic(&current, &next));
    next.route_generation = current.route_generation;
    next.route_digest[0] ^= 1;
    assert!(!provider_session_replacement_is_monotonic(&current, &next));

    next.route_digest = current.route_digest;
    next.route_id[0] ^= 1;
    assert!(!provider_session_replacement_is_monotonic(&current, &next));

    next.route_id = current.route_id;
    next.resource_namespace_digest[0] ^= 1;
    assert!(!provider_session_replacement_is_monotonic(&current, &next));

    next.resource_namespace_digest = current.resource_namespace_digest;
    next.provider_key_id[0] ^= 1;
    assert!(!provider_session_replacement_is_monotonic(&current, &next));

    next.provider_key_generation = current.provider_key_generation + 1;
    assert!(provider_session_replacement_is_monotonic(&current, &next));
}

#[test]
fn released_tombstones_accept_only_absence_or_exact_provider_terminality() {
    assert!(released_inventory_is_terminal(None));
    assert!(released_inventory_is_terminal(Some(
        InventoryLeaseStateV1::Released
    )));
    for state in [
        InventoryLeaseStateV1::Active,
        InventoryLeaseStateV1::Reaping,
    ] {
        assert!(!released_inventory_is_terminal(Some(state)));
    }
}

#[test]
fn authenticated_inventory_contradictions_become_durable_diagnostics() {
    let head = pristine_head();
    let acquisition_id = [59; 32];
    let (active_entry, evidence) =
        matching_inventory_entry(acquisition_id, InventoryLeaseStateV1::Active);
    let mut row = pending_history_row(acquisition_id, provider_context(&head));
    row.phase = SourceAcquisitionPhaseV1::Released;
    row.evidence = Some(evidence.clone());
    let rows = BTreeMap::from([(acquisition_id, row)]);

    let active = inventory_with_entries(&head, vec![active_entry]);
    let contradiction = reconcile_inventory(
        &rows,
        head.holder_authority_id,
        head.provider_authority_id,
        &active,
    )
    .expect("authenticated semantic contradiction is consumable");
    assert!(contradiction.has_authority_conflicts);

    let (released_entry, _) =
        matching_inventory_entry(acquisition_id, InventoryLeaseStateV1::Released);
    let released = inventory_with_entries(&head, vec![released_entry]);
    let terminal = reconcile_inventory(
        &rows,
        head.holder_authority_id,
        head.provider_authority_id,
        &released,
    )
    .expect("matching provider terminality is consumable");
    assert!(!terminal.has_authority_conflicts);
}

#[test]
fn inventory_terminality_requires_an_observation_after_release_admission() {
    let mut head = pristine_head();
    let release_floor = head.inventory_observation_ordinal;

    assert!(!inventory_observation_postdates_release(
        &head,
        release_floor
    ));

    head.inventory_observation_ordinal = 1;
    assert!(inventory_observation_postdates_release(
        &head,
        release_floor
    ));
    assert!(!inventory_observation_postdates_release(&head, 1));

    head.inventory_observation_ordinal = u64::MAX;
    assert!(inventory_observation_postdates_release(&head, u64::MAX - 1));
    assert!(!inventory_observation_postdates_release(&head, u64::MAX));
    assert!(next_inventory_observation_ordinal(u64::MAX).is_err());

    assert!(inventory_release_ordinals_are_ordered(3, 4, 4));
    assert!(inventory_release_ordinals_are_ordered(3, 4, 9));
    assert!(!inventory_release_ordinals_are_ordered(3, 3, 9));
    assert!(!inventory_release_ordinals_are_ordered(3, 4, 3));
}

#[test]
fn preexisting_inventory_omission_cannot_finish_a_later_release() {
    let mut head = pristine_head();
    install_empty_signed_inventory(&mut head, 7);
    let mut row = pending_history_row([41; 32], provider_context(&head));
    row.release_inventory_observation_floor = Some(7);

    assert!(
        !inventory_floor_proves_terminal_release(&head, &row)
            .expect("stale floor is a valid negative result")
    );

    head.inventory_observation_ordinal = 8;
    assert!(
        inventory_floor_proves_terminal_release(&head, &row)
            .expect("fresh omission establishes provider terminality")
    );
}

#[test]
fn recovered_inventory_proof_digest_is_exact_at_the_same_observation() {
    let mut head = pristine_head();
    install_empty_signed_inventory(&mut head, 8);
    let mut row = pending_history_row([61; 32], provider_context(&head));
    row.phase = SourceAcquisitionPhaseV1::Released;
    row.release_inventory_observation_floor = Some(7);
    row.provider_inventory_observation_ordinal = Some(8);
    row.provider_inventory_digest = Some([62; 32]);
    let mut rows = BTreeMap::from([(row.acquisition_id, row)]);

    assert!(validate_recovered_inventory_projection(&rows, &head).is_err());

    rows.get_mut(&[61; 32])
        .expect("test acquisition exists")
        .provider_inventory_digest = head.inventory_digest;
    validate_recovered_inventory_projection(&rows, &head)
        .expect("the exact same-observation floor reopens");
}

#[test]
fn operation_ids_collide_across_acquire_and_release_roles() {
    let release = SourceAcquisitionOperationV1 {
        operation_id: [2; 16],
        request_digest: [3; 32],
    };
    assert!(operation_id_matches_row([1; 16], Some(release), [1; 16]));
    assert!(operation_id_matches_row([1; 16], Some(release), [2; 16]));
    assert!(!operation_id_matches_row([1; 16], Some(release), [4; 16]));
}

#[test]
fn release_authority_requires_same_lineage_and_monotonic_fence() {
    let acquire = SourceAcquisitionAssignmentV1 {
        sandbox_id: [1; 16],
        incarnation_id: [2; 16],
        assignment_epoch: 4,
        desired_generation: 7,
        assignment_digest: [3; 32],
        namespace_generation: 1,
    };
    let mut release = SourceAcquisitionReleaseAuthorityV1 {
        sandbox_id: acquire.sandbox_id,
        incarnation_id: acquire.incarnation_id,
        assignment_epoch: acquire.assignment_epoch,
        desired_generation: acquire.desired_generation,
        assignment_digest: acquire.assignment_digest,
        expected_revision: 1,
        expected_record_digest: [4; 32],
    };
    assert!(release_authority_dominates(acquire, release));

    release.desired_generation += 1;
    release.assignment_digest = [5; 32];
    assert!(release_authority_dominates(acquire, release));

    release.assignment_epoch += 1;
    release.desired_generation = 1;
    assert!(release_authority_dominates(acquire, release));

    release.assignment_epoch = acquire.assignment_epoch - 1;
    release.desired_generation = u64::MAX;
    assert!(!release_authority_dominates(acquire, release));

    release.assignment_epoch = acquire.assignment_epoch;
    release.desired_generation = acquire.desired_generation;
    release.assignment_digest = [6; 32];
    assert!(!release_authority_dominates(acquire, release));

    release.assignment_digest = acquire.assignment_digest;
    release.sandbox_id[0] ^= 1;
    assert!(!release_authority_dominates(acquire, release));

    release.sandbox_id = acquire.sandbox_id;
    release.incarnation_id[0] ^= 1;
    assert!(!release_authority_dominates(acquire, release));
}

#[test]
fn acquisition_and_provider_head_transactions_are_domain_separated() {
    let head = pristine_head();
    let mut type_confusable_id = [0_u8; 32];
    type_confusable_id[..16].copy_from_slice(&head.holder_authority_id);
    type_confusable_id[16..].copy_from_slice(&head.provider_authority_id);

    assert_ne!(
        transaction_id(type_confusable_id, 1),
        provider_head_transaction_id(&head)
    );
}

#[test]
fn final_create_projection_changes_only_catalog_field() {
    let mut final_semantics = Vec::new();
    let mut expected = Vec::new();
    for tag in 1_u8..=27 {
        final_semantics.push(tag);
        expected.push(tag);
        if tag == 13 {
            final_semantics.extend_from_slice(&32_u32.to_be_bytes());
            final_semantics.extend_from_slice(&[13; 32]);
            expected.extend_from_slice(&0_u32.to_be_bytes());
        } else {
            final_semantics.extend_from_slice(&1_u32.to_be_bytes());
            final_semantics.push(tag);
            expected.extend_from_slice(&1_u32.to_be_bytes());
            expected.push(tag);
        }
    }

    assert_eq!(
        lifecycle::project_final_create_semantics(&final_semantics)
            .expect("valid exact field sequence"),
        expected
    );
    final_semantics.push(0);
    assert!(lifecycle::project_final_create_semantics(&final_semantics).is_err());
}

#[test]
fn final_create_projection_requires_one_nonzero_catalog_commitment() {
    let mut empty_catalog = Vec::new();
    let mut zero_catalog = Vec::new();
    for tag in 1_u8..=27 {
        empty_catalog.push(tag);
        zero_catalog.push(tag);
        if tag == 13 {
            empty_catalog.extend_from_slice(&0_u32.to_be_bytes());
            zero_catalog.extend_from_slice(&32_u32.to_be_bytes());
            zero_catalog.extend_from_slice(&[0; 32]);
        } else {
            empty_catalog.extend_from_slice(&1_u32.to_be_bytes());
            empty_catalog.push(tag);
            zero_catalog.extend_from_slice(&1_u32.to_be_bytes());
            zero_catalog.push(tag);
        }
    }

    assert!(lifecycle::project_final_create_semantics(&empty_catalog).is_err());
    assert!(lifecycle::project_final_create_semantics(&zero_catalog).is_err());
}
