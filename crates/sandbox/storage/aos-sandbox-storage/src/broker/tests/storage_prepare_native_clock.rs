//! Deterministic signed-admission and actual Native append guard regressions.
//!
//! Canonical Clone/catalog/Start history is test DATA. Real plan/lease crypto,
//! sealed four-member records, Native guards, append/sync and reopen remain in
//! the tests. Explicit fixture clock/fault injection does not qualify installed
//! PID1 ownership, physical Clone resolution, receiving payment or Session use.

use aos_sandbox_api::aos::sandbox::local::v1::PrepareNixStorageGenerationRequestV1;
use aos_sandbox_controller_domain::journal::StoragePrepareNativeClockCaptureV1;
use aos_sandbox_controller_domain::{Journal, JournalLimits, JournalRecord, JournalTransaction};
use aos_sandbox_protocol::nix_generation::{
    CanonicalNixGenerationPreparationV1, NixGenerationControlV1, NixGenerationOriginV1,
    NixGenerationStartPrefixV1,
};

use super::*;
use crate::authorization::{SealedStorageAdmission, VerifiedStoragePreparationAdmissionV1};
use crate::nix_generation::{StorageGenerationCauseV1, StorageGenerationNativeLoanV1};

struct NativeFixture {
    directory: TempDir,
    broker: StorageAdmissionCoordinator,
    original: crate::StorageGenerationAttemptV1,
    admission: VerifiedStoragePreparationAdmissionV1,
    sealed: SealedStorageAdmission,
    sealed_preparation: Vec<u8>,
    policy: crate::resolver::protected_catalog::StorageResolverPolicyBindingV1,
    head: crate::CatalogBindingV1,
}

fn checked_clone_catalog(generation: u64) -> ResolvedCatalogCommitmentV1 {
    let base = clone_catalog(generation);
    let CatalogPlanV1::Clone { source, .. } = base.plan() else {
        unreachable!()
    };
    let metadata = ObjectDigest::from_bytes([44; 32]);
    let root = WorkspaceRootPolicyV1::clone_preserve(
        source.guid(),
        crate::root_policy::PortableRootAttributesV1::new(1000, 1001, 0o2750).unwrap(),
        metadata,
    )
    .unwrap();
    let identity = crate::clone_identity::CloneIdentityRequirementV1::new_for_test(
        source.guid(),
        metadata,
        1000,
        1001,
        1,
        0,
        ObjectDigest::from_bytes([45; 32]),
    )
    .unwrap();
    ResolvedCatalogCommitmentV1::new_execution_v1(
        generation,
        base.domains(),
        base.plan().clone(),
        Some(root),
        Some(identity),
    )
    .unwrap()
}

fn selected_request(
    catalog: &ResolvedCatalogCommitmentV1,
    head: crate::CatalogBindingV1,
) -> (Vec<u8>, BrokerAssignment) {
    let apply = workspace_request(StorageAction::STORAGE_ACTION_CLONE, 7);
    let assignment = decode_assignment(&apply).unwrap();
    let (nested, inventory, _) = preparation_request_at_head(&apply, catalog, head);
    let mut nested = PrepareStorageCatalogRequest::decode_from_slice(&nested).unwrap();
    let deadline = clock().boottime_nanoseconds() + 30_000_000_000;
    nested
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = deadline;
    // Keep the catalog preparation's own expiry within every admitted cutoff.
    // The original Start/request cutoff deliberately remains much later.
    nested.preparation_expires_boottime_nanoseconds =
        clock().boottime_nanoseconds() + 1_000_000_000;
    let execution = catalog.execution_binding().unwrap();
    let controls = [
        "nix/var/nix/db/db.sqlite",
        "nix/var/nix/db/schema",
        "nix/var/nix/db/reserved",
        "etc/nix/nix.conf",
    ]
    .map(str::to_owned);
    let origin = NixGenerationOriginV1 {
        version: 1,
        node: *NODE.as_bytes(),
        deployment: [11; 32],
        domain: [12; 16],
        domain_commitment: [13; 32],
        project: [14; 16],
        sandbox: *assignment.sandbox().as_bytes(),
        incarnation: *assignment.incarnation().as_bytes(),
        source_generation: 1,
        input_artifact: [15; 32],
        public_tree: ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Tree.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([16; 32]),
            1,
        ),
        storage_handle: [31; 32],
        source_version_handle: [32; 32],
        hold_id: [33; 16],
        root_policy_digest: *execution.root_policy_digest().as_bytes(),
        clone_identity_digest: *execution.clone_identity_digest().as_bytes(),
        metadata_digest: [44; 32],
        inventory_generation: inventory.generation(),
        inventory_digest: *inventory.digest().as_bytes(),
        catalog_generation: head.generation(),
        catalog_digest: *head.digest().as_bytes(),
        quota_bytes: 4096,
        reservation_bytes: 1,
        controls: std::array::from_fn(|index| NixGenerationControlV1 {
            kind: index as u8 + 1,
            name: controls[index].clone(),
            bytes: 0,
            sha256: [20; 32],
            verity_sha256: [21; 32],
            source_inode: 22,
        }),
    };
    let origin_bytes = origin.encode().unwrap();
    let prefix = NixGenerationStartPrefixV1 {
        operation: [7; 16],
        step: 0,
        assignment: *assignment.digest().as_bytes(),
        desired: [23; 32],
        effect: [24; 32],
        recipe: [25; 32],
        input_set: [26; 32],
        presentation: [27; 32],
        domain: origin.domain,
        project: origin.project,
        sandbox: origin.sandbox,
        incarnation: origin.incarnation,
        origin: Sha256::digest(&origin_bytes).into(),
        source_generation: 1,
        next_generation: 2,
        host_boot_id: clock().host_boot_id(),
        first_wall_seconds: clock().wall_seconds(),
        first_boottime_nanoseconds: clock().boottime_nanoseconds(),
        deadline_boottime_nanoseconds: deadline,
    };
    let request = PrepareNixStorageGenerationRequestV1 {
        canonical_prepare: nested.encode_to_vec(),
        original_start_prefix: prefix.encode().unwrap(),
        generation_origin: origin_bytes,
        ..Default::default()
    }
    .encode_to_vec();
    (request, assignment)
}

fn fixture(plan_expires: i64, lease_expires: i64) -> NativeFixture {
    let directory = TempDir::new().unwrap();
    let keys = Fixture::new();
    let bootstrap = catalog(8, 9);
    let mut broker = initialized_coordinator(&directory, &keys, &bootstrap);
    let head = broker.transactions.catalog_head_binding().unwrap();
    let catalog = checked_clone_catalog(head.generation() + 1);
    let (request, assignment) = selected_request(&catalog, head);
    let checked = CanonicalNixGenerationPreparationV1::decode(
        &request,
        peer(),
        peer_policy(),
        clock().boottime_nanoseconds(),
    )
    .unwrap();
    let grant = BrokerGrant::new(
        BrokerVerb::StoragePrepareCatalog,
        BrokerGrantTarget::Assignment,
        checked.argument_commitment(),
        request.len() as u32,
        0,
    )
    .unwrap();
    let artifacts = keys.signed_artifacts(
        assignment,
        vec![grant],
        100,
        plan_expires,
        lease_expires,
        BrokerAudience::Storage,
        ProtocolId::StorageBroker,
        ProtocolVersion::new(1, 0),
    );
    let admission = broker
        .authority
        .admit_nix_generation_preparation(
            &artifacts,
            &checked,
            &request,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &clock(),
            None,
        )
        .unwrap();
    let policy = crate::resolver::protected_catalog::StorageResolverPolicyBindingV1::from_authenticated_parts(
        7, ObjectDigest::from_bytes([61; 32]), ObjectDigest::from_bytes([62; 32]),
    ).unwrap();
    broker
        .transactions
        .admit_resolver_policy_catalog(policy.catalog_binding())
        .unwrap();
    let sealed = broker.authority.seal_preparation(&admission).unwrap();
    let prepared = RetainedStorageCatalogPreparationV1::prepare_nix_generation(
        &checked,
        &request,
        catalog,
        *checked.prepare().header().request_id(),
        clock().host_boot_id(),
        admission.effect_deadline_boottime_nanoseconds(),
        admission.plan_digest(),
        admission.lease_digest(),
        StoragePreparationAuthorityRecordsV1 {
            sealed_fence: &sealed.current_fence,
            sealed_effect: &sealed.effect,
            sealed_operation_fence: &sealed.operation_fence,
        },
        policy,
    )
    .unwrap();
    let receipt = broker
        .authority
        .seal_catalog_preparation_receipt(&[7; 16], &prepared.receipt_payload)
        .unwrap();
    let retained = prepared.record.with_receipt(receipt).unwrap();
    let sealed_preparation = broker
        .authority
        .seal_catalog_preparation_record(&[7; 16], &retained.encode_payload().unwrap())
        .unwrap();
    let mut original = crate::StorageGenerationAttemptV1::new();
    original.request = Some(request);
    original.checked = Some(Ok(checked));
    original.initial = Some(Ok(clock()));
    original.entered = true;
    NativeFixture {
        directory,
        broker,
        original,
        admission,
        sealed,
        sealed_preparation,
        policy,
        head,
    }
}

fn crossing_sample(boottime: u64) -> RawPairedClockSample {
    let elapsed_seconds = (boottime - clock().boottime_nanoseconds()) / 1_000_000_000;
    clock_at(
        clock().host_boot_id(),
        clock().wall_seconds() + elapsed_seconds as i64,
        boottime,
    )
}

fn append_selected(fixture: &mut NativeFixture) -> Result<(), crate::StorageStateError> {
    let selected = fixture.original.checked.as_ref().unwrap().as_ref().unwrap();
    let authority = fixture
        .broker
        .authority
        .borrow_preparation_native_admission(&fixture.admission, selected);
    let original = StorageGenerationNativeLoanV1 {
        native: &mut fixture.original.native,
        clock: &mut fixture.original.native_clock,
        first: &mut fixture.original.first,
    };
    fixture
        .broker
        .transactions
        .retain_catalog_preparation_with_generation(
            selected.prepare().operation_id(),
            *selected.prepare().fence().sandbox_id(),
            *selected.prepare().header().request_id(),
            fixture.head,
            fixture.sealed.current_fence.clone(),
            fixture.sealed.effect.clone(),
            fixture.sealed.operation_fence.clone(),
            fixture.sealed_preparation.clone(),
            fixture.policy,
            Some(crate::state::StorageCatalogPreparationNativeV1::Nix(original, authority)),
        )
}

fn exact_transaction(fixture: &NativeFixture) -> JournalTransaction {
    JournalTransaction::new(
        [90; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![2; 16],
                fixture.sealed.current_fence.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                vec![135; 16],
                fixture.sealed.effect.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                vec![7; 16],
                fixture.sealed.operation_fence.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::StorageCatalogPreparation,
                vec![7; 16],
                fixture.sealed_preparation.clone(),
            ),
        ],
    )
    .unwrap()
}

#[test]
fn earlier_plan_or_lease_cutoff_refuses_at_the_actual_native_frontier() {
    // The lease allows ten seconds of skew: 170 remains valid at the initial
    // wall clock of 150 while its conservative cutoff still precedes the request.
    for (plan, lease) in [(160, 300), (300, 170)] {
        let mut fixture = fixture(plan, lease);
        let deadline = fixture.admission.effect_deadline_boottime_nanoseconds();
        let checked = fixture.original.checked.as_ref().unwrap().as_ref().unwrap();
        assert!(deadline < checked.prefix().deadline_boottime_nanoseconds);
        let before = fixture.broker.transactions.journal_sequence_for_test();
        fixture.original.native_clock =
            StoragePrepareNativeClockCaptureV1::with_untrusted_sample_for_fixture(Ok(
                crossing_sample(deadline),
            ));

        assert!(append_selected(&mut fixture).is_err());

        assert!(
            fixture
                .original
                .native_clock
                .sample_result()
                .unwrap()
                .is_ok()
        );
        assert!(
            fixture
                .original
                .native_clock
                .validation_result()
                .unwrap()
                .is_err()
        );
        assert!(matches!(
            fixture.original.first,
            Some(StorageGenerationCauseV1::NativeClock)
        ));
        assert!(fixture.original.native.as_ref().unwrap().is_err());
        assert_eq!(
            fixture.broker.transactions.journal_sequence_for_test(),
            before
        );
        assert!(!fixture.broker.transaction_journal_requires_reopen());
        assert!(
            fixture
                .broker
                .transactions
                .catalog_preparation_record(&[7; 16])
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn successful_selected_clock_retains_actual_commit_and_exact_four_values() {
    let mut fixture = fixture(160, 300);
    let live_preparation_sample = clock().boottime_nanoseconds() + 500_000_000;
    fixture.original.native_clock =
        StoragePrepareNativeClockCaptureV1::with_untrusted_sample_for_fixture(Ok(crossing_sample(
            live_preparation_sample,
        )));
    let before = fixture.broker.transactions.journal_sequence_for_test();

    append_selected(&mut fixture).unwrap();

    assert!(fixture.original.native.as_ref().unwrap().is_ok());
    assert!(
        fixture
            .original
            .native_clock
            .validation_result()
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        fixture.broker.transactions.journal_sequence_for_test(),
        before + 6
    );
    assert_eq!(
        fixture.broker.transactions.catalog_head_binding().unwrap(),
        fixture.head
    );
    fixture.broker.authenticate_catalog_preparations().unwrap();
    for (namespace, key, expected) in [
        (
            RecordNamespace::DesiredState,
            [2; 16],
            &fixture.sealed.current_fence,
        ),
        (RecordNamespace::Effect, [135; 16], &fixture.sealed.effect),
        (
            RecordNamespace::AuthorityPublication,
            [7; 16],
            &fixture.sealed.operation_fence,
        ),
        (
            RecordNamespace::StorageCatalogPreparation,
            [7; 16],
            &fixture.sealed_preparation,
        ),
    ] {
        assert_eq!(
            fixture
                .broker
                .transactions
                .authority_record(namespace, &key)
                .unwrap(),
            Some(expected.as_slice())
        );
    }
}

#[test]
fn native_capacity_refusal_precedes_the_fixed_clock_observation() {
    let fixture = fixture(160, 300);
    let transaction = exact_transaction(&fixture);
    let selected = fixture.original.checked.as_ref().unwrap().as_ref().unwrap();
    let authority = fixture
        .broker
        .authority
        .borrow_preparation_native_admission(&fixture.admission, selected);
    let directory = TempDir::new().unwrap();
    let limits = JournalLimits {
        maximum_journal_bytes: 1024,
        ..JournalLimits::default()
    };
    let (mut journal, _) = Journal::open(directory.path().join("bounded.journal"), limits).unwrap();
    let mut capture = StoragePrepareNativeClockCaptureV1::with_untrusted_sample_for_fixture(Ok(
        crossing_sample(fixture.admission.effect_deadline_boottime_nanoseconds()),
    ));
    let before = journal.snapshot_sequence();

    let result = journal
        .commit_storage_prepare_with_clock_v1(authority.borrow_clock(&transaction), &mut capture);

    assert!(matches!(
        result,
        Err(aos_sandbox_controller_domain::JournalError::JournalTooLarge)
    ));
    assert!(capture.sample_result().is_none());
    assert!(capture.validation_result().is_none());
    assert_eq!(journal.snapshot_sequence(), before);
}

#[test]
fn durable_native_error_stays_first_through_later_debt_and_reopen() {
    let mut fixture = fixture(160, 300);
    let live_preparation_sample = clock().boottime_nanoseconds() + 500_000_000;
    fixture.original.native_clock =
        StoragePrepareNativeClockCaptureV1::with_durable_append_failure_for_fixture(
            crossing_sample(live_preparation_sample),
        );

    let result = append_selected(&mut fixture);

    assert!(result.is_err());
    assert!(fixture.broker.transaction_journal_requires_reopen());
    assert!(matches!(
        fixture.original.first,
        Some(StorageGenerationCauseV1::Native)
    ));
    let original_error = fixture.original.failure().unwrap().to_string();
    assert!(original_error.contains("after durable native append"));
    fixture.original.prepared = Some(Err(StorageBrokerError::State(result.unwrap_err())));
    fixture.original.clock_debt = Some(StorageAdmissionError::FenceRejected);
    fixture.original.finished = true;
    assert_eq!(
        fixture.original.failure().unwrap().to_string(),
        original_error
    );
    assert!(fixture.original.clock_debt().is_some());
    assert!(fixture.original.prepared().is_none());

    let NativeFixture {
        directory,
        broker,
        sealed_preparation,
        ..
    } = fixture;
    drop(broker);
    let keys = Fixture::new();
    let reopened = coordinator(&directory, &keys);
    reopened.authenticate_catalog_preparations().unwrap();
    assert_eq!(
        reopened
            .transactions
            .catalog_preparation_record(&[7; 16])
            .unwrap(),
        Some(sealed_preparation.as_slice())
    );
}

#[test]
fn changed_four_member_transaction_cannot_borrow_the_clock_restriction() {
    let fixture = fixture(160, 300);
    let expected = exact_transaction(&fixture);
    let selected = fixture.original.checked.as_ref().unwrap().as_ref().unwrap();
    let authority = fixture
        .broker
        .authority
        .borrow_preparation_native_admission(&fixture.admission, selected);
    let mut changed = expected.records().to_vec();
    changed.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        b"extra".to_vec(),
        vec![1],
    ));
    let changed = JournalTransaction::new(*expected.id(), changed).unwrap();

    assert!(authority.borrow_clock(&changed).is_err());
}

#[test]
fn production_capture_layout_fits_the_replaced_clock_reservoir() {
    let previous = std::mem::size_of::<(
        Option<Result<RawPairedClockSample, crate::StorageRuntimeError>>,
        Option<StorageAdmissionError>,
    )>();
    let retained = StoragePrepareNativeClockCaptureV1::retained_layout_bytes();
    eprintln!(
        "selected Storage native clock retained bytes: previous={previous}, current={retained}"
    );

    assert!(
        retained <= previous,
        "new persistent clock slots require a real supplier adjustment"
    );
}

#[test]
fn ordinary_prepare_clock_joins_real_signed_admission_and_exact_retained_members() {
    // Real fixture plan/lease signatures and actual sealed journal members are
    // used here. This tests a clock restriction, not genuine PID1 payment.
    let mut production = production_preparation_fixture(7);
    let semantics = CanonicalStoragePreparationSemanticsV1::decode(
        &production.request, peer(), peer_policy(), clock().boottime_nanoseconds(),
    ).unwrap();
    let admission = production.broker.authority.admit_preparation(
        &production.artifacts, &semantics, &production.request,
        ProtocolVersion::new(1, 0), peer(), peer_policy(), &clock(), None,
    ).unwrap();
    production.broker.prepare_catalog_from_protected_policy(
        &production.request, &production.artifacts, &production.policies,
        ProtocolVersion::new(1, 0), peer(), peer_policy(), &mut || Ok(clock()),
    ).unwrap();
    let locations = [
        (RecordNamespace::DesiredState, *semantics.fence().sandbox_id()),
        (RecordNamespace::Effect, *semantics.header().request_id()),
        (RecordNamespace::AuthorityPublication, semantics.operation_id()),
        (RecordNamespace::StorageCatalogPreparation, semantics.operation_id()),
    ];
    let records: Vec<_> = locations.into_iter().map(|(namespace, key)| JournalRecord::put(
        namespace, key.to_vec(), production.broker.transactions.authority_record(namespace, &key)
            .unwrap().unwrap().to_vec(),
    )).collect();
    let transaction = JournalTransaction::new([90; 16], records.clone()).unwrap();
    let original = production.broker.authority
        .borrow_ordinary_preparation_native_admission(&admission, &semantics);
    let loan = original.borrow_clock(&transaction).unwrap();

    assert!(loan.require_native_clock(clock()).is_ok());
    assert!(matches!(loan.require_native_clock(crossing_sample(
        admission.effect_deadline_boottime_nanoseconds(),
    )), Err(StorageAdmissionError::FenceRejected)));

    let mut extra = records;
    extra.push(JournalRecord::put(RecordNamespace::Operation, vec![1], vec![2]));
    let extra = JournalTransaction::new([91; 16], extra).unwrap();
    assert!(matches!(original.borrow_clock(&extra), Err(StorageAdmissionError::RequestMismatch)));
}
