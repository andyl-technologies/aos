//! Exercises the actual bounded writer and refused private constructor custody.

use super::*;
use crucible_node_contract::{HashRef, U64};

fn content() -> ContentRef {
    ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".to_owned(),
            domain: "cnp.blob.v1".to_owned(),
            digest: "0".repeat(64),
        },
        length: U64::new(1),
        media_type: "application/octet-stream".to_owned(),
    }
}

#[test]
fn bounded_writer_keeps_the_actual_prefix_and_capacity_after_refusal() {
    let mut bank = Vec::new();
    bank.try_reserve_exact(4).unwrap();
    let capacity = bank.capacity();

    {
        let mut writer = ReservedWriter {
            bank: &mut bank,
            maximum: 4,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"de").is_err());
    }

    assert_eq!(bank, b"abc");
    assert_eq!(bank.capacity(), capacity);
}

#[test]
fn bounded_writer_obeys_exact_and_one_short_extents_without_growing() {
    for maximum in [3, 4] {
        let mut bank = Vec::with_capacity(4);
        let capacity = bank.capacity();
        let result = ReservedWriter {
            bank: &mut bank,
            maximum,
        }
        .write_all(b"abcd");

        assert_eq!(result.is_ok(), maximum == 4);
        assert_eq!(bank.capacity(), capacity);
        assert_eq!(bank.len(), if maximum == 4 { 4 } else { 0 });
    }
}

#[test]
fn missing_private_input_keeps_both_caller_slots_and_spends_the_attempt() {
    let host = content();
    let private_launch = Id::new("private-launch").unwrap();
    let mut attempt = NativeImport18PrivateBirthAttempt::new_data();
    let mut source = Some(b"{}".to_vec());
    let mut registration = None;
    let mut completed = None;

    assert!(
        OriginalAckPeerBirth::retain_import18_private_birth_into_data(
            &host,
            &private_launch,
            &mut source,
            &mut registration,
            &mut attempt,
            &mut completed,
        )
        .is_err()
    );
    assert_eq!(source.as_deref(), Some(b"{}".as_slice()));
    assert!(registration.is_none());
    assert!(completed.is_none());

    registration = Some(b"{}".to_vec());
    assert!(matches!(
        OriginalAckPeerBirth::retain_import18_private_birth_into_data(
            &host,
            &private_launch,
            &mut source,
            &mut registration,
            &mut attempt,
            &mut completed,
        ),
        Err(RuntimeError::DuplicateOperation)
    ));
    assert!(completed.is_none());
    assert_eq!(registration.as_deref(), Some(b"{}".as_slice()));
}

#[test]
fn private_clone_geometry_is_actual_field_length_and_refuses_one_short() {
    let host = content();
    let id = Id::new("private-launch").unwrap();
    let expected = [
        host.hash.algorithm.len(),
        host.hash.domain.len(),
        host.hash.digest.len(),
        host.media_type.len(),
        id.as_str().len(),
    ]
    .into_iter()
    .sum::<usize>();
    let row = NativeImport18PrivateBirthAttempt::construction_storage_data(&host, &id, usize::MAX)
        .unwrap();

    let (clone_transient, clone_scratch) =
        crate::node_adapters::cnp::semantic::source::private_birth_clone_construction_data(
            &host,
            &id,
            usize::MAX,
        )
        .unwrap();
    assert_eq!(row[0], expected);
    assert_eq!(
        row[1],
        expected + clone_transient + size_of::<Option<ContentRef>>() + size_of::<Option<Id>>()
    );
    assert_eq!(
        row[2],
        NativeImport18PrivateBirthAttempt::counter_scratch_data() + clone_scratch
    );
    assert!(
        NativeImport18PrivateBirthAttempt::construction_storage_data(
            &host,
            &id,
            row[2].max(row[1]).max(row[0])
        )
        .is_ok()
    );
    // The component applies the same explicit bound to all axes. This is the
    // true admitted scratch axis, not a donor standing in for clone geometry.
    assert!(
        NativeImport18PrivateBirthAttempt::construction_storage_data(
            &host,
            &id,
            row[2].max(row[1]).max(row[0]) - 1
        )
        .is_err()
    );
}

#[test]
fn transferred_registration_spare_banks_are_counted_even_when_empty() {
    let plan = PacketCompleteAckHostRegistrationPlan {
        connection_id: Id::new("controller").unwrap(),
        features: Vec::with_capacity(3),
        extensions: Vec::with_capacity(2),
        envelope_extensions: Vec::with_capacity(5),
    };
    let actual = plan.connection_id.allocated_capacity()
        + plan.features.capacity() * size_of::<Id>()
        + plan.extensions.capacity() * size_of::<crucible_node_contract::ExtensionSelection>()
        + plan.envelope_extensions.capacity() * size_of::<String>();

    assert_eq!(storage::registration_storage(&plan).unwrap(), actual);
}

#[test]
fn literal_value_currency_keeps_reserved_strings_and_full_u64_identity() {
    fn commitment(value: &Value) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash_value(&mut hash, value, 0).unwrap();
        *hash.finalize().as_bytes()
    }

    let literal = serde_json::json!({"$serde_json::private::RawValue": "[1,2]"});
    let expanded = serde_json::json!([1, 2]);
    assert_ne!(commitment(&literal), commitment(&expanded));
    assert_eq!(commitment(&literal), commitment(&literal.clone()));
    assert_ne!(
        commitment(&serde_json::json!(u64::MAX)),
        commitment(&serde_json::json!(u64::MAX - 1))
    );
}

#[test]
fn literal_value_currency_refuses_beyond_the_existing_source_writer_profile() {
    let mut value = Value::Null;
    for _ in 0..65 {
        value = Value::Array(vec![value]);
    }
    let mut hash = blake3::Hasher::new();

    assert!(matches!(
        hash_value(&mut hash, &value, 0),
        Err(RuntimeError::ResourceLimit)
    ));
}

fn ordinary_source(reactive: bool) -> PacketCompleteSemanticSource {
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
    let coordinator = fixture::coordinator();
    if reactive {
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            fixture::installation(&coordinator, 1),
            fixture::reactive(&coordinator, 1),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    } else {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(&coordinator, 0),
            fixture::producer(),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    }
}

fn failed_input_fixture(source: &PacketCompleteSemanticSource) -> NativeImport18BirthConstruction {
    // This deliberately failed DATA owner cannot issue a Source quote. No
    // declaration, Initial, Recipe, launch commitment or native witness exists.
    NativeImport18BirthConstruction {
        identity: Identity {
            source: source as *const PacketCompleteSemanticSource as usize,
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch_operands: [0; 32],
        },
        inputs_started: false,
        registration: None,
        private_launch: None,
        coordinator: None,
        source_value: None,
        registration_value: None,
        source_bank: None,
        registration_bank: None,
        private_birth: NativeImport18PrivateBirthAttempt::new_data(),
        stage: Stage::Initialized,
        failed: true,
    }
}

#[test]
fn actual_parent_initializers_leave_both_ordinary_roles_without_a_worker() {
    for reactive in [false, true] {
        let source = ordinary_source(reactive);
        assert!(source.native_import18_birth_construction.is_none());
        assert!(!source.ack_birth_attempted);
        assert_eq!(
            source
                .native_import18_birth_construction_retained_storage_data(0)
                .unwrap(),
            0
        );
        assert!(
            !source
                .is_original_native_import18_declaration_data()
                .unwrap()
        );
    }
}

#[test]
fn missing_input_moves_same_bank_into_failed_once_owner_without_a_witness() {
    for missing_private in [false, true] {
        let source = ordinary_source(false);
        let mut owner = failed_input_fixture(&source);
        let mut private = (!missing_private).then(|| Id::new("retained-private").unwrap());
        let mut plan = missing_private.then(|| PacketCompleteAckHostRegistrationPlan {
            connection_id: Id::new("retained-connection").unwrap(),
            features: Vec::with_capacity(3),
            extensions: Vec::with_capacity(2),
            envelope_extensions: Vec::with_capacity(5),
        });
        let private_address = private.as_ref().map(|id| id.as_str().as_ptr());
        let connection_address = plan
            .as_ref()
            .map(|plan| plan.connection_id.as_str().as_ptr());
        let features_address = plan.as_ref().map(|plan| plan.features.as_ptr());
        assert!(
            owner
                .retain_initial_operands_data(&mut private, &mut plan)
                .is_err()
        );
        assert!(owner.inputs_started && owner.failed);
        assert!(private.is_none() && plan.is_none());
        assert_eq!(
            owner.private_launch.as_ref().map(|id| id.as_str().as_ptr()),
            private_address
        );
        assert_eq!(
            owner
                .registration
                .as_ref()
                .map(|plan| plan.connection_id.as_str().as_ptr()),
            connection_address
        );
        assert_eq!(
            owner
                .registration
                .as_ref()
                .map(|plan| plan.features.as_ptr()),
            features_address
        );

        let mut retry_private = Some(Id::new("retry-private").unwrap());
        let mut retry_plan = None;
        assert!(matches!(
            owner.retain_initial_operands_data(&mut retry_private, &mut retry_plan),
            Err(RuntimeError::DuplicateOperation)
        ));
        assert!(retry_private.is_some() && owner.failed);
        assert!(
            !source
                .is_original_native_import18_declaration_data()
                .unwrap()
        );
    }
}

#[test]
fn real_parent_census_retains_failed_worker_and_legacy_header_refuses_omission() {
    use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;
    use std::cell::RefCell;
    let mut source = ordinary_source(false);
    let aliases = RefCell::new(OriginalRestoredOwnerCapacityAliases::unallocated(1).unwrap());
    let old_header =
        serde_json::to_value(source.borrowed_settled17_header_data(&aliases).unwrap()).unwrap();
    let before = source
        .original_complete_boot_association_storage_data_with_error::<RuntimeError>(usize::MAX)
        .unwrap();
    let mut partial = failed_input_fixture(&source);
    let mut private = None;
    let mut plan = Some(PacketCompleteAckHostRegistrationPlan {
        connection_id: Id::new("retained-connection").unwrap(),
        features: Vec::with_capacity(3),
        extensions: Vec::with_capacity(2),
        envelope_extensions: Vec::with_capacity(5),
    });
    assert!(
        partial
            .retain_initial_operands_data(&mut private, &mut plan)
            .is_err()
    );
    let expected = partial.retained_storage_data(usize::MAX).unwrap();
    source.native_import18_birth_construction = Some(Box::new(partial));
    let owner = source
        .native_import18_birth_construction
        .as_ref()
        .unwrap()
        .as_ref() as *const _;
    assert_eq!(
        source
            .original_complete_boot_association_storage_data_with_error::<RuntimeError>(usize::MAX)
            .unwrap(),
        before + expected
    );
    assert_eq!(
        source
            .native_import18_birth_construction_retained_storage_data(expected)
            .unwrap(),
        expected
    );
    assert!(matches!(
        source.native_import18_birth_construction_retained_storage_data(expected - 1),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(
        serde_json::to_value(source.borrowed_settled17_header_data(&aliases).unwrap()).is_err()
    );
    assert_eq!(
        source
            .native_import18_birth_construction
            .as_ref()
            .unwrap()
            .as_ref() as *const _,
        owner
    );
    assert!(
        source
            .native_import18_birth_construction
            .as_ref()
            .unwrap()
            .failed
    );
    assert!(source.ack_peer_birth.borrow().is_none());
    assert!(
        !source
            .is_original_native_import18_declaration_data()
            .unwrap()
    );
    source.native_import18_birth_construction = None;
    assert_eq!(
        serde_json::to_value(source.borrowed_settled17_header_data(&aliases).unwrap()).unwrap(),
        old_header
    );
}

#[test]
fn actual_initialize_row_names_box_return_and_refuses_one_short_before_construction() {
    // This is the actual pre-constructor DATA quote, without Source authority,
    // a selected launch, an Initial/Recipe issuer or any allocated worker.
    let row = storage::initialize_storage_data(usize::MAX).unwrap();
    let retained = size_of::<NativeImport18BirthConstruction>();
    let transient = NativeImport18PrivateBirthAttempt::new_construction_transient_data()
        + size_of::<NativeImport18BirthConstruction>()
        + size_of::<NativeImport18BirthConstruction>()
        + size_of::<Box<NativeImport18BirthConstruction>>()
        + size_of::<Option<Box<NativeImport18BirthConstruction>>>()
        + size_of::<Option<Id>>() * 5
        + size_of::<Option<PacketCompleteAckHostRegistrationPlan>>() * 5;
    assert_eq!(row, [retained, transient, storage::counter_scratch_data()]);

    let exact = row.into_iter().max().unwrap();
    assert_eq!(storage::initialize_storage_data(exact).unwrap(), row);
    assert!(matches!(
        storage::initialize_storage_data(exact - 1),
        Err(RuntimeError::ResourceLimit)
    ));
}

#[test]
fn actual_template_attempt_counts_same_source_failed_worker_without_code_or_birth_authority() {
    use crate::node_adapters::cnp::semantic::packet_complete_source::template18::OriginalNativeSourceTemplate18Attempt;
    use std::rc::Rc;
    for reactive in [false, true] {
        for missing_private in [false, true] {
            let code = Rc::new(ordinary_source(reactive));
            let quote = code
                .native_source_template18_construction_data(usize::MAX)
                .unwrap();
            let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
            code.native_source_template18_into(&quote, &mut attempt)
                .unwrap();
            let before = attempt.retained_requested_storage_data(usize::MAX).unwrap();
            let source = attempt.completed_unique_data().unwrap();
            let mut worker = failed_input_fixture(source);
            let mut private = (!missing_private).then(|| Id::new("retained-private").unwrap());
            let mut plan = missing_private.then(|| PacketCompleteAckHostRegistrationPlan {
                connection_id: Id::new("retained-connection").unwrap(),
                features: Vec::with_capacity(3),
                extensions: Vec::with_capacity(2),
                envelope_extensions: Vec::with_capacity(5),
            });
            // The real input-take method fails after retaining whichever peer
            // exists. This failed DATA fixture issues no launch/Initial/Recipe.
            assert_eq!(
                worker.retain_initial_operands_data(&mut private, &mut plan),
                Err(RuntimeError::OwnerUnavailable)
            );
            let extra = worker.retained_storage_data(usize::MAX).unwrap();
            source.ack_birth_attempted = true;
            source.native_import18_birth_construction = Some(Box::new(worker));
            let address = source
                .native_import18_birth_construction
                .as_deref()
                .unwrap() as *const _;
            let actual = before + extra;
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
            assert_eq!(
                attempt.retained_requested_storage_data(actual - 1),
                Err(RuntimeError::ResourceLimit)
            );
            let source = attempt.completed_data().unwrap();
            assert!(
                source
                    .original_complete_code_retained_storage_precredit_data(usize::MAX)
                    .is_err()
            );
            assert!(
                source
                    .original_complete_report_startup_retained_storage_precredit_data(usize::MAX)
                    .is_err()
            );
            assert!(
                source
                    .original_complete_retained_storage_precredit_data(usize::MAX)
                    .is_err()
            );
            assert!(source.ack_peer_birth.borrow().is_none());
            assert!(source.authenticate_current_native().is_err());
            let worker = source
                .native_import18_birth_construction
                .as_deref()
                .unwrap();
            assert_eq!(worker as *const _, address);
            assert!(worker.inputs_started && worker.failed);
            assert!(private.is_none() && plan.is_none());
            let mut retry = Some(Id::new("retry-private").unwrap());
            let mut empty = None;
            assert_eq!(
                attempt
                    .completed_unique_data()
                    .unwrap()
                    .native_import18_birth_construction
                    .as_mut()
                    .unwrap()
                    .retain_initial_operands_data(&mut retry, &mut empty),
                Err(RuntimeError::DuplicateOperation)
            );
            assert!(retry.is_some());
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
        }
    }
}

#[test]
fn template_attempt_rejects_foreign_or_unspent_failed_worker_without_erasing_it() {
    use crate::node_adapters::cnp::semantic::packet_complete_source::template18::OriginalNativeSourceTemplate18Attempt;
    use std::rc::Rc;
    let code = Rc::new(ordinary_source(false));
    let quote = code
        .native_source_template18_construction_data(usize::MAX)
        .unwrap();
    for foreign in [false, true] {
        let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
        code.native_source_template18_into(&quote, &mut attempt)
            .unwrap();
        let source = attempt.completed_unique_data().unwrap();
        let worker = failed_input_fixture(if foreign { &code } else { source });
        source.ack_birth_attempted = foreign;
        source.native_import18_birth_construction = Some(Box::new(worker));
        let address = source
            .native_import18_birth_construction
            .as_deref()
            .unwrap() as *const _;
        assert_eq!(
            attempt.retained_requested_storage_data(usize::MAX),
            Err(if foreign {
                RuntimeError::ForeignAuthority
            } else {
                RuntimeError::OutstandingObligations
            })
        );
        assert_eq!(
            attempt
                .completed_data()
                .unwrap()
                .native_import18_birth_construction
                .as_deref()
                .unwrap() as *const _,
            address
        );
        assert!(
            attempt
                .completed_data()
                .unwrap()
                .native_import18_birth_construction
                .as_deref()
                .unwrap()
                .failed
        );
    }
}
