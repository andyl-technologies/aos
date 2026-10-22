//! Exercises actual unsigned DATA construction without opaque Source producers.

use super::*;
use crucible_node_format::values::MAX_ID_BYTES;

fn request() -> PacketNativeImport18BootstrapRequest {
    PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![7; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX - 2),
            maximum_simultaneous_transient_bytes: U64::new(1),
            declared_counter_scratch_bytes: U64::new(1),
        },
    }
}

fn ids() -> [Id; 3] {
    ["s", "i", "r"].map(|prefix| {
        let mut text = String::with_capacity(4096);
        text.push_str(&prefix.repeat(MAX_ID_BYTES));
        Id::new(text).unwrap()
    })
}

#[test]
fn unsigned_assignment_owns_independent_bounded_ids_and_preserves_empty_moved_roots() {
    let ids = ids();
    let request = request();
    let row = native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap();
    let mut output = None;

    native_import18_bootstrap_assignment_into_data(
        ids.each_ref(),
        &request,
        &row,
        usize::MAX,
        &mut output,
    )
    .unwrap();

    let owner = output.as_ref().unwrap();
    let history = owner.borrowed_history_data();
    assert!(history.assigned);
    assert!(!history.failed);
    assert_eq!(
        history.step,
        Some(PacketNativeImport18BootstrapAssignmentStep::Envelope)
    );
    assert_eq!(history.body, Some(&serde_json::json!({})));
    assert_eq!(history.funding, Some(&serde_json::json!({})));
    assert!(history.encoded_recipe.is_none());
    let original = history.original.unwrap();
    assert_eq!(original.sequence.get(), 2);
    assert_eq!(original.method, Method::NativeImport18Bootstrap);
    assert!(original.extensions.is_empty());
    for (actual, input) in [
        original.session_id.0.as_ref().unwrap(),
        original.incarnation_id.0.as_ref().unwrap(),
        original.request_id.0.as_ref().unwrap(),
    ]
    .into_iter()
    .zip(&ids)
    {
        assert_eq!(actual, input);
        assert_eq!(actual.allocated_capacity(), MAX_ID_BYTES);
        assert_eq!(input.allocated_capacity(), 4096);
        assert_ne!(actual.as_str().as_ptr(), input.as_str().as_ptr());
    }
    for absent in [
        &original.node_id,
        &original.execution_owner_id,
        &original.capture_owner_id,
        &original.operation_id,
    ] {
        assert!(absent.0.is_none());
    }
    assert_eq!(
        Value::Object(original.body.clone()),
        serde_json::to_value(&request).unwrap()
    );
    assert!(owner.retained_requested_bytes_data().unwrap() <= row.axes[0]);
    assert_eq!(request.recipe_identity.as_slice(), &[7; 32]);
}

#[test]
fn occupied_assignment_refuses_before_validation_or_replacement() {
    let ids = ids();
    let mut request = request();
    let row = native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap();
    let mut output = None;
    native_import18_bootstrap_assignment_into_data(
        ids.each_ref(),
        &request,
        &row,
        usize::MAX,
        &mut output,
    )
    .unwrap();
    let pointer = output
        .as_ref()
        .unwrap()
        .borrowed_history_data()
        .original
        .unwrap()
        .request_id
        .0
        .as_ref()
        .unwrap()
        .as_str()
        .as_ptr();
    request.schema = "foreign".into();

    assert!(
        native_import18_bootstrap_assignment_into_data(
            ids.each_ref(),
            &request,
            &row,
            0,
            &mut output,
        )
        .is_err()
    );

    let history = output.as_ref().unwrap().borrowed_history_data();
    assert!(history.assigned);
    assert!(!history.failed);
    assert_eq!(
        history
            .original
            .unwrap()
            .request_id
            .0
            .as_ref()
            .unwrap()
            .as_str()
            .as_ptr(),
        pointer
    );
}

#[test]
fn invalid_request_and_short_restriction_keep_installed_failed_prefixes() {
    let ids = ids();
    let row = native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap();
    for fault in 0..5 {
        let mut request = request();
        let mut changed = row;
        let mut maximum = usize::MAX;
        match fault {
            0 => request.schema.push('x'),
            1 => request.recipe_identity = Bytes::new(vec![7; 31]),
            2 => request.initial_funding.declared_counter_scratch_bytes = U64::new(0),
            3 => maximum = 0,
            _ => changed.axes[0] += 1,
        }
        let mut output = None;

        assert!(
            native_import18_bootstrap_assignment_into_data(
                ids.each_ref(),
                &request,
                &changed,
                maximum,
                &mut output,
            )
            .is_err(),
            "fault {fault}"
        );

        let owner = output.as_ref().unwrap();
        let history = owner.borrowed_history_data();
        assert!(history.failed);
        assert!(!history.assigned);
        assert!(history.step.is_none());
        assert!(history.body.is_none());
        assert!(history.funding.is_none());
        assert!(history.encoded_recipe.is_none());
        assert!(history.original.is_none());
        assert_eq!(history.requested_storage, changed.axes);
        assert_eq!(
            owner.retained_requested_bytes_data().unwrap(),
            size_of::<PacketNativeImport18BootstrapAssignmentData>()
        );
    }
}

#[test]
fn every_initialized_failed_bank_contributes_actual_capacity_to_the_census() {
    let row = native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap();
    let mut owner = PacketNativeImport18BootstrapAssignmentData {
        row,
        step: Some(PacketNativeImport18BootstrapAssignmentStep::Body),
        body: Some(serde_json::json!({"schema": "invalid retained partial"})),
        funding: Some(serde_json::json!({"retained_requested_bytes": "1"})),
        encoded_recipe: Some(String::with_capacity(2048)),
        original: None,
        assigned: false,
        failed: true,
    };
    let actual = owner.retained_requested_bytes_data().unwrap();
    assert!(actual > size_of::<PacketNativeImport18BootstrapAssignmentData>() + 2048);
    owner.encoded_recipe = None;
    assert_eq!(
        actual - owner.retained_requested_bytes_data().unwrap(),
        2048
    );
    owner.body = None;
    owner.funding = None;
    assert_eq!(
        owner.retained_requested_bytes_data().unwrap(),
        size_of::<PacketNativeImport18BootstrapAssignmentData>()
    );
}
