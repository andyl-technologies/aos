//! Exercises finite Control geometry and failed DATA owners without native grants.

use super::*;

fn original() -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original
}

#[test]
fn real_control_terminal_quote_has_exact_maximum_and_full_original_binding()
-> Result<(), ProviderError> {
    let control = super::super::native5::current_control17_fixture_data(false)?;
    let original = original();
    let storage = control.quote_capture17_terminal_data(&original, usize::MAX)?;
    let exact =
        usize::try_from(storage.row_data().requested_peak_data()?).map_err(|_| exhausted())?;

    assert!(
        control
            .quote_capture17_terminal_data(&original, exact)
            .is_ok()
    );
    assert!(
        control
            .quote_capture17_terminal_data(&original, exact - 1)
            .is_err()
    );
    storage.authenticate_data(&control, &original)?;

    let foreign = super::super::native5::current_control17_fixture_data(false)?;
    assert!(storage.authenticate_data(&foreign, &original).is_err());
    let mut changed = original.clone();
    changed.sequence = U64::new(original.sequence.get() + 1);
    assert!(storage.authenticate_data(&control, &changed).is_err());
    changed = original.clone();
    changed
        .extensions
        .insert("changed".into(), Value::Bool(true));
    assert!(storage.authenticate_data(&control, &changed).is_err());
    Ok(())
}

#[test]
fn terminal_projection_dominates_actual_closed_body_and_preserves_all_refs()
-> Result<(), ProviderError> {
    let reference = canonical::content_ref(b"{}", "application/json")?;
    let view = terminal::CaptureCompleted17 {
        status: "completed",
        operation_state: OperationState::Completed,
        result: terminal::CaptureResult17 {
            capture_manifest: &reference,
            owner_state_refs: [&reference],
            unchanged_cut_receipt: &reference,
        },
        extensions: Extensions::new(),
    };
    let mut out = Projection::new(usize::MAX)?;
    terminal::project_body(&mut out)?;
    let projected = out.finish(usize::MAX)?;
    let actual = actual_serialization_storage_data(&view, Default::default(), usize::MAX)?;

    within(&actual, &projected)?;
    let value = serde_json::to_value(view).map_err(ContractError::from)?;
    assert_eq!(
        value["result"]["owner_state_refs"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        value["result"]["capture_manifest"],
        value["result"]["owner_state_refs"][0]
    );
    assert_eq!(
        value["result"]["capture_manifest"],
        value["result"]["unchanged_cut_receipt"]
    );
    Ok(())
}

#[test]
fn actual_split_node_bound_grows_with_nonempty_tree_height_and_checks_overflow()
-> Result<(), ProviderError> {
    let empty = insertion::<Id, Map<String, Value>>(0)?;
    let wide = insertion::<Id, Map<String, Value>>(64)?;
    assert!(wide > empty);
    // A full root can split into two nodes and a new root. The defining bound
    // must cover those actual nodes instead of the donor's single-node row.
    let one_node = tree_storage_data(
        0,
        1,
        size_of::<Id>() + size_of::<Map<String, Value>>(),
        align_of::<Id>().max(align_of::<Map<String, Value>>()),
    )?;
    assert!(insertion::<Id, Map<String, Value>>(11)? >= 3 * one_node);
    assert!(insertion::<Id, Map<String, Value>>(usize::MAX).is_err());
    Ok(())
}

#[test]
fn canonical_correspondence_bank_retains_prefix_and_never_grows_on_refusal()
-> Result<(), ProviderError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(5).map_err(|_| exhausted())?;
    let capacity = bytes.capacity();
    let mut writer = CanonicalBank {
        bytes: &mut bytes,
        maximum: 5,
    };
    writer.write_all(b"abc").map_err(|_| exhausted())?;

    assert!(writer.write_all(b"def").is_err());
    assert_eq!(bytes, b"abc");
    assert_eq!(bytes.capacity(), capacity);
    Ok(())
}

#[test]
fn exact_reference_comparison_checks_every_closed_leaf_without_allocating_dto()
-> Result<(), ProviderError> {
    let reference = canonical::content_ref(b"{}", "application/json")?;
    let value = serde_json::to_value(&reference).map_err(ContractError::from)?;
    assert!(confirmation::matches_reference_data(&value, &reference));
    for pointer in [
        "/hash/algorithm",
        "/hash/domain",
        "/hash/digest",
        "/length",
        "/media_type",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).ok_or_else(refused)? = Value::String("changed".into());
        assert!(!confirmation::matches_reference_data(&changed, &reference));
    }
    let mut extra = value.clone();
    extra
        .as_object_mut()
        .ok_or_else(refused)?
        .insert("extra".into(), Value::Null);
    assert!(!confirmation::matches_reference_data(&extra, &reference));
    Ok(())
}

#[test]
fn actual_failed_initializers_keep_complete_inert_state_and_real_control_edges()
-> Result<(), ProviderError> {
    let control = super::super::native5::current_control17_fixture_data(false)?;
    let original = original();
    let quote = control.quote_capture17_terminal_data(&original, usize::MAX)?;
    let admitted = quote.row_data();
    let baseline = Rc::strong_count(control.capture17_identity_data());
    let registration = NativeCapture17RegistrationAttempt::failed_data(&control, admitted);
    let reply = NativeCapture17ReplyAttempt::failed_data(&control, admitted);
    let confirmation = NativeCapture17ConfirmationAttempt::failed_data(&control, admitted);
    assert_eq!(
        Rc::strong_count(control.capture17_identity_data()),
        baseline + 3
    );
    assert!(registration.registered_data(&control).is_err());
    assert!(reply.body_data().is_err());
    assert!(confirmation.completed_data(&control, &original).is_err());

    let mut observer = MetadataObserver::new();
    control.observe_settled17_root_hold_metadata_data(&mut observer)?;
    observer.observe(&registration)?;
    observer.observe(&reply)?;
    observer.observe(&confirmation)?;
    let facts = observer.finish();
    assert_eq!(facts.shared_backing_views, 4);
    assert_eq!(facts.vector_capacity_bytes, 0);
    assert_eq!(facts.string_capacity_bytes, 0);
    for (value, count) in [
        (
            serde_json::to_value(&registration).map_err(ContractError::from)?,
            10,
        ),
        (
            serde_json::to_value(&reply).map_err(ContractError::from)?,
            10,
        ),
        (
            serde_json::to_value(&confirmation).map_err(ContractError::from)?,
            15,
        ),
    ] {
        assert_eq!(value.as_object().map(Map::len), Some(count));
        assert_eq!(value["phase"], Value::String("failed".into()));
        assert_eq!(
            value["control_identity_role"],
            Value::String("current-native-control-identity".into())
        );
        assert_eq!(value["original"], Value::Null);
        assert_eq!(
            value["admitted"],
            serde_json::to_value(admitted).map_err(ContractError::from)?
        );
    }
    Ok(())
}

#[test]
fn reference_length_matches_only_canonical_u64_wire_text() -> Result<(), ProviderError> {
    let reference = canonical::content_ref(b"{}", "application/json")?;

    for expected in [0, 1, 9, 10, u64::MAX] {
        // Full references here are inert comparison DATA. Their lengths are
        // deliberately varied without claiming content verification or custody.
        let mut reference = reference.clone();
        reference.length = U64::new(expected);
        let canonical = expected.to_string();
        let value = serde_json::to_value(&reference).map_err(ContractError::from)?;
        assert!(confirmation::matches_reference_data(&value, &reference));

        for alias in [format!("0{canonical}"), format!("+{canonical}")] {
            let mut changed = value.clone();
            changed["length"] = Value::String(alias);
            assert!(!confirmation::matches_reference_data(&changed, &reference));
        }

        for rejected in [
            "",
            "-1",
            "1.0",
            "1e0",
            " 1",
            "1 ",
            "\u{0661}",
            "18446744073709551616",
        ] {
            let mut changed = value.clone();
            changed["length"] = Value::String(rejected.into());
            assert!(!confirmation::matches_reference_data(&changed, &reference));
        }
    }
    Ok(())
}
