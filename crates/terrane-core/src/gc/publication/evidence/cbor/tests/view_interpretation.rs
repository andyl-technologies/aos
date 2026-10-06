//! Checks D-110 ordinary data against fixed literals and independent inputs.
//!
//! Literal bytes come from the sealed normative proposal, not record codecs.
//! The global registry decoder does not yet support property3/attribute2; context
//! records reject unknown property revisions while preserving unsupported
//! non-property semantic uints as ordinary data. No native
//! producer, original/current authority or index relationship is certified.

use super::*;

fn current_registries() -> ConfiguredRegistryInputs {
    let mut inputs = registries();
    inputs.property_revision = 3;
    inputs.attribute_revision = 2;
    inputs.behavioral_properties.push("index-gaps".into());
    inputs.behavioral_properties.push("index-roots".into());
    inputs.behavioral_properties.sort();
    inputs
}

fn context(mode: ViewInterpretationMode) -> ConsumedViewInterpretation {
    ConsumedViewInterpretation {
        view: [1; 32],
        original_root: [2; 32],
        mode,
        registries: registries(),
    }
}

fn one_view() -> ConsumedViewPolicy {
    ConsumedViewPolicy {
        view: [1; 32],
        default_domain: "public".into(),
        roots: vec![ConsumedRootPolicy {
            root: [2; 32],
            path: b"/".to_vec(),
            layers: vec![ConsumedRootLayer {
                properties: vec![0xa0],
                overrides: vec![0xa0],
            }],
        }],
    }
}

fn complete_inputs() -> LineageUsedInputs {
    let mut inputs = used();
    inputs.views = vec![one_view()];
    inputs.view_interpretations = Some(vec![context(ViewInterpretationMode::Legacy)]);
    inputs
}

// Hand-framed CDDL uses existing independent fixture bytes. Production
// encoders and decode/reencode round trips do not construct expected inputs.
fn supported_context_fixture() -> Vec<u8> {
    let mut bytes = vec![0x84];
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_digest(&mut bytes, &[2; 32]);
    bytes.push(0);
    bytes.extend_from_slice(&registry_fixture());
    bytes
}

fn supported_inputs_fixture() -> Vec<u8> {
    let mut bytes = used_fixture();
    bytes[0] = 0xa8;
    bytes.pop();
    bytes.extend_from_slice(&[0x81, 0x83]);
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_string(&mut bytes, 0x60, b"public");
    bytes.extend_from_slice(&[0x81, 0x83]);
    fixture_digest(&mut bytes, &[2; 32]);
    bytes.extend_from_slice(&[0x41, b'/', 0x81, 0x82, 0x41, 0xa0, 0x41, 0xa0]);
    bytes.extend_from_slice(&[7, 0x81]);
    bytes.extend_from_slice(&supported_context_fixture());
    bytes
}

// Fixed byte offsets below belong to the independently published-proposal
// context literal: two digest32 values, mode0, then registry keys0/1/2.
fn remove_literal_property(bytes: &mut Vec<u8>, encoded_name: &[u8]) {
    assert_eq!(&bytes[70..78], &[0xa9, 0, 1, 1, 3, 2, 0x98, bytes[77]]);
    let start = bytes
        .windows(encoded_name.len())
        .position(|part| part == encoded_name)
        .unwrap();
    bytes.drain(start..start + encoded_name.len());
    bytes[77] -= 1;
}

fn independent_view_fixture(root: &[u8; 32], properties: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x83];
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_string(&mut bytes, 0x60, b"public");
    bytes.extend_from_slice(&[0x81, 0x83]);
    fixture_digest(&mut bytes, root);
    bytes.extend_from_slice(&[0x41, b'/', 0x81, 0x82]);
    fixture_string(&mut bytes, 0x40, properties);
    bytes.extend_from_slice(&[0x41, 0xa0]);
    bytes
}

fn repeated_view_inputs_fixture(second_root: &[u8; 32]) -> Vec<u8> {
    let mut bytes = used_fixture();
    bytes[0] = 0xa8;
    bytes.pop();
    bytes.push(0x82);
    bytes.extend_from_slice(&independent_view_fixture(&[2; 32], &[0xa0]));
    bytes.extend_from_slice(&independent_view_fixture(second_root, &[0xa0]));
    bytes.extend_from_slice(&[7, 0x81]);
    bytes.extend_from_slice(&supported_context_fixture());
    bytes
}

#[test]
fn absent_context_preserves_published_bytes_and_reports_missing_data() {
    let bytes = hex_bytes(OLD_WHOLE_INPUTS);
    assert_eq!(
        bytes,
        crate::gc::publication::published_vectors::bytes("d79-used-inputs-claim")
    );
    let decoded = LineageUsedInputs::decode(&bytes).unwrap();
    assert_eq!(decoded, used());
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.view_interpretations, None);
    assert_eq!(decoded.check_supported_view_contexts(), Ok(false));

    let mut explicit = used();
    explicit.view_interpretations = Some(vec![]);
    let bytes = hex_bytes(EXPLICIT_EMPTY_WHOLE_INPUTS);
    assert_eq!(explicit.encode().unwrap(), bytes);
    assert_eq!(LineageUsedInputs::decode(&bytes).unwrap(), explicit);
    // Empty-set data completeness grants no nonempty signed-source evidence.
    assert_eq!(explicit.check_supported_view_contexts(), Ok(true));

    let valid = used_fixture();
    assert_eq!(
        LineageUsedInputs::decode(&valid[..valid.len() - 1]),
        Err(EvidenceError::Cbor(crate::cbor::Error::Malformed))
    );
    let mut wrong_version = valid.clone();
    wrong_version[2] = 2;
    assert_eq!(
        LineageUsedInputs::decode(&wrong_version),
        Err(EvidenceError::Schema)
    );
    let mut repeated_key = valid.clone();
    repeated_key[3] = 0;
    assert_eq!(
        LineageUsedInputs::decode(&repeated_key),
        Err(EvidenceError::Schema)
    );
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        LineageUsedInputs::decode(&trailing),
        Err(EvidenceError::Cbor(crate::cbor::Error::TrailingData))
    );
}

#[test]
fn explicit_modes_and_recorded_old_fences_match_independent_literals() {
    for (mode, literal) in [
        (ViewInterpretationMode::Legacy, LEGACY_CURRENT_CONTEXT),
        (ViewInterpretationMode::Recorded, RECORDED_CURRENT_CONTEXT),
    ] {
        let mut model = context(mode);
        model.registries = current_registries();
        let bytes = hex_bytes(literal);
        assert_eq!(model.encode().unwrap(), bytes);
        assert_eq!(ConsumedViewInterpretation::decode(&bytes).unwrap(), model);
        assert_eq!(
            model.check_supported_interpretation(),
            Err(EvidenceError::UnsupportedRevision)
        );
    }
    assert_ne!(
        hex_bytes(LEGACY_CURRENT_CONTEXT),
        hex_bytes(RECORDED_CURRENT_CONTEXT)
    );

    let mut old = context(ViewInterpretationMode::Recorded);
    old.registries.later_properties = vec!["index-gaps".into(), "index-roots".into()];
    let bytes = hex_bytes(RECORDED_OLD_CONTEXT);
    assert_eq!(old.encode().unwrap(), bytes);
    assert_eq!(ConsumedViewInterpretation::decode(&bytes).unwrap(), old);
    old.check_supported_interpretation().unwrap();

    // SPEC-known revision3 requires its exact 35 names as ordinary data,
    // independently of this implementation's interpretation-support refusal.
    let correct = hex_bytes(LEGACY_CURRENT_CONTEXT);
    assert_eq!(&correct[70..78], &[0xa9, 0, 1, 1, 3, 2, 0x98, 35]);
    let mut missing_one = correct.clone();
    remove_literal_property(&mut missing_one, b"\x6aindex-gaps");
    let mut missing_both = missing_one.clone();
    remove_literal_property(&mut missing_both, b"\x6bindex-roots");

    let mut extra = correct.clone();
    let fields = [3, 2, 4, 1, 5, 1, 6, 1, 7, 0x6a];
    let end = extra
        .windows(fields.len())
        .position(|part| part == fields)
        .unwrap();
    extra.splice(end..end, [0x62, b'z', b'z']);
    extra[77] = 36;

    let mut wrong = correct;
    let start = wrong
        .windows(11)
        .position(|part| part == b"\x6aindex-gaps")
        .unwrap();
    wrong[start + 10] = b'z';
    for malformed in [missing_one, missing_both, extra, wrong] {
        assert_eq!(
            ConsumedViewInterpretation::decode(&malformed),
            Err(EvidenceError::Contradiction)
        );
    }
}

#[test]
fn optional_context_matches_independent_complete_supported_wire() {
    let model = complete_inputs();
    let bytes = supported_inputs_fixture();
    assert_eq!(model.encode().unwrap(), bytes);
    assert_eq!(LineageUsedInputs::decode(&bytes).unwrap(), model);
    assert_eq!(model.check_supported_view_contexts(), Ok(true));

    let mut unknown = model;
    unknown.view_interpretations.as_mut().unwrap()[0]
        .registries
        .tree_revision = 2;
    let bytes = unknown.encode().unwrap();
    assert_eq!(LineageUsedInputs::decode(&bytes).unwrap(), unknown);
    assert_eq!(
        unknown.check_supported_view_contexts(),
        Err(EvidenceError::UnsupportedRevision)
    );
}

#[test]
fn global_registry_and_current_whole_support_boundaries_remain_unchanged() {
    assert_eq!(
        LineageUsedInputs::decode(&hex_bytes(CURRENT_WHOLE_INPUTS)),
        Err(EvidenceError::UnsupportedRevision)
    );
    let mut bytes = registry_fixture();
    bytes[4] = 3;
    assert_eq!(
        ConfiguredRegistryInputs::decode(&bytes),
        Err(EvidenceError::UnsupportedRevision)
    );
    assert_eq!(
        ConfiguredRegistryInputs::decode(&registry_fixture()).unwrap(),
        registries()
    );

    // Structural preservation applies only to the new context, never key4.
    let mut inputs = complete_inputs();
    inputs.registries.tree_revision = 2;
    assert_eq!(inputs.encode(), Err(EvidenceError::UnsupportedRevision));
    let mut absent = used();
    absent.registries.tree_revision = 2;
    assert_eq!(
        absent.check_supported_view_contexts(),
        Err(EvidenceError::UnsupportedRevision)
    );
}

#[test]
fn exact_view_coverage_and_original_namespace_root_are_required() {
    let valid = complete_inputs();
    for contexts in [
        vec![],
        vec![context(ViewInterpretationMode::Legacy); 2],
        vec![
            context(ViewInterpretationMode::Legacy),
            ConsumedViewInterpretation {
                view: [3; 32],
                ..context(ViewInterpretationMode::Legacy)
            },
        ],
        vec![ConsumedViewInterpretation {
            original_root: [3; 32],
            ..context(ViewInterpretationMode::Legacy)
        }],
    ] {
        let mut invalid = valid.clone();
        invalid.view_interpretations = Some(contexts);
        assert!(invalid.encode().is_err());
    }

    // The invalid wire bodies are assembled from independent CDDL fixtures,
    // so decoding is not tested only against values built by the encoder.
    let complete_wire = supported_inputs_fixture();
    let row = supported_context_fixture();
    let prefix = &complete_wire[..complete_wire.len() - row.len() - 2];
    let mut missing_wire = prefix.to_vec();
    missing_wire.extend_from_slice(&[7, 0x80]);
    assert_eq!(
        LineageUsedInputs::decode(&missing_wire),
        Err(EvidenceError::Contradiction)
    );
    let mut duplicate_wire = prefix.to_vec();
    duplicate_wire.extend_from_slice(&[7, 0x82]);
    duplicate_wire.extend_from_slice(&row);
    duplicate_wire.extend_from_slice(&row);
    assert_eq!(
        LineageUsedInputs::decode(&duplicate_wire),
        Err(EvidenceError::Schema)
    );
    let mut wrong_root_wire = prefix.to_vec();
    wrong_root_wire.extend_from_slice(&[7, 0x81]);
    let mut wrong_root_row = row;
    wrong_root_row[37..69].fill(3);
    wrong_root_wire.extend_from_slice(&wrong_root_row);
    assert_eq!(
        LineageUsedInputs::decode(&wrong_root_wire),
        Err(EvidenceError::Contradiction)
    );

    let mut missing_origin = valid.clone();
    missing_origin.views[0].roots[0].path = b"/filtered".to_vec();
    assert_eq!(missing_origin.encode(), Err(EvidenceError::Contradiction));

    let mut distinct_paths = valid;
    let mut occurrence = distinct_paths.views[0].roots[0].clone();
    occurrence.path = b"/other".to_vec();
    distinct_paths.views[0].roots.push(occurrence);
    assert!(distinct_paths.encode().is_ok());
}

#[test]
fn each_occurrence_and_override_uses_its_own_view_fence() {
    let mut inputs = complete_inputs();
    inputs.view_interpretations.as_mut().unwrap()[0].mode = ViewInterpretationMode::Recorded;
    inputs.view_interpretations.as_mut().unwrap()[0]
        .registries
        .later_properties = vec!["index-roots".into()];
    let opaque = b"\xa1\x6bindex-roots\x00".to_vec();
    let mut other = inputs.views[0].roots[0].clone();
    other.path = b"/other".to_vec();
    other.layers[0].overrides = opaque.clone();
    other.layers.push(ConsumedRootLayer {
        properties: opaque.clone(),
        overrides: vec![0xa0],
    });
    inputs.views[0].roots[0].layers[0].properties = opaque.clone();
    inputs.views[0].roots.push(other);
    assert_eq!(inputs.check_supported_view_contexts(), Ok(true));
    let bytes = inputs.encode().unwrap();
    assert_eq!(LineageUsedInputs::decode(&bytes).unwrap(), inputs);

    let mut missing_later = inputs.clone();
    missing_later.view_interpretations.as_mut().unwrap()[0]
        .registries
        .later_properties
        .clear();
    assert_eq!(missing_later.encode(), Err(EvidenceError::Schema));

    // A second view cannot borrow the first view's permitted later name.
    let mut second = one_view();
    second.view = [3; 32];
    second.roots[0].layers[0].overrides = opaque;
    inputs.views.push(second);
    inputs
        .view_interpretations
        .as_mut()
        .unwrap()
        .push(ConsumedViewInterpretation {
            view: [3; 32],
            ..context(ViewInterpretationMode::Recorded)
        });
    assert_eq!(inputs.encode(), Err(EvidenceError::Schema));
    inputs.view_interpretations.as_mut().unwrap()[1]
        .registries
        .later_properties = vec!["index-roots".into()];
    assert_eq!(inputs.check_supported_view_contexts(), Ok(true));
}

#[test]
fn independently_selected_data_detects_each_changed_used_input() {
    let stored = context(ViewInterpretationMode::Recorded);
    stored.check_selected_data(&stored).unwrap();
    let mut changed = Vec::new();
    let mut mode = stored.clone();
    mode.mode = ViewInterpretationMode::Legacy;
    changed.push(mode);
    let mut root = stored.clone();
    root.original_root = [3; 32];
    changed.push(root);
    let mut view = stored.clone();
    view.view = [3; 32];
    changed.push(view);
    let mut revision = stored.clone();
    revision.registries.property_revision = 2;
    revision
        .registries
        .behavioral_properties
        .push("index-roots".into());
    revision.registries.behavioral_properties.sort();
    changed.push(revision);
    let mut later = stored.clone();
    later.registries.later_properties.push("index-roots".into());
    changed.push(later);
    let mut attributes = stored.clone();
    attributes.registries.attribute_revision = 2;
    changed.push(attributes);
    let mut tree = stored.clone();
    tree.registries.tree_revision = 2;
    changed.push(tree);
    let mut identity = stored.clone();
    identity.registries.identity_profile = "unregistered".into();
    changed.push(identity);

    for selected in changed {
        assert_eq!(
            stored.check_selected_data(&selected),
            Err(EvidenceError::Contradiction)
        );
    }
}

#[test]
fn signed_view_data_binds_original_root_without_certifying_signature() {
    let commit = crate::refs::Commit::decode(&legacy_commit_fixture()).unwrap();
    let mut inputs = context(ViewInterpretationMode::Recorded);
    inputs.view = hex_bytes("c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6")
        .try_into()
        .unwrap();
    inputs.original_root =
        hex_bytes("9366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c20bbc392")
            .try_into()
            .unwrap();
    inputs.check_signed_view_data(&commit).unwrap();

    let mut wrong_root = inputs.clone();
    wrong_root.original_root = [3; 32];
    assert_eq!(
        wrong_root.check_signed_view_data(&commit),
        Err(EvidenceError::Contradiction)
    );
    let mut wrong_view = inputs.clone();
    wrong_view.view = [3; 32];
    assert_eq!(
        wrong_view.check_signed_view_data(&commit),
        Err(EvidenceError::Contradiction)
    );
    let mut unsigned = commit;
    unsigned.signature = None;
    assert_eq!(
        inputs.check_signed_view_data(&unsigned),
        Err(EvidenceError::Contradiction)
    );
}

#[test]
fn malformed_modes_shapes_name_fences_and_headers_refuse() {
    let valid = supported_context_fixture();
    let mut unknown_mode = valid.clone();
    unknown_mode[69] = 2;
    assert_eq!(
        ConsumedViewInterpretation::decode(&unknown_mode),
        Err(EvidenceError::Schema)
    );
    let mut short_root = valid.clone();
    short_root[36] = 31;
    short_root.remove(68);
    assert_eq!(
        ConsumedViewInterpretation::decode(&short_root),
        Err(EvidenceError::Schema)
    );
    let mut trailing = valid;
    trailing.push(0);
    assert!(ConsumedViewInterpretation::decode(&trailing).is_err());

    let mut overlapping = context(ViewInterpretationMode::Legacy);
    overlapping.registries.later_properties.push("acl".into());
    assert_eq!(overlapping.encode(), Err(EvidenceError::Contradiction));
    let mut duplicate = context(ViewInterpretationMode::Legacy);
    duplicate
        .registries
        .behavioral_properties
        .push("writers".into());
    assert_eq!(duplicate.encode(), Err(EvidenceError::Schema));

    let mut null_context = used_fixture();
    null_context[0] = 0xa8;
    null_context.extend_from_slice(&[7, 0xf6]);
    assert!(LineageUsedInputs::decode(&null_context).is_err());
    let mut unknown_field = used_fixture();
    unknown_field[0] = 0xa8;
    unknown_field.extend_from_slice(&[8, 0x80]);
    assert_eq!(
        LineageUsedInputs::decode(&unknown_field),
        Err(EvidenceError::Schema)
    );
}

#[test]
fn sorted_contexts_cover_exact_views_without_changing_view_order() {
    let mut inputs = complete_inputs();
    let mut second = one_view();
    second.view = [3; 32];
    inputs.views.insert(0, second);
    inputs
        .view_interpretations
        .as_mut()
        .unwrap()
        .push(ConsumedViewInterpretation {
            view: [3; 32],
            ..context(ViewInterpretationMode::Recorded)
        });
    assert_eq!(inputs.check_supported_view_contexts(), Ok(true));
    let bytes = inputs.encode().unwrap();
    let decoded = LineageUsedInputs::decode(&bytes).unwrap();
    assert_eq!(decoded.views[0].view, [3; 32]);
    assert_eq!(decoded.views[1].view, [1; 32]);

    let mut unsorted = inputs.clone();
    unsorted.view_interpretations.as_mut().unwrap().reverse();
    assert_eq!(unsorted.encode(), Err(EvidenceError::Schema));
    let duplicate = inputs.views[0].clone();
    inputs.views.push(duplicate);
    // Existing ordinary view-policy rows are not redefined by key7. One
    // explicit context covers the exact distinct view set and every row.
    assert_eq!(inputs.check_supported_view_contexts(), Ok(true));
    let bytes = inputs.encode().unwrap();
    assert_eq!(LineageUsedInputs::decode(&bytes).unwrap(), inputs);
    let matching_wire = repeated_view_inputs_fixture(&[2; 32]);
    let matching = LineageUsedInputs::decode(&matching_wire).unwrap();
    assert_eq!(matching.views.len(), 2);
    assert_eq!(matching.encode().unwrap(), matching_wire);
    assert_eq!(matching.check_supported_view_contexts(), Ok(true));
    assert_eq!(
        LineageUsedInputs::decode(&repeated_view_inputs_fixture(&[3; 32])),
        Err(EvidenceError::Contradiction)
    );

    // One view has one fence across every repeated row. Global allowances
    // and other rows must not supply a missing name by union or flattening.
    let mut conflicting = complete_inputs();
    conflicting.registries.later_properties = vec!["z".into()];
    conflicting.view_interpretations.as_mut().unwrap()[0].mode = ViewInterpretationMode::Recorded;
    conflicting.view_interpretations.as_mut().unwrap()[0]
        .registries
        .later_properties = vec!["index-roots".into()];
    conflicting.views[0].roots[0].layers[0].properties = b"\xa1\x6bindex-roots\x00".to_vec();
    let mut second = one_view();
    second.roots[0].layers[0].properties = b"\xa1\x61z\x00".to_vec();
    conflicting.views.push(second);
    assert_eq!(conflicting.encode(), Err(EvidenceError::Schema));

    let mut global_registry = registry_fixture();
    global_registry.pop();
    global_registry.extend_from_slice(&[0x81, 0x61, b'z']);
    let mut context_registry = registry_fixture();
    context_registry.pop();
    context_registry.push(0x81);
    fixture_string(&mut context_registry, 0x60, b"index-roots");
    let mut selected_context = vec![0x84];
    fixture_digest(&mut selected_context, &[1; 32]);
    fixture_digest(&mut selected_context, &[2; 32]);
    selected_context.push(1);
    selected_context.extend_from_slice(&context_registry);

    // Full independent wire: a global later allowance for z cannot mask its
    // absence from the single selected fence shared by both same-view rows.
    let mut conflicting_wire = vec![0xa8, 0, 1, 1, 0x80, 2, 0x80, 3, 0x81];
    conflicting_wire.extend_from_slice(&pin_fixture());
    conflicting_wire.push(4);
    conflicting_wire.extend_from_slice(&global_registry);
    conflicting_wire.push(5);
    conflicting_wire.extend_from_slice(&config_fixture());
    conflicting_wire.extend_from_slice(&[6, 0x82]);
    conflicting_wire.extend_from_slice(&independent_view_fixture(
        &[2; 32],
        b"\xa1\x6bindex-roots\x00",
    ));
    conflicting_wire.extend_from_slice(&independent_view_fixture(&[2; 32], b"\xa1\x61z\x00"));
    conflicting_wire.extend_from_slice(&[7, 0x81]);
    conflicting_wire.extend_from_slice(&selected_context);
    assert_eq!(
        LineageUsedInputs::decode(&conflicting_wire),
        Err(EvidenceError::Schema)
    );

    let mut second_context = context(ViewInterpretationMode::Recorded);
    second_context.registries.later_properties = vec!["z".into()];
    conflicting
        .view_interpretations
        .as_mut()
        .unwrap()
        .push(second_context);
    assert_eq!(conflicting.encode(), Err(EvidenceError::Schema));
}

#[test]
fn unknown_per_view_profiles_are_data_and_refuse_interpretation() {
    let mut future = hex_bytes(LEGACY_CURRENT_CONTEXT);
    future[74] = 4;
    assert_eq!(
        ConsumedViewInterpretation::decode(&future),
        Err(EvidenceError::UnsupportedRevision)
    );
    let mut unknown_property = context(ViewInterpretationMode::Recorded);
    unknown_property.registries.property_revision = 4;
    assert_eq!(
        unknown_property.encode(),
        Err(EvidenceError::UnsupportedRevision)
    );

    // Known property fences remain mandatory even when another semantic uint
    // is unsupported. Tree2 still parses as ordinary data and refuses execution.

    let baseline = context(ViewInterpretationMode::Recorded);
    let mut profiles = Vec::new();
    let mut properties = baseline.clone();
    properties.registries = current_registries();
    profiles.push(properties);
    let mut attributes = baseline.clone();
    attributes.registries.attribute_revision = 2;
    profiles.push(attributes);
    let mut selector = baseline.clone();
    selector.registries.selector_revision = 2;
    profiles.push(selector);
    let mut tree = baseline.clone();
    tree.registries.tree_revision = 2;
    profiles.push(tree);
    let mut chunk = baseline.clone();
    chunk.registries.chunk_revision = 2;
    profiles.push(chunk);
    let mut identity = baseline;
    identity.registries.identity_profile = "unregistered".into();
    profiles.push(identity);

    for profile in profiles {
        let bytes = profile.encode().unwrap();
        assert_eq!(ConsumedViewInterpretation::decode(&bytes).unwrap(), profile);
        assert_eq!(
            profile.check_supported_interpretation(),
            Err(EvidenceError::UnsupportedRevision)
        );
    }
}

const LEGACY_CURRENT_CONTEXT: &str = concat!(
    "845820010101010101010101010101010101010101010101010101010101010101010158200202020202020202020202",
    "02020202020202020202020202020202020202020200a9000101030298236361636c68626173656c696e65656368756e",
    "6b68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e6564656475",
    "7068646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d657267",
    "655f62797465736668617368657364686f6d6565696e6465786a696e6465782d676170736b696e6465782d726f6f7473",
    "656d657267656a6f6e2d72656c656173656b706173737468726f7567686870726566657463686571756f74616a726561",
    "7373656d626c796a726564756e64616e63796d7265666c6f675f72657461696e697265706c6963617465667265746169",
    "6e6e7370616e5f6d61785f62797465736573746f72656c7374726963742d6174747273657472757374647761726d7477",
    "686f6c655f7061636b5f7468726573686f6c64647769706567777269746572730302040105010601076a74657272616e",
    "652d76310880",
);

const RECORDED_CURRENT_CONTEXT: &str = concat!(
    "845820010101010101010101010101010101010101010101010101010101010101010158200202020202020202020202",
    "02020202020202020202020202020202020202020201a9000101030298236361636c68626173656c696e65656368756e",
    "6b68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e6564656475",
    "7068646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d657267",
    "655f62797465736668617368657364686f6d6565696e6465786a696e6465782d676170736b696e6465782d726f6f7473",
    "656d657267656a6f6e2d72656c656173656b706173737468726f7567686870726566657463686571756f74616a726561",
    "7373656d626c796a726564756e64616e63796d7265666c6f675f72657461696e697265706c6963617465667265746169",
    "6e6e7370616e5f6d61785f62797465736573746f72656c7374726963742d6174747273657472757374647761726d7477",
    "686f6c655f7061636b5f7468726573686f6c64647769706567777269746572730302040105010601076a74657272616e",
    "652d76310880",
);

const RECORDED_OLD_CONTEXT: &str = concat!(
    "845820010101010101010101010101010101010101010101010101010101010101010158200202020202020202020202",
    "02020202020202020202020202020202020202020201a9000101010298216361636c68626173656c696e65656368756e",
    "6b68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e6564656475",
    "7068646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d657267",
    "655f62797465736668617368657364686f6d6565696e646578656d657267656a6f6e2d72656c656173656b7061737374",
    "68726f7567686870726566657463686571756f74616a7265617373656d626c796a726564756e64616e63796d7265666c",
    "6f675f72657461696e697265706c69636174656672657461696e6e7370616e5f6d61785f62797465736573746f72656c",
    "7374726963742d6174747273657472757374647761726d7477686f6c655f7061636b5f7468726573686f6c6464776970",
    "6567777269746572730301040105010601076a74657272616e652d763108826a696e6465782d676170736b696e646578",
    "2d726f6f7473",
);

const CURRENT_WHOLE_INPUTS: &str = concat!(
    "a80001018002800381840089015820010101010101010101010101010101010101010101010101010101010101010142",
    "2f72667075626c696301020304422f6371726567697374726174696f6e2e63626f72582054be1d91e3b0eb5f6580ee56",
    "cad2140e5820200c7c7a81b03c703cc268831f7c04a9000101030298236361636c68626173656c696e65656368756e6b",
    "68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e656465647570",
    "68646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d65726765",
    "5f62797465736668617368657364686f6d6565696e6465786a696e6465782d676170736b696e6465782d726f6f747365",
    "6d657267656a6f6e2d72656c656173656b706173737468726f7567686870726566657463686571756f74616a72656173",
    "73656d626c796a726564756e64616e63796d7265666c6f675f72657461696e697265706c69636174656672657461696e",
    "6e7370616e5f6d61785f62797465736573746f72656c7374726963742d6174747273657472757374647761726d747768",
    "6f6c655f7061636b5f7468726573686f6c64647769706567777269746572730302040105010601076a74657272616e65",
    "2d7631088005aa0001016173026468696e7403a201617203616804828261700182617002051a0004000006667075626c",
    "696307666364632d316d08861a000400001a001000001a00400000183002582007070707070707070707070707070707",
    "0707070707070707070707070707070709f6068183582001010101010101010101010101010101010101010101010101",
    "01010101010101667075626c696381835820020202020202020202020202020202020202020202020202020202020202",
    "0202412f818241a041a00781845820010101010101010101010101010101010101010101010101010101010101010158",
    "20020202020202020202020202020202020202020202020202020202020202020200a9000101030298236361636c6862",
    "6173656c696e65656368756e6b68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d70",
    "72657373696f6e65646564757068646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074",
    "696f6e6f6761705f6d657267655f62797465736668617368657364686f6d6565696e6465786a696e6465782d67617073",
    "6b696e6465782d726f6f7473656d657267656a6f6e2d72656c656173656b706173737468726f75676868707265666574",
    "63686571756f74616a7265617373656d626c796a726564756e64616e63796d7265666c6f675f72657461696e69726570",
    "6c69636174656672657461696e6e7370616e5f6d61785f62797465736573746f72656c7374726963742d617474727365",
    "7472757374647761726d7477686f6c655f7061636b5f7468726573686f6c646477697065677772697465727303020401",
    "05010601076a74657272616e652d76310880",
);

const OLD_WHOLE_INPUTS: &str = concat!(
    "a70001018002800381840089015820010101010101010101010101010101010101010101010101010101010101010142",
    "2f72667075626c696301020304422f6371726567697374726174696f6e2e63626f72582054be1d91e3b0eb5f6580ee56",
    "cad2140e5820200c7c7a81b03c703cc268831f7c04a9000101010298216361636c68626173656c696e65656368756e6b",
    "68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e656465647570",
    "68646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d65726765",
    "5f62797465736668617368657364686f6d6565696e646578656d657267656a6f6e2d72656c656173656b706173737468",
    "726f7567686870726566657463686571756f74616a7265617373656d626c796a726564756e64616e63796d7265666c6f",
    "675f72657461696e697265706c69636174656672657461696e6e7370616e5f6d61785f62797465736573746f72656c73",
    "74726963742d6174747273657472757374647761726d7477686f6c655f7061636b5f7468726573686f6c646477697065",
    "67777269746572730301040105010601076a74657272616e652d7631088005aa0001016173026468696e7403a2016172",
    "03616804828261700182617002051a0004000006667075626c696307666364632d316d08861a000400001a001000001a",
    "004000001830025820070707070707070707070707070707070707070707070707070707070707070709f60680",
);

const EXPLICIT_EMPTY_WHOLE_INPUTS: &str = concat!(
    "a80001018002800381840089015820010101010101010101010101010101010101010101010101010101010101010142",
    "2f72667075626c696301020304422f6371726567697374726174696f6e2e63626f72582054be1d91e3b0eb5f6580ee56",
    "cad2140e5820200c7c7a81b03c703cc268831f7c04a9000101010298216361636c68626173656c696e65656368756e6b",
    "68636c61737369667974636f6d70616374696f6e5f7468726573686f6c646b636f6d7072657373696f6e656465647570",
    "68646567726164656466646f6d61696e6a6475726162696c6974796a656e6372797074696f6e6f6761705f6d65726765",
    "5f62797465736668617368657364686f6d6565696e646578656d657267656a6f6e2d72656c656173656b706173737468",
    "726f7567686870726566657463686571756f74616a7265617373656d626c796a726564756e64616e63796d7265666c6f",
    "675f72657461696e697265706c69636174656672657461696e6e7370616e5f6d61785f62797465736573746f72656c73",
    "74726963742d6174747273657472757374647761726d7477686f6c655f7061636b5f7468726573686f6c646477697065",
    "67777269746572730301040105010601076a74657272616e652d7631088005aa0001016173026468696e7403a2016172",
    "03616804828261700182617002051a0004000006667075626c696307666364632d316d08861a000400001a001000001a",
    "004000001830025820070707070707070707070707070707070707070707070707070707070707070709f606800780",
);
