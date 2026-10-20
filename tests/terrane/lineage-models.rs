//! Compares independent consumed-lineage field witnesses with ordinary codecs.
//!
//! The primitive tables and public typed models are constructed separately.
//! Success demonstrates canonical fields and represented relationships only;
//! opaque tokens/signatures grant no trust, policy, lineage or operation rights.
//!
//! ```text
//! required-control-pin = [kind, owner, key, raw_digest]
//! consumed-root-policy = [root, absolute_path, [[properties, overrides]+]]
//! consumed-view-policy = [view, default_domain, [root_occurrence*]]
//! ```

/// Owns the independent primitive field tables.
#[path = "lineage_models/fields.rs"]
mod fields;
/// Owns separately constructed complete public ordinary models.
#[path = "lineage_models/models.rs"]
mod models;
/// Owns independently malformed primitive input tables.
#[path = "lineage_models/negative.rs"]
mod negative;
/// Owns primitive assembly and bounded named reference parsing.
#[path = "lineage_models/support.rs"]
mod support;

use support::{Family, Value, encode, reference};
use terrane_format::gc::publication::evidence::*;
use terrane_format::refs::Commit;

#[test]
fn reference_control_pin_models_preserve_all_kinds_and_owners() {
    let reference = reference();
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("lineage-pin-"))
            .count(),
        18
    );
    for provider in ["local", "s3", "gcs"] {
        for kind in 0..6 {
            let name = format!("lineage-pin-{provider}-{kind}");
            let wire = encode(&fields::pin(kind, provider));
            let model = models::pin(kind, provider);
            assert_eq!(reference[&name].wire, wire, "{name}");
            assert_eq!(
                model
                    .encode()
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                wire
            );
            assert_eq!(
                RequiredControlPin::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
                model
            );
        }
    }
}

#[test]
fn reference_consumed_root_models_preserve_layers_and_occurrences() {
    let reference = reference();
    let empty = vec![ConsumedRootLayer {
        properties: vec![0xa0],
        overrides: vec![0xa0],
    }];
    let empty_fields = vec![Value::Array(vec![
        Value::Bytes(vec![0xa0]),
        Value::Bytes(vec![0xa0]),
    ])];
    let mut reversed_fields = fields::layers();
    reversed_fields.reverse();
    let mut reversed_models = models::layers();
    reversed_models.reverse();
    let field_path = [
        vec![b'/'],
        [vec![vec![b'x'; 255]; 15], vec![vec![b'x'; 254], vec![b'x']]]
            .concat()
            .join(b"/".as_slice()),
    ]
    .concat();
    let mut model_path = Vec::from(b"/".as_slice());
    for index in 0..17 {
        if index > 0 {
            model_path.push(b'/');
        }
        model_path.extend(vec![
            b'x';
            match index {
                0..=14 => 255,
                15 => 254,
                _ => 1,
            }
        ]);
    }
    assert_eq!(field_path.len(), 4097);
    assert_eq!(model_path.len(), 4097);
    let cases = [
        (
            "absolute-root",
            fields::root(b"/", empty_fields.clone()),
            models::root(b"/", empty.clone()),
        ),
        (
            "full-layers",
            fields::root(b"/graft", fields::layers()),
            models::root(b"/graft", models::layers()),
        ),
        (
            "ordered-layers-reversed",
            fields::root(b"/graft", reversed_fields),
            models::root(b"/graft", reversed_models),
        ),
        (
            "path-byte-maximum",
            fields::root(&field_path, fields::layers()),
            models::root(&model_path, models::layers()),
        ),
        (
            "opaque-path-bytes",
            fields::root(b"/\xff\xfe", fields::layers()),
            models::root(&[b'/', 255, 254], models::layers()),
        ),
        (
            "maximum-layer-count",
            fields::root(b"/graft", vec![empty_fields[0].clone(); 65]),
            models::root(b"/graft", vec![empty[0].clone(); 65]),
        ),
    ];
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("lineage-root-"))
            .count(),
        cases.len()
    );

    for (name, fields, model) in cases {
        let name = format!("lineage-root-{name}");
        let wire = encode(&fields);
        assert_eq!(reference[&name].wire, wire, "{name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            ConsumedRootPolicy::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
    }
}

#[test]
fn reference_consumed_view_models_preserve_domains_and_order() {
    let reference = reference();
    let cases = [
        ("public", "public", false),
        ("private", "private:leaf", false),
        ("group", "group:readers", false),
        ("tenant", "tenant:fixture", false),
        ("empty-occurrences", "public", true),
    ];
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("lineage-view-"))
            .count(),
        cases.len()
    );
    for (name, domain, empty) in cases {
        let name = format!("lineage-view-{name}");
        let model = models::view(domain, empty);
        let wire = encode(&fields::view(domain, empty));
        assert_eq!(reference[&name].wire, wire, "{name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            ConsumedViewPolicy::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
        if !empty {
            assert_eq!(model.roots[0], model.roots[2]);
            assert_eq!(model.roots[0].root, model.roots[1].root);
            assert_ne!(model.roots[0].path, model.roots[1].path);
        }
    }
}

#[test]
fn reference_lineage_used_inputs_preserve_complete_nested_fields() {
    let reference = reference();
    let cases = [
        ("complete", true, false),
        ("empty-consumption", false, false),
        ("inert-later-property", true, true),
    ];
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("lineage-used-"))
            .count(),
        cases.len()
    );
    for (name, full, later) in cases {
        let name = format!("lineage-used-{name}");
        let model = models::used(full, later);
        let wire = encode(&fields::used(full, later));
        assert_eq!(reference[&name].wire, wire, "{name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            LineageUsedInputs::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
    }
}

#[test]
fn reference_checked_lineage_preserves_complete_source_fields() {
    let reference = reference();
    let cases = [
        ("local-complete", "local", true, false),
        ("s3-complete", "s3", true, false),
        ("gcs-maximum-loss", "gcs", true, true),
        ("legacy-empty", "local", false, false),
    ];
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("lineage-checked-"))
            .count(),
        cases.len()
    );
    for (name, provider, full, maximum) in cases {
        let name = format!("lineage-checked-{name}");
        let commit_fields = fields::commit(full);
        let commit_bytes = encode(&commit_fields);
        let commit_model = models::commit(full);
        assert_eq!(
            commit_model
                .encode()
                .unwrap_or_else(|error| panic!("Commit: {error}")),
            commit_bytes
        );
        assert_eq!(
            Commit::decode(&commit_bytes).unwrap_or_else(|error| panic!("Commit: {error}")),
            commit_model
        );
        let commit_id = fields::commit_id(&commit_bytes);
        assert_eq!(reference[&name].commit_id, Some(commit_id));
        assert_eq!(
            commit_model
                .identity()
                .unwrap_or_else(|error| panic!("Commit ID: {error}")),
            commit_id
        );
        let Value::Map(unsigned_fields) = commit_fields else {
            panic!("Commit map")
        };
        let unsigned_fields = Value::Map(
            unsigned_fields
                .into_iter()
                .filter(|(key, _)| !matches!(key, Value::UInt(8)))
                .collect(),
        );
        assert_eq!(
            commit_model
                .signature_preimage()
                .unwrap_or_else(|error| panic!("preimage: {error}")),
            encode(&unsigned_fields)
        );
        if let Some(context) = &commit_model.profile_pair.commit_context {
            assert_eq!(context.reference(), "refs/heads/_/authored");
            assert_eq!(context.surface(), "sdk");
            assert_eq!(context.locality(), &models::locality());
            assert_eq!(context.roots().len(), 2);
            assert_eq!(context.roots()[0].path(), b"/");
            assert_eq!(context.roots()[0].domain(), "public");
            assert_eq!(context.roots()[1].path(), b"/graft");
            assert_eq!(context.roots()[1].domain(), "private:leaf");
        }
        let model = models::checked(provider, full, maximum, commit_bytes, commit_id);
        let wire = encode(&fields::checked(provider, full, maximum));
        assert_eq!(reference[&name].wire, wire, "{name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            CheckedLineage::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
        assert_eq!(model.controls, model.used.controls);
        if full {
            assert_ne!(model.source_name, "refs/heads/_/authored");
        }
    }
}

#[test]
fn reference_lineage_field_negatives_require_structural_rejection() {
    let reference = reference();
    let cases = negative::cases();
    assert_eq!(cases.len(), 155);
    assert_eq!(
        cases
            .iter()
            .map(|case| &case.name)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        cases.len()
    );
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("bad-lineage-"))
            .count(),
        cases.len()
    );
    for case in cases {
        assert_eq!(reference[&case.name].wire, case.wire, "{}", case.name);
        let rejected = match case.family {
            Family::Pin => RequiredControlPin::decode(&case.wire).map(|_| ()),
            Family::Root => ConsumedRootPolicy::decode(&case.wire).map(|_| ()),
            Family::View => ConsumedViewPolicy::decode(&case.wire).map(|_| ()),
            Family::Used => LineageUsedInputs::decode(&case.wire).map(|_| ()),
            Family::Checked => CheckedLineage::decode(&case.wire).map(|_| ()),
        };
        assert!(rejected.is_err(), "accepted {}", case.name);
        if case.name.ends_with("huge-count") || case.name == "bad-lineage-root-path-too-long" {
            assert_eq!(
                rejected,
                Err(EvidenceError::Cbor(terrane_format::cbor::Error::Limit)),
                "{}",
                case.name
            );
        }
    }
}
