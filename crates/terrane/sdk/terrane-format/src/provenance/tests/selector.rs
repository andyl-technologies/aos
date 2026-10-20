//! Checks that attribute selectors share the registered attribute vocabulary.

use super::*;

#[test]
fn prov_selector_presets_missing_acceptance_ancestry_stays_absent_under_negation() {
    let mut annotated = entry(b"target");
    annotated.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    annotated.attrs_present = true;
    let (root, bytes) = tree(vec![item(b"file", annotated)], None);
    let mut introduction = receipt(root, crate::refs::EntryOrigin::Current);
    introduction.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let introduced = signed_record(root, Vec::new(), Some(vec![introduction]), true);
    let introducing = introduced.identity();
    let source = crate::refs::EntrySource {
        commit: introducing,
        root,
        path: b"file".to_vec(),
    };
    let (parent_root, parent_bytes) = tree(Vec::new(), None);
    let parent = signed_record(parent_root, Vec::new(), None, true);
    let mut imported_receipt = receipt(root, crate::refs::EntryOrigin::Source(source.clone()));
    imported_receipt.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Source(source),
    )]);
    let imported = signed_record(
        root,
        vec![parent.identity()],
        Some(vec![imported_receipt]),
        false,
    );
    let view = imported.identity();
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    history.insert_commit(introduced).unwrap();
    history.insert_commit(imported).unwrap();
    let location = EntryLocation {
        commit: view,
        root,
        path: b"file".to_vec(),
    };

    assert_eq!(history.introducing_commit(&location), Ok(introducing));
    assert_eq!(
        history.attribute_producer(&location, "hash.sha256"),
        Ok(introducing)
    );

    let mut selector = Vec::new();
    crate::cbor::write_array(&mut selector, 2);
    crate::cbor::write_text(&mut selector, "not");
    crate::cbor::write_array(&mut selector, 2);
    crate::cbor::write_text(&mut selector, "accepted-by");
    selector.extend_from_slice(Selector::preset(Preset::Strict).encode());
    let mut attribute_selector = Vec::new();
    crate::cbor::write_array(&mut attribute_selector, 3);
    crate::cbor::write_text(&mut attribute_selector, "attr-by");
    crate::cbor::write_text(&mut attribute_selector, "hash.sha256");
    attribute_selector.extend_from_slice(&selector);
    let mut issuer = Vec::new();
    crate::cbor::write_array(&mut issuer, 2);
    crate::cbor::write_text(&mut issuer, "issuer");
    crate::cbor::write_text(&mut issuer, "issuer");
    let mut attribute_introduction = Vec::new();
    crate::cbor::write_array(&mut attribute_introduction, 3);
    crate::cbor::write_text(&mut attribute_introduction, "attr-by");
    crate::cbor::write_text(&mut attribute_introduction, "hash.sha256");
    attribute_introduction.extend_from_slice(Selector::preset(Preset::Strict).encode());
    let mut nested_attribute = Vec::new();
    crate::cbor::write_array(&mut nested_attribute, 3);
    crate::cbor::write_text(&mut nested_attribute, "attr-by");
    crate::cbor::write_text(&mut nested_attribute, "hash.sha256");
    nested_attribute.extend_from_slice(&attribute_introduction);

    for stage in 0..3 {
        if stage == 1 {
            history.insert_commit(parent.clone()).unwrap();
        } else if stage == 2 {
            history
                .insert_tree(parent_root, &[(parent_root, parent_bytes.clone())])
                .unwrap();
        }

        for selector in [
            Selector::preset(Preset::Any),
            Selector::preset(Preset::Strict),
            Selector::decode(&issuer).unwrap(),
            Selector::decode(&attribute_introduction).unwrap(),
            Selector::decode(&nested_attribute).unwrap(),
        ] {
            let context =
                TrustContext::new(&history, view, selector, "private", Some("baseline")).unwrap();

            assert!(context.accepts(root, b"file"), "stage {stage}");
        }
        for bytes in [&selector, &attribute_selector] {
            let context = TrustContext::new(
                &history,
                view,
                Selector::decode(bytes).unwrap(),
                "private",
                Some("baseline"),
            )
            .unwrap();

            assert_eq!(context.accepts(root, b"file"), stage == 2);
        }
        assert_eq!(
            history
                .attribute_acceptance_commits(&location, "hash.sha256", introducing)
                .is_ok(),
            stage == 2
        );
        assert_eq!(history.provenance_walk(&location).is_ok(), stage == 2);
    }
}

#[test]
fn prov_selector_presets_inherited_root_acceptance_remains_required_for_any_view() {
    let mut annotated = entry(b"target");
    annotated.attrs = vec![crate::tree_format::Attribute {
        name: "hash.sha256",
        value: b"\x61x",
    }];
    annotated.attrs_present = true;
    let (child, child_bytes) = tree(vec![item(b"file", annotated)], None);
    let mut introduction = receipt(child, crate::refs::EntryOrigin::Current);
    introduction.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Current,
    )]);
    let introduced = signed_record(child, Vec::new(), Some(vec![introduction]), true);
    let source = crate::refs::EntrySource {
        commit: introduced.identity(),
        root: child,
        path: b"file".to_vec(),
    };
    let mut carried = receipt(child, crate::refs::EntryOrigin::Source(source.clone()));
    carried.attributes = Some(vec![(
        "hash.sha256".to_string(),
        crate::refs::EntryOrigin::Source(source),
    )]);

    let mut content_acceptance = Vec::new();
    crate::cbor::write_array(&mut content_acceptance, 2);
    crate::cbor::write_text(&mut content_acceptance, "not");
    crate::cbor::write_array(&mut content_acceptance, 2);
    crate::cbor::write_text(&mut content_acceptance, "accepted-by");
    content_acceptance.extend_from_slice(Selector::preset(Preset::Strict).encode());
    let mut attribute_acceptance = Vec::new();
    crate::cbor::write_array(&mut attribute_acceptance, 3);
    crate::cbor::write_text(&mut attribute_acceptance, "attr-by");
    crate::cbor::write_text(&mut attribute_acceptance, "hash.sha256");
    attribute_acceptance.extend_from_slice(&content_acceptance);

    for (requirement, expected) in [
        (Selector::preset(Preset::Strict).encode().to_vec(), true),
        (content_acceptance, false),
        (attribute_acceptance, false),
    ] {
        // A child's Any override must not remove the ancestor's constraint.
        let mut child_trust = Vec::new();
        crate::cbor::write_text(&mut child_trust, "any");
        let mut graft = entry(b"unused");
        graft.kind = crate::tree_format::EntryKind::Tree {
            root: child,
            props: Some(vec![crate::tree_format::Property {
                name: "trust",
                value: &child_trust,
            }]),
        };
        let (root, bytes) = tree(
            vec![item(b"mount", graft)],
            Some(vec![crate::tree_format::Property {
                name: "trust",
                value: &requirement,
            }]),
        );
        let imported = signed_record(root, vec![[42; 32]], Some(vec![carried.clone()]), false);
        let view = imported.identity();
        let mut history = VerifiedHistory::new(MIN_CHUNK);
        history
            .insert_tree(child, &[(child, child_bytes.clone())])
            .unwrap();
        history.insert_tree(root, &[(root, bytes)]).unwrap();
        history.insert_commit(introduced.clone()).unwrap();
        history.insert_commit(imported).unwrap();
        let location = history.locate(view, b"mount/file").unwrap().0;

        assert_eq!(
            history.introducing_commit(&location),
            Ok(introduced.identity())
        );
        assert_eq!(
            history.attribute_producer(&location, "hash.sha256"),
            Ok(introduced.identity())
        );

        let context = TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Any),
            "private",
            Some("baseline"),
        )
        .unwrap();

        assert_eq!(context.accepts_path(b"mount/file"), expected);
        assert!(history.provenance_walk(&location).is_err());
    }
}

fn attribute_selector(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::cbor::write_array(&mut bytes, 3);
    crate::cbor::write_text(&mut bytes, "attr-by");
    crate::cbor::write_text(&mut bytes, name);
    bytes.extend_from_slice(Selector::preset(Preset::Strict).encode());
    bytes
}

#[test]
fn prov_selector_presets_attribute_names_follow_registered_vocabulary() {
    for name in [
        "uid",
        "gid",
        "zstd-dictionary",
        "hash.sha256",
        "hash.sha512",
        "hash.git-blob-sha1",
        "hash.git-blob-sha256",
        "class.magic",
        "class.elf",
        "class.shebang",
        "provenance.reintroduced-from",
        "nar.hash_sha256",
        "nar.size",
        "nar.references",
        "nar.deriver",
        "nar.signatures",
        "nar.ca",
        "nar.file_hash",
        "nar.file_size",
        "nar.compression",
        "nix-cache-info.store_dir",
        "nix-cache-info.priority",
        "nix-cache-info.want_mass_query",
        "reapi.size_bytes",
        "reapi.output_digests",
        "gha.key",
        "gha.version",
        "gha.scope",
        "gha.size",
        "gha.created_at",
        "oci.media_type",
        "oci.subject",
        "oci.annotations",
        "tag.custom",
        "tag.é",
    ] {
        let bytes = attribute_selector(name);
        let selector = Selector::decode(&bytes).unwrap();

        assert_eq!(selector.encode(), bytes, "{name}");
    }

    let longest_tag = alloc::format!("tag.{}", "x".repeat(251));
    let bytes = attribute_selector(&longest_tag);
    assert_eq!(Selector::decode(&bytes).unwrap().encode(), bytes);

    for name in [
        "",
        "tag.",
        "unregistered",
        "hash.sha384",
        "nar.custom",
        "oci.custom",
        "custom.marker",
        &alloc::format!("{longest_tag}x"),
    ] {
        assert!(
            Selector::decode(&attribute_selector(name)).is_err(),
            "{name}"
        );
    }
}
