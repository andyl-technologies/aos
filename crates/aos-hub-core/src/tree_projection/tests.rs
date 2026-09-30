//! Verified selection, continuation and source-boundary regressions.

use super::*;

fn fixture(count: usize) -> (String, Vec<u8>, Vec<String>) {
    let entries = (0..count)
        .map(|index| TreeEntry {
            name: format!("package-{index:02}.toml"),
            mode: if index % 2 == 0 { "100644" } else { "100755" }.into(),
            oid: object::hash_object(ObjectKind::Blob, format!("package {index}").as_bytes()),
        })
        .collect::<Vec<_>>();
    let names = entries.iter().map(|entry| entry.name.clone()).collect();
    let content = object::encode_tree(&entries);
    (
        object::hash_object(ObjectKind::Tree, &content).to_hex(),
        content,
        names,
    )
}

#[test]
fn verified_projection_selects_only_exact_names_and_preserves_modes() {
    let (oid, content, _) = fixture(10);
    let names = vec![
        "absent.toml".into(),
        "package-01.toml".into(),
        "package-08.toml".into(),
    ];
    let page = project_tree(&oid, &content, &names, None, &"a".repeat(64)).unwrap();

    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].name, "package-01.toml");
    assert_eq!(page.entries[0].kind, GitTreeEntryKind::ExecutableBlob);
    assert_eq!(page.entries[1].name, "package-08.toml");
    assert_eq!(page.end_index, names.len());
    assert!(page.next_cursor.is_none());
    assert!(!serde_json::to_string(&page)
        .unwrap()
        .contains("content_base64"));
}

#[test]
fn pages_bind_every_selected_position_and_cannot_change_source_or_predicate() {
    let (oid, content, names) = fixture(40);
    let source = "a".repeat(64);
    let first = project_tree(&oid, &content, &names, None, &source).unwrap();
    let cursor = first.next_cursor.as_ref().unwrap();
    let second = project_tree(&oid, &content, &names, Some(cursor), &source).unwrap();
    let third = project_tree(&oid, &content, &names, second.next_cursor.as_ref(), &source).unwrap();

    assert_eq!(
        (
            first.entries.len(),
            second.entries.len(),
            third.entries.len()
        ),
        (16, 16, 8)
    );
    assert_eq!(
        (
            first.end_index,
            second.start_index,
            second.end_index,
            third.start_index
        ),
        (16, 16, 32, 32)
    );
    assert!(third.next_cursor.is_none());
    assert!(project_tree(&oid, &content, &names, Some(cursor), &"b".repeat(64)).is_err());
    let mut changed_names = names.clone();
    changed_names[0] = "another.toml".into();
    assert!(project_tree(&oid, &content, &changed_names, Some(cursor), &source).is_err());
    let mut skipped = second.clone();
    skipped.start_index += 1;
    assert!(skipped
        .validate(&oid, &names, Some(cursor), &source)
        .is_err());
    let mut repeated = cursor.clone();
    repeated.next_index = names.len();
    assert!(validate_request(&oid, &names, Some(&repeated)).is_err());
}

#[test]
fn invalid_hash_ambiguous_source_and_unselected_rows_fail() {
    let (oid, content, names) = fixture(3);
    assert!(project_tree(&"b".repeat(64), &content, &names, None, &"a".repeat(64)).is_err());
    let mut duplicate = object::parse_tree(&content).unwrap();
    duplicate.push(duplicate[0].clone());
    let duplicate = object::encode_tree(&duplicate);
    let duplicate_oid = object::hash_object(ObjectKind::Tree, &duplicate).to_hex();
    assert!(project_tree(&duplicate_oid, &duplicate, &names, None, &"a".repeat(64)).is_err());
    let mut page = project_tree(&oid, &content, &names, None, &"a".repeat(64)).unwrap();
    page.entries[0].name = "unselected.toml".into();
    assert!(page.validate(&oid, &names, None, &"a".repeat(64)).is_err());
}

#[test]
fn bounded_predicates_pages_and_source_bytes_refuse_excess() {
    let (oid, _, _) = fixture(1);
    for names in [
        vec!["../other".into()],
        vec!["same".into(), "same".into()],
        vec!["z".into(), "a".into()],
        vec!["x".repeat(MAX_TREE_ENTRY_NAME_BYTES + 1)],
    ] {
        assert!(validate_request(&oid, &names, None).is_err());
    }
    let names = (0..MAX_TREE_SELECTION_NAMES + 1)
        .map(|index| format!("{index:03}"))
        .collect::<Vec<_>>();
    assert!(validate_request(&oid, &names, None).is_err());
    let oversized = vec![0; MAX_TREE_CONTENT_BYTES + 1];
    assert!(project_tree(
        &oid,
        &oversized,
        &["package-00.toml".into()],
        None,
        &"a".repeat(64)
    )
    .is_err());

    let entries = (0..MAX_TREE_PAGE_ENTRIES)
        .map(|index| TreeEntry {
            name: format!("{index:02}{}", "x".repeat(MAX_TREE_ENTRY_NAME_BYTES - 2)),
            mode: "100644".into(),
            oid: Oid::from_hex(&oid).unwrap(),
        })
        .collect::<Vec<_>>();
    let names = entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let content = object::encode_tree(&entries);
    let tree = object::hash_object(ObjectKind::Tree, &content).to_hex();
    let page = project_tree(&tree, &content, &names, None, &"a".repeat(64)).unwrap();
    assert!(serde_json::to_vec(&page).unwrap().len() < MAX_TREE_PAGE_BYTES);
}
