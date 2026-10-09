//! Exercises closed graph policy; no model case supplies native qualification.

#![allow(clippy::unwrap_used)]

use super::*;

fn root(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/nix/store/00000000000000000000000000000000-{name}"
    ))
}

fn encoded(rows: &[(&str, &[&str])], roots: &[&str]) -> Vec<u8> {
    let value = serde_json::json!({"schema":"aos.reference-graph/v1",
        "roots":roots.iter().map(|name| root(name)).collect::<Vec<_>>(),"subtractRoots":[],
        "paths":rows.iter().map(|(name, refs)| serde_json::json!({"path":root(name),
            "narHash":"sha256:retained-original-metadata","narSize":12,
            "references":refs.iter().map(|name| root(name)).collect::<Vec<_>>() })).collect::<Vec<_>>() });
    canonical::canonical_json(&value).unwrap()
}

#[test]
fn follows_exact_original_roots_and_refuses_foreign_or_missing_dependencies() {
    let expected = BTreeSet::from([root("device"), root("provider")]);
    let bytes = encoded(
        &[
            ("device", &["library"]),
            ("library", &[]),
            ("provider", &["library"]),
        ],
        &["provider", "device"],
    );
    assert_eq!(
        validate_graph(&bytes, Some(&expected)).unwrap(),
        BTreeSet::from([root("device"), root("library"), root("provider")])
    );

    assert!(validate_graph(&bytes, Some(&BTreeSet::from([root("foreign")]))).is_err());
    assert!(
        validate_graph(
            &encoded(
                &[("device", &["missing"]), ("provider", &[])],
                &["provider", "device"]
            ),
            Some(&expected)
        )
        .is_err()
    );
    assert!(
        validate_graph(
            &encoded(
                &[("device", &[]), ("foreign", &[]), ("provider", &[])],
                &["provider", "device"]
            ),
            Some(&expected)
        )
        .is_err()
    );
}

#[test]
fn rejects_duplicate_unsorted_unknown_and_noncanonical_graph_material() {
    let expected = BTreeSet::from([root("provider")]);
    for rows in [
        vec![("provider", &[][..]), ("provider", &[][..])],
        vec![("z", &[][..]), ("provider", &[][..])],
    ] {
        assert!(validate_graph(&encoded(&rows, &["provider"]), Some(&expected)).is_err());
    }
    let original = encoded(&[("provider", &[])], &["provider"]);
    let mut value = canonical::parse_json(&original, 1024 * 1024).unwrap();
    value["passed"] = serde_json::json!(true);
    assert!(validate_graph(&canonical::canonical_json(&value).unwrap(), Some(&expected)).is_err());
    let mut with_newline = original;
    with_newline.push(b'\n');
    assert!(validate_graph(&with_newline, Some(&expected)).is_err());
}

#[test]
fn rejects_non_store_roots_and_traversal_without_reading_host_paths() {
    for path in [
        "/nix/store/not-a-store-root/file",
        "/tmp/provider",
        "/nix/store/../provider",
        "/nix/store/00000000000000000000000000000000-provider/./bin/provider",
    ] {
        assert!(store_root(Path::new(path)).is_err(), "{path}");
    }
    assert_eq!(
        store_root(&root("provider").join("bin/provider")).unwrap(),
        root("provider")
    );
}
