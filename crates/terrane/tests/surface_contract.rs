//! Exercises public exposure syntax, schema validation and registry contracts.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "Test fixtures and assertions intentionally panic on invalid setup."
)]

use terrane::{
    config::Config,
    role::{Role, RoleError},
    surface::{self, TreeSchema, ViewMetadata},
};

#[cfg(all(feature = "surface-sdk", unix))]
fn exposure(id: &str, endpoint: &str, extra: &str) -> String {
    format!(
        "[[expose]]\nid='{id}'\nview='refs/heads/main'\nsurface='sdk'\nat='{endpoint}'\ntoken='file:/etc/terrane/token'\n{extra}\n"
    )
}

#[test]
fn shared_role_configuration_requires_explicit_invocation_selection() {
    let config = Config::parse("store='disk(/var/lib/terrane)'\n").unwrap();
    assert_eq!(config.role(), None);
    assert_eq!(config.select_role(None), Err(RoleError::Missing));
    assert_eq!(
        config.select_role(Some(Role::Publish)).unwrap(),
        Role::Publish
    );
    let config = Config::parse("role='serve'\nstore='disk(/var/lib/terrane)'\n").unwrap();
    assert!(matches!(
        config.select_role(Some(Role::Publish)),
        Err(RoleError::Mismatch { .. })
    ));
}

#[test]
fn shared_host_configuration_preserves_requested_policy_without_runtime_claims() {
    let config = Config::parse("store='disk(/var/lib/terrane)'\n[locality]\nregion='west'\n[host_tier]\npath='/var/lib/terrane'\nsize_bytes=4096\nreassembly='always'\n[host_tier.domains.'private:東京']\npath='/var/lib/terrane/domain'\nwipe='zero'\n[tokens]\nissuer_public_keys=['file:/etc/terrane/issuer.pub']\nhost_token='file:/etc/terrane/host.token'\n").unwrap();
    assert_eq!(config.locality().region, "west");
    assert_eq!(config.host_tier().unwrap().size_bytes, 4096);
    assert_eq!(config.tokens().issuer_public_keys.len(), 1);
    assert!(
        Config::parse(
            "store='disk(/tmp)'\n[host_tier]\npath='/tmp'\nsize_bytes=0\nreassembly='never'"
        )
        .is_err()
    );
}

#[test]
fn registry_cannot_claim_uncompiled_or_runtime_loaded_surfaces() {
    for name in [
        "fuse",
        "browse",
        "nix-cache",
        "api",
        "x-plugin",
        "/tmp/plugin.so",
    ] {
        assert!(surface::registration(name).is_none());
    }
    assert_eq!(
        surface::registration("sdk").is_some(),
        cfg!(all(feature = "surface-sdk", unix))
    );
}

#[cfg(all(feature = "surface-sdk", unix))]
#[test]
fn exposures_preserve_order_and_reject_partial_configuration() {
    let text = format!(
        "store='disk(/tmp)'\n{}{}",
        exposure("first", "/tmp/first", "mode={reader='pinned'}"),
        exposure("second", "/tmp/second", "mode={reader='pinned'}")
    );
    let config = Config::parse(&text).unwrap();
    assert_eq!(
        config
            .exposures()
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for (id, endpoint, extra) in [
        ("first", "/tmp/other", "mode={reader='pinned'}"),
        ("third", "/tmp/first", "mode={reader='pinned'}"),
        ("third", "/tmp/other", "mode={reader='follow'}"),
        ("third", "/tmp/other", ""),
        ("third", "/tmp/../escape", "mode={reader='pinned'}"),
        (
            "third",
            "/tmp/other",
            "mode={reader='pinned',writer='sync'}",
        ),
    ] {
        assert!(Config::parse(&format!("{text}{}", exposure(id, endpoint, extra))).is_err());
    }
}

#[test]
fn token_references_reject_inline_credentials_and_invalid_locators() {
    use terrane::config::token::validate_reference;
    for invalid in [
        "",
        "eyJhbGciOi...",
        "file:relative",
        "file:/a/../secret",
        "secret:",
        "anonymous:refs/heads/main:unknown",
    ] {
        assert!(validate_reference(invalid).is_err(), "{invalid}");
    }
    for valid in [
        "file:/etc/terrane/token",
        "secret:provider/key",
        "/etc/terrane/token",
        "anonymous:refs/heads/main:read",
        "anonymous:refs/heads/**:read",
    ] {
        assert!(validate_reference(valid).is_ok(), "{valid}");
    }
}

#[test]
fn metadata_schema_checks_root_types_properties_and_forbidden_paths() {
    let metadata = ViewMetadata {
        commit: [9; 32],
        minimum_chunk_size: 65536,
        entries: vec![],
        root_attributes: vec![("priority".into(), vec![0x18, 40])],
        properties: vec![("hashes".into(), vec![0x80])],
    };
    let mut schema = TreeSchema {
        required_attributes: vec![(b"/".to_vec(), "priority".into(), 0)],
        required_properties: vec![("hashes".into(), vec![vec![0x80]])],
        ..TreeSchema::default()
    };
    assert!(surface::validate_schema(&schema, &metadata).is_ok());
    schema.required_attributes[0].2 = 3;
    assert!(surface::validate_schema(&schema, &metadata).is_err());
    schema.required_attributes.clear();
    schema.required_properties[0].1 = vec![vec![0x81, 0x61, b'x']];
    assert!(surface::validate_schema(&schema, &metadata).is_err());
}

#[test]
fn schemas_check_entry_kinds_attributes_root_and_forbidden_matches() {
    use terrane::surface::SchemaEntryKind;
    use terrane_core::tree_format::{Attribute, Entry, EntryKind, encode_entry};

    let entry = Entry {
        kind: EntryKind::Directory { mode: 0o700 },
        attrs: vec![Attribute {
            name: "uid",
            value: &[0x18, 42],
        }],
        attrs_present: true,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let metadata = ViewMetadata {
        commit: [8; 32],
        minimum_chunk_size: 65536,
        entries: vec![(b"cas/sha256".to_vec(), encode_entry(&entry, 65536).unwrap())],
        root_attributes: Vec::new(),
        properties: Vec::new(),
    };
    let mut schema = TreeSchema {
        required_entries: vec![
            (b"/".to_vec(), SchemaEntryKind::Root),
            (b"cas/*".to_vec(), SchemaEntryKind::Directory),
        ],
        required_attributes: vec![(b"cas/*".to_vec(), "uid".into(), 0)],
        ..TreeSchema::default()
    };
    assert!(surface::validate_schema(&schema, &metadata).is_ok());
    schema.required_entries[1].1 = SchemaEntryKind::File;
    assert!(surface::validate_schema(&schema, &metadata).is_err());
    schema.required_entries[1].1 = SchemaEntryKind::Directory;
    schema.forbidden_entries.push(b"**/sha256".to_vec());
    assert!(surface::validate_schema(&schema, &metadata).is_err());
    schema.forbidden_entries.clear();
    schema.required_attributes[0].1 = "gid".into();
    assert!(surface::validate_schema(&schema, &metadata).is_err());
}
