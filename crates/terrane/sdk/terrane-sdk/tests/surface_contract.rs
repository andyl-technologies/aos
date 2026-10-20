//! Exercises public exposure syntax, schema validation and registry contracts.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "Test fixtures and assertions intentionally panic on invalid setup."
)]

use terrane_sdk::{
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
    use terrane_sdk::config::token::validate_reference;
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
    use terrane_format::tree_format::{Attribute, Entry, EntryKind, encode_entry};
    use terrane_sdk::surface::SchemaEntryKind;

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
    schema.required_attributes.clear();
    schema.required_entries = vec![(b"cas/sha*".to_vec(), SchemaEntryKind::Directory)];
    assert!(
        surface::validate_schema(&schema, &metadata).is_err(),
        "embedded stars are literal"
    );
    schema.required_entries = vec![(b"cas/**/sha256".to_vec(), SchemaEntryKind::Directory)];
    assert!(surface::validate_schema(&schema, &metadata).is_ok());
}

#[test]
fn schema_collections_allow_empty_matches_but_literal_entries_establish_existence() {
    use terrane_sdk::surface::SchemaEntryKind;

    let metadata = ViewMetadata {
        commit: [1; 32],
        minimum_chunk_size: 65536,
        entries: Vec::new(),
        root_attributes: Vec::new(),
        properties: Vec::new(),
    };
    for pattern in [b"*".as_slice(), b"**", b"cas/*", b"cas/**/file"] {
        let schema = TreeSchema {
            required_entries: vec![(pattern.to_vec(), SchemaEntryKind::File)],
            required_attributes: vec![(pattern.to_vec(), "uid".into(), 0)],
            ..TreeSchema::default()
        };
        assert!(surface::validate_schema(&schema, &metadata).is_ok());
    }
    let mut schema = TreeSchema {
        required_attributes: vec![(b"missing".to_vec(), "uid".into(), 0)],
        ..TreeSchema::default()
    };
    assert!(surface::validate_schema(&schema, &metadata).is_ok());
    schema
        .required_entries
        .push((b"missing".to_vec(), SchemaEntryKind::File));
    assert!(surface::validate_schema(&schema, &metadata).is_err());
    schema.required_entries = vec![(b"/".to_vec(), SchemaEntryKind::Root)];
    schema.required_attributes.clear();
    assert!(surface::validate_schema(&schema, &metadata).is_ok());
    schema
        .required_attributes
        .push((b"/".to_vec(), "uid".into(), 0));
    assert!(surface::validate_schema(&schema, &metadata).is_err());
}

#[test]
fn malformed_schema_patterns_fail_independently_of_tree_matches() {
    use terrane_sdk::surface::SchemaEntryKind;

    let metadata = ViewMetadata {
        commit: [1; 32],
        minimum_chunk_size: 65536,
        entries: Vec::new(),
        root_attributes: Vec::new(),
        properties: Vec::new(),
    };
    for pattern in [
        b"".as_slice(),
        b"//a",
        b"a//b",
        b"/a/",
        b".",
        b"a/../b",
        b"a\0b",
        b"a/./b",
        b"///",
        b"/..",
    ] {
        let schemas = [
            TreeSchema {
                required_entries: vec![(pattern.to_vec(), SchemaEntryKind::File)],
                ..TreeSchema::default()
            },
            TreeSchema {
                required_attributes: vec![(pattern.to_vec(), "uid".into(), 0)],
                ..TreeSchema::default()
            },
            TreeSchema {
                forbidden_entries: vec![pattern.to_vec()],
                ..TreeSchema::default()
            },
        ];
        for schema in schemas {
            assert!(
                surface::validate_schema(&schema, &metadata).is_err(),
                "{pattern:?}"
            );
        }
    }
}

fn native_host_configuration() -> String {
    format!(
        r#"store = "bucket(file:///tmp/store)"
[host_tier]
path = "/var/lib/terrane"
size_bytes = 1048576
reassembly = "never"
[host_tier.publisher]
socket_path = "/run/terrane-publish/publisher.sock"
serve_uid = 1001
publish_uid = 1002
content_uid = 1001
content_gid = 1003
max_connections = 32
[host_tier.quota]
socket_path = "/run/terrane-quota/helper.sock"
configuration_epoch = "{}"
[host_tier.domains.public]
path = "/var/lib/terrane/public"
wipe = "none"
quota_owner_id = "public-owner"
[host_tier.domains.public.publisher]
retirement_grace_ms = 30000
chunk_profile = "cdc-1m"
chunk_seed = "{}"
"#,
        "01".repeat(16),
        "02".repeat(32),
    )
}

#[test]
fn native_host_configuration_preserves_explicit_runtime_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse(&native_host_configuration())?;
    let host = config.host_tier().ok_or("host tier")?;
    let publisher = host.publisher.as_ref().ok_or("publisher config")?;
    assert_eq!((publisher.serve_uid, publisher.publish_uid), (1001, 1002));
    assert_eq!(publisher.max_connections, 32);
    assert_eq!(
        host.quota
            .as_ref()
            .ok_or("quota config")?
            .configuration_epoch,
        [1; 16]
    );

    let domain = &host.domains["public"];
    assert_eq!(domain.quota_owner_id.as_deref(), Some("public-owner"));
    let policy = domain.publisher.as_ref().ok_or("domain policy")?;
    assert_eq!(policy.retirement_grace_ms, 30_000);
    assert_eq!(policy.chunk_seed, [2; 32]);
    assert_eq!(
        policy.profile()?,
        terrane_format::chunking::ChunkProfile::cdc_1m([2; 32])
    );
    Ok(())
}

#[test]
fn native_host_configuration_rejects_missing_or_ambiguous_operator_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = native_host_configuration();
    for (from, to) in [
        ("serve_uid = 1001", "serve_uid = 1002"),
        ("content_uid = 1001", "content_uid = 1002"),
        ("content_gid = 1003", "content_gid = 4294967295"),
        ("max_connections = 32", "max_connections = 0"),
        ("max_connections = 32", "max_connections = 1025"),
        ("retirement_grace_ms = 30000", "retirement_grace_ms = 0"),
        (
            "retirement_grace_ms = 30000",
            "retirement_grace_ms = 300001",
        ),
        ("chunk_profile = \"cdc-1m\"", "chunk_profile = \"unknown\""),
        ("chunk_profile = \"cdc-1m\"", ""),
        ("quota_owner_id = \"public-owner\"", "quota_owner_id = \"\""),
        (
            "socket_path = \"/run/terrane-quota/helper.sock\"",
            "socket_path = \"relative.sock\"",
        ),
    ] {
        assert!(
            Config::parse(&valid.replace(from, to)).is_err(),
            "accepted {to:?}"
        );
    }
    for field in ["chunk_seed", "configuration_epoch"] {
        let line = valid
            .lines()
            .find(|line| line.starts_with(field))
            .ok_or("hex field")?;
        assert!(Config::parse(&valid.replace(line, &format!("{field} = \"AA\""))).is_err());
        let width = if field == "chunk_seed" { 32 } else { 16 };
        let uppercase = format!("{field} = \"{}\"", "AB".repeat(width));
        assert!(Config::parse(&valid.replace(line, &uppercase)).is_err());
        assert!(Config::parse(&valid.replace(line, "")).is_err());
    }
    Ok(())
}
