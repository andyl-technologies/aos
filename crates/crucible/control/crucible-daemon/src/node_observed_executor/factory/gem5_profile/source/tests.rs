//! Source-owned v1 compatibility, strict metadata and qualification boundaries.

// crucible-lint: allow panic-shortcut -- Metadata fixtures deliberately panic on failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

use super::*;

fn original_source() -> Value {
    json!({
        "schema": "crucible.gem5.source-foundation.v1",
        "revision": "f5c5a6e390f55dd5984977815bf9d0bd05da6945",
        "upstream": "https://github.com/gem5/gem5",
        "version": "25.1.0.1",
        "buildConfiguration": "ALL",
        "recipeSha256": "1".repeat(64),
        "patches": [{"file":"terminal.patch", "sha256":"2".repeat(64)}],
        "crucibleNodeProtocol": false,
        "qualifiedExactCapture": false,
        "qualifiedLiveBranch": false
    })
}

fn enriched_source() -> Value {
    let mut source = original_source();
    source["fullSystemQualified"] = json!(false);
    source["platformRecipeSha256"] = json!("3".repeat(64));
    source["platformManifestHelperSha256"] = json!("4".repeat(64));
    source["terminalSource"] = json!({
        "recipeSha256": "5".repeat(64),
        "manifestHelperSha256": "6".repeat(64),
        "patches": [{"file":"terminal.patch", "sha256":"2".repeat(64)}],
        "fullSystemQualified": false
    });
    source["nativeCompilerOrigin"] = json!({
        "schema": "crucible.gem5.native-wrapper-origin.v1",
        "native_output": "/nix/store/native-gem5",
        "native_source": "/nix/store/native-gem5-source",
        "native_derivation": "/nix/store/native-gem5.drv",
        "native_elf": {"bytes": 123, "sha256": "7".repeat(64)},
        "origin": {"bytes": 456, "sha256": "8".repeat(64)}
    });
    source
}

fn valid(value: Value) -> bool {
    serde_json::from_value::<Source>(value).is_ok_and(|source| source.validate().is_ok())
}

#[test]
fn original_and_source_enriched_v1_preserve_the_same_closed_scope() {
    assert!(valid(original_source()));
    assert!(valid(enriched_source()));

    let mut original = original_source();
    original["fullSystemQualified"] = json!(false);
    assert!(valid(original));

    // Source-only enrichments are independent optional additions to v1.
    for field in ["terminalSource", "nativeCompilerOrigin"] {
        let mut changed = enriched_source();
        changed.as_object_mut().unwrap().remove(field);
        assert!(valid(changed), "refused absent {field}");
    }
    let mut changed = enriched_source();
    changed
        .as_object_mut()
        .unwrap()
        .remove("platformRecipeSha256");
    changed
        .as_object_mut()
        .unwrap()
        .remove("platformManifestHelperSha256");
    assert!(valid(changed));
}

#[test]
fn source_metadata_cannot_promote_native_or_full_system_qualification() {
    for pointer in [
        "/crucibleNodeProtocol",
        "/qualifiedExactCapture",
        "/qualifiedLiveBranch",
        "/fullSystemQualified",
        "/terminalSource/fullSystemQualified",
    ] {
        let mut changed = enriched_source();
        *changed.pointer_mut(pointer).unwrap() = json!(true);
        assert!(!valid(changed), "accepted qualification at {pointer}");
    }
    let mut changed = enriched_source();
    changed
        .as_object_mut()
        .unwrap()
        .remove("fullSystemQualified");
    assert!(!valid(changed));
    let mut changed = enriched_source();
    changed["terminalSource"]
        .as_object_mut()
        .unwrap()
        .remove("fullSystemQualified");
    assert!(!valid(changed));
}

#[test]
fn source_versions_hashes_and_complete_extension_bindings_are_required() {
    for (pointer, replacement) in [
        ("/schema", json!("crucible.gem5.source-foundation.v2")),
        ("/version", json!("25.1.0.2")),
        ("/revision", json!("0".repeat(40))),
        ("/platformRecipeSha256", json!("invalid")),
        ("/platformManifestHelperSha256", json!("invalid")),
        ("/terminalSource/recipeSha256", json!("invalid")),
        ("/terminalSource/manifestHelperSha256", json!("invalid")),
        ("/terminalSource/patches", json!([])),
        ("/terminalSource/patches/0/file", json!("../outside.patch")),
        ("/terminalSource/patches/0/sha256", json!("0".repeat(64))),
        (
            "/nativeCompilerOrigin/schema",
            json!("crucible.gem5.native-wrapper-origin.v2"),
        ),
        ("/nativeCompilerOrigin/native_output", json!("/tmp/gem5")),
        (
            "/nativeCompilerOrigin/native_source",
            json!("/nix/store/../outside"),
        ),
        (
            "/nativeCompilerOrigin/native_derivation",
            json!("/nix/store/native"),
        ),
        ("/nativeCompilerOrigin/native_elf/bytes", json!(0)),
        ("/nativeCompilerOrigin/native_elf/bytes", json!("123")),
        (
            "/nativeCompilerOrigin/native_elf/bytes",
            json!(super::super::MAX_ARTIFACT_BYTES + 1),
        ),
        ("/nativeCompilerOrigin/native_elf/sha256", json!("invalid")),
        ("/nativeCompilerOrigin/origin/bytes", json!(0)),
        ("/nativeCompilerOrigin/origin/sha256", json!("invalid")),
    ] {
        let mut changed = enriched_source();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(!valid(changed), "accepted changed {pointer}");
    }
    for field in ["platformRecipeSha256", "platformManifestHelperSha256"] {
        let mut changed = enriched_source();
        changed.as_object_mut().unwrap().remove(field);
        assert!(!valid(changed), "accepted missing {field}");
    }
}

#[test]
fn unknown_source_fields_remain_closed_at_every_nested_boundary() {
    for pointer in [
        "",
        "/patches/0",
        "/terminalSource",
        "/terminalSource/patches/0",
        "/nativeCompilerOrigin",
        "/nativeCompilerOrigin/native_elf",
        "/nativeCompilerOrigin/origin",
    ] {
        let mut changed = enriched_source();
        changed.pointer_mut(pointer).unwrap()["qualification_override"] = json!(false);
        assert!(
            serde_json::from_value::<Source>(changed).is_err(),
            "accepted unknown field at {pointer}"
        );
    }
}

#[test]
fn optional_source_extensions_refuse_explicit_null() {
    for field in [
        "fullSystemQualified",
        "platformRecipeSha256",
        "platformManifestHelperSha256",
        "terminalSource",
        "nativeCompilerOrigin",
    ] {
        for mut changed in [original_source(), enriched_source()] {
            changed[field] = Value::Null;
            assert!(
                serde_json::from_value::<Source>(changed).is_err(),
                "accepted explicit null for {field}"
            );
        }
    }
}
