//! Bounded metadata and measured-package data controls; no native issuer exists.

use crucible_node_contract::{Id, U64, canonical};
use serde_json::json;

use super::{InstalledTypedReaderPackage, metadata};

// These inert controls intentionally panic when the closed metadata contract
// changes; no runtime or source qualification is constructed by the fixture.
#[test]
fn excessive_or_positional_rosters_refuse_before_typed_reconstruction() {
    let value = json!({"objects": vec![json!({"path": "/nix/store/not-measured"}); 4097]});
    assert!(metadata::array(&value, "objects", 4096).is_err());
    assert!(metadata::array(&json!([[1, 2]]), "objects", 4096).is_err());
    assert!(metadata::keys(&json!([[1, 2]]), "artifacts", &["device", "provider"]).is_err());
}

#[test]
fn exact_roster_credit_accepts_and_unexpected_roles_refuse() {
    let value = json!({"objects": vec![json!(null); 4096]});
    assert_eq!(metadata::array(&value, "objects", 4096).ok(), Some(4096));
    assert!(
        metadata::keys(
            &json!({"artifacts": {"device": null, "provider": null, "substitute": null}}),
            "artifacts",
            &["device", "provider"],
        )
        .is_err()
    );
}

#[test]
fn positional_noncanonical_and_underdeclared_metadata_refuse() {
    assert!(metadata::canonical_object(b"[]", 2).is_err());
    assert!(metadata::canonical_object(b"{ \"objects\":[]}", 1024).is_err());
    assert!(metadata::canonical_object(b"{\"objects\":[]}", 1).is_err());
}

#[test]
#[ignore = "requires independently measured CRUCIBLE_TYPED_READER_MANIFEST"]
fn actual_measured_package_regenerates_typed_data_without_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(std::env::var("CRUCIBLE_TYPED_READER_MANIFEST")?);
    let bytes = std::fs::read(&path)?;
    let original = canonical::content_ref(&bytes, "application/json")?;

    let package = InstalledTypedReaderPackage::load(&path, &original)?;
    let profile = package.profile(
        Id::new("reader")?,
        Id::new("owner/reader")?,
        U64::new(1000),
        U64::new(1_000_000_000),
        true,
    )?;

    assert_eq!(package.identity(), &original);
    assert_eq!(
        package.definition().selection().semantic_version.major,
        U64::new(1)
    );
    assert_eq!(
        package.definition().selection().semantic_version.minor,
        U64::new(1)
    );
    assert!(
        package
            .limitations()
            .iter()
            .any(|value| value == "source-class-unqualified")
    );
    assert_eq!(package.semantic_contracts().len(), 8);
    assert!(profile.input_lineage_definition().is_some());
    assert!(package.runtime_objects().count() > 0);
    Ok(())
}
