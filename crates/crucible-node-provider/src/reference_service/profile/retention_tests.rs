//! Checks complete private profile retention without installing source authority.

use super::*;
use crucible_node_contract::{U64, canonical};

fn profile() -> Result<ReferenceProfile, ProviderError> {
    ReferenceProfile::build(
        id("retention/node")?,
        id("retention/owner")?,
        canonical::content_ref(b"synthetic provider", "application/octet-stream")?,
        canonical::content_ref(b"synthetic device", "application/octet-stream")?,
        U64::new(100),
        U64::new(1_000_000_000),
    )
}

#[test]
fn complete_retention_exact_limit_and_private_body_container() -> Result<(), ProviderError> {
    let mut original = profile()?;
    let exact = measure(&original, 1024 * 1024)?;
    assert!(original.preflight_retention(exact).is_ok());
    assert!(original.preflight_retention(exact - 1).is_err());
    let public_objects = original.contents.len();

    // A body retained only in the private container must still consume credit.
    let body = vec![b'x'; 1024];
    original.content.push(ProfileContent {
        reference: canonical::content_ref(&body, "application/octet-stream")?,
        bytes: body,
    });
    assert_eq!(original.contents.len(), public_objects);
    assert!(original.preflight_retention(exact).is_err());
    let updated = measure(&original, 1024 * 1024)?;
    assert!(updated > exact);
    assert!(original.preflight_retention(updated).is_ok());
    Ok(())
}

#[test]
fn separately_retained_definition_is_charged() -> Result<(), ProviderError> {
    let mut original = profile()?;
    let exact = measure(&original, 1024 * 1024)?;
    let reference = |body| canonical::content_ref(body, "application/json");
    let definition = crate::reference_lineage::InputLineageDefinition::build_negotiated(
        reference(b"namespace")?,
        reference(b"handler")?,
        reference(b"event")?,
        reference(b"input")?,
        reference(b"stop")?,
    )?;

    // This inert shape isolates the separately owned definition; no public
    // profile body is modified and no namespace/native trust is installed.
    original.input_reader = Some(definition);
    assert!(original.preflight_retention(exact).is_err());
    let updated = measure(&original, 1024 * 1024)?;
    assert!(updated > exact);
    assert!(original.preflight_retention(updated).is_ok());
    assert!(original.preflight_retention(0).is_err());
    assert!(original.preflight_retention(64 * 1024 * 1024 + 1).is_err());
    Ok(())
}
