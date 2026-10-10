//! Checks complete borrowed installation refusal before any body enters custody.

use super::*;
use crucible_node_contract::canonical;

#[test]
fn complete_installation_aggregate_refusal_retains_no_prefix() -> Result<(), ProviderError> {
    let first = b"first";
    let second = b"second";
    let first_ref = canonical::content_ref(first, "application/octet-stream")?;
    let second_ref = canonical::content_ref(second, "application/octet-stream")?;
    let roster = [
        (&first_ref, first.as_slice()),
        (&second_ref, second.as_slice()),
    ];

    let mut short = ClientContent::new(first.len() + second.len() - 1, 2, 64)?;
    assert!(short.install_borrowed(roster).is_err());
    assert_eq!(short.references().count(), 0);
    assert_eq!(short.reserved, 0);
    let mut exact = ClientContent::new(first.len() + second.len(), 2, 64)?;
    exact.install_borrowed(roster)?;
    assert_eq!(exact.get(&first_ref)?, first);
    assert_eq!(exact.get(&second_ref)?, second);
    exact.install_borrowed(roster)?;
    assert_eq!(exact.references().count(), 2);
    assert_eq!(exact.reserved, first.len() + second.len());
    Ok(())
}

#[test]
fn complete_installation_conflict_and_object_credit_precede_prefix() -> Result<(), ProviderError> {
    let body = b"same raw body";
    let original = canonical::content_ref(body, "application/octet-stream")?;
    let mut alias = original.clone();
    alias.media_type = "text/plain".to_owned();
    let mut content = ClientContent::new(1024, 2, 64)?;

    // Both individually verify. Reusing the digest with conflicting complete
    // reference metadata still refuses the entire prospective installation.
    alias.verify(body)?;
    assert!(
        content
            .install_borrowed([(&original, body.as_slice()), (&alias, body.as_slice()),])
            .is_err()
    );
    assert_eq!(content.references().count(), 0);
    let other_body = b"another body";
    let other = canonical::content_ref(other_body, "application/octet-stream")?;
    let mut one = ClientContent::new(1024, 1, 64)?;
    assert!(
        one.install_borrowed([
            (&original, body.as_slice()),
            (&other, other_body.as_slice()),
        ])
        .is_err()
    );
    assert_eq!(one.references().count(), 0);
    Ok(())
}
