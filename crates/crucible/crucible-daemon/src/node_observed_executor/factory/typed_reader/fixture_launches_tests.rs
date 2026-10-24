//! Checks conservative whole-launch credit before installed payload copies.

use super::*;

#[test]
fn exact_encoded_extent_refuses_one_byte_below_credit() -> Result<(), ProviderError> {
    let body = b"four";
    let reference = canonical::content_ref(body, "application/octet-stream")?;
    let required = 8 + 1024;
    let mut exact = 16 * 1024 * 1024 - required;
    let mut objects = 2;

    charge_public_body(&reference, body, &mut exact, &mut objects)?;
    assert_eq!(exact, 16 * 1024 * 1024);
    assert_eq!(objects, 3);

    let mut short = 16 * 1024 * 1024 - required + 1;
    let original = short;
    let mut objects = 2;
    assert!(charge_public_body(&reference, body, &mut short, &mut objects).is_err());
    assert_eq!(short, original);
    assert_eq!(objects, 2);
    Ok(())
}

#[test]
fn original_body_identity_is_checked_before_retention_credit() -> Result<(), ProviderError> {
    let reference = canonical::content_ref(b"four", "application/octet-stream")?;
    let mut bytes = 4 * 1024 * 1024;
    let mut objects = 2;

    assert!(charge_public_body(&reference, b"five", &mut bytes, &mut objects).is_err());
    assert_eq!(bytes, 4 * 1024 * 1024);
    assert_eq!(objects, 2);
    Ok(())
}

#[test]
fn complete_installed_object_count_has_a_fixed_pre_copy_ceiling() -> Result<(), ProviderError> {
    let body = b"four";
    let reference = canonical::content_ref(body, "application/octet-stream")?;
    let mut bytes = 4 * 1024 * 1024;
    let mut objects = 4095;

    charge_public_body(&reference, body, &mut bytes, &mut objects)?;
    assert_eq!(objects, 4096);
    assert!(charge_public_body(&reference, body, &mut bytes, &mut objects).is_err());
    assert_eq!(objects, 4096);
    Ok(())
}
