//! Regression coverage for allocation limits on untrusted RPC messages.

use aos_proto::aos::auth::v1::{TokenRequest, TokenRequestView};
use buffa::{DecodeError, DecodeOptions};

#[test]
fn unknown_fields_share_the_limit_for_owned_and_borrowed_requests() {
    // Field 15 is unknown to TokenRequest. Repeated empty values previously
    // amplified small wire messages into unbounded unknown-field allocations.
    let encoded = [0x7a, 0x00].repeat(5);
    let options = DecodeOptions::new().with_unknown_field_limit(4);

    let owned = options.decode_from_slice::<TokenRequest>(&encoded);
    let borrowed = options.decode_view::<TokenRequestView<'_>>(&encoded);

    assert!(matches!(owned, Err(DecodeError::UnknownFieldLimitExceeded)));
    assert!(matches!(
        borrowed,
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
}

#[test]
fn allowed_unknown_fields_preserve_forward_compatibility() {
    let encoded = [0x0a, 0x03, b'k', b'e', b'y', 0x7a, 0x00];
    let options = DecodeOptions::new().with_unknown_field_limit(1);

    let owned = options.decode_from_slice::<TokenRequest>(&encoded).unwrap();
    let borrowed = options
        .decode_view::<TokenRequestView<'_>>(&encoded)
        .unwrap();

    assert_eq!(owned.provisioning_token, "key");
    assert_eq!(borrowed.provisioning_token, "key");
}
