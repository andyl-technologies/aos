//! Checks shared reference syntax and diagnostic precedence at schema boundaries.

use super::*;

#[test]
fn borrowed_content_shape_matches_validation_and_preserves_error_precedence() {
    let original = ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: "0".repeat(64),
        },
        length: 0.into(),
        media_type: "application/octet-stream".into(),
    };

    for (mutation, expected_field) in [
        ("valid", None),
        ("valid_media_boundary", None),
        ("algorithm", Some("algorithm")),
        ("empty_domain", Some("domain")),
        ("long_domain", Some("domain")),
        ("non_ascii_domain", Some("domain")),
        ("short_digest", Some("digest")),
        ("uppercase_digest", Some("digest")),
        ("non_hex_digest", Some("digest")),
        ("other_domain", Some("hash.domain")),
        ("empty_media", Some("media_type")),
        ("long_media", Some("media_type")),
        ("control_media", Some("media_type")),
        ("non_ascii_media", Some("media_type")),
    ] {
        let mut reference = original.clone();
        match mutation {
            "valid" => {}
            "valid_media_boundary" => reference.media_type = "~".repeat(128),
            "algorithm" => {
                reference.hash.algorithm.clear();
                reference.hash.domain.clear();
                reference.hash.digest.clear();
                reference.media_type.clear();
            }
            "empty_domain" => reference.hash.domain.clear(),
            "long_domain" => reference.hash.domain = "x".repeat(129),
            "non_ascii_domain" => reference.hash.domain = "é".into(),
            "short_digest" => reference.hash.digest.truncate(63),
            "uppercase_digest" => reference.hash.digest = "A".repeat(64),
            "non_hex_digest" => reference.hash.digest = "g".repeat(64),
            "other_domain" => reference.hash.domain = "other.domain".into(),
            "empty_media" => reference.media_type.clear(),
            "long_media" => reference.media_type = "x".repeat(129),
            "control_media" => reference.media_type = "text/plain\n".into(),
            "non_ascii_media" => reference.media_type = "text/é".into(),
            _ => unreachable!(),
        }

        assert_eq!(
            reference.has_valid_shape(),
            expected_field.is_none(),
            "{mutation}"
        );
        let actual = match reference.validate() {
            Ok(()) => None,
            Err(ContractError::Invalid { field, .. }) => Some(field),
            Err(_) => Some("unexpected error kind"),
        };
        assert_eq!(actual, expected_field, "{mutation}");
    }
}
