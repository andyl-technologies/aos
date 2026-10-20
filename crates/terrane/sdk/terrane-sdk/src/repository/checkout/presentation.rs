//! Derives safe inode presentation from existing canonical tree metadata.

use crate::repository::Error;
use terrane_format::{cbor::Decoder, tree_format::Attribute};

/// Reads an optional registered ownership attribute without inventing inode fields.
///
/// # Errors
/// Rejects noninteger or out-of-range ownership values rather than truncating.
pub(crate) fn ownership(attributes: &[Attribute<'_>], name: &str) -> Result<Option<u32>, Error> {
    let Some(attribute) = attributes.iter().find(|attribute| attribute.name == name) else {
        return Ok(None);
    };
    let mut decoder = Decoder::new(attribute.value);
    let value = decoder.uint().map_err(|_| Error::Unrealizable)?;
    decoder.finish().map_err(|_| Error::Unrealizable)?;
    let value = u32::try_from(value).map_err(|_| Error::Unrealizable)?;
    if value == u32::MAX {
        return Err(Error::Unrealizable);
    }
    Ok(Some(value))
}

/// Denies privileged namespaces unless a future registered policy allows them.
///
/// Unknown properties never grant namespace authority. Names and values stay raw.
pub(crate) fn visible_xattr(name: &[u8]) -> bool {
    ![
        b"security.".as_slice(),
        b"system.".as_slice(),
        b"trusted.".as_slice(),
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Ownership fixtures intentionally panic on unexpected decoding failures."
)]
mod tests {
    use super::*;

    #[test]
    fn privileged_namespaces_are_hidden_and_raw_user_names_remain_visible() {
        for name in [
            b"security.capability".as_slice(),
            b"system.posix_acl_access",
            b"trusted.overlay",
        ] {
            assert!(!visible_xattr(name));
        }
        assert!(visible_xattr(b"user.\xff"));
        assert!(visible_xattr(b"securityish.value"));
    }

    #[test]
    fn ownership_uses_only_registered_attributes_and_rejects_invalid_values() {
        let attributes = [Attribute {
            name: "uid",
            value: &[0x18, 42],
        }];
        assert_eq!(ownership(&attributes, "uid").unwrap(), Some(42));
        assert_eq!(ownership(&attributes, "gid").unwrap(), None);
        assert!(
            ownership(
                &[Attribute {
                    name: "uid",
                    value: &[0x20]
                }],
                "uid"
            )
            .is_err()
        );
    }
}
