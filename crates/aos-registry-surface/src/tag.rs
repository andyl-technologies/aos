//! Signed tag payloads: parsing, signature splitting, and verification.
//!
//! Channel partitions are served as *raw tag payloads* — the uncompressed
//! tag object content, with the armored SSH signature appended to the
//! message (exactly what `git cat-file -p` shows for a signed tag). Release
//! tags are the same bytes wrapped as loose `tag` objects. In both cases
//! the signature covers everything before the armor block.
//!
//! Header parsing is shared with `apm` via [`crate::tagobject`] (which
//! `aos_package::registry::verify` re-exports) so the two readers cannot
//! drift on the format.

use anyhow::{bail, Context, Result};

use super::sshsig;
use super::tagobject::{parse_tag_object, verify_name_binding, TagObject};

const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";

/// A tag payload split into its signed bytes and armored signature.
#[derive(Debug, Clone)]
pub struct SignedTag {
    /// Parsed tag headers (name, target object, target type).
    pub tag: TagObject,
    /// The bytes the signature covers: everything before the armor block.
    pub signed_payload: Vec<u8>,
    /// The armored SSH signature block.
    pub signature: String,
}

/// Split and parse a raw signed tag payload.
///
/// # Errors
///
/// Returns an error when the payload is not UTF-8, has no signature block,
/// or its headers fail to parse.
pub fn parse_signed_tag(payload: &[u8]) -> Result<SignedTag> {
    let text = std::str::from_utf8(payload).context("tag payload is not UTF-8")?;
    let armor_start = text
        .find(ARMOR_BEGIN)
        .context("tag payload has no SSH signature block")?;
    let tag = parse_tag_object(text).context("parsing tag headers")?;
    Ok(SignedTag {
        tag,
        signed_payload: text.as_bytes()[..armor_start].to_vec(),
        signature: text[armor_start..].trim_end().to_string(),
    })
}

/// Parse and fully verify a signed tag payload served under `expected_name`.
///
/// Checks, in order: the SSH signature against `trusted_keys`, then the
/// name binding (the embedded tag name must equal the name the payload was
/// served under, so a valid tag cannot be replayed at another path).
///
/// # Errors
///
/// Returns an error when the payload is malformed, unsigned, signed by an
/// untrusted key, or name-bound to a different name.
pub fn verify_signed_tag(
    payload: &[u8],
    expected_name: &str,
    trusted_keys: &[String],
) -> Result<SignedTag> {
    let signed = parse_signed_tag(payload)?;
    sshsig::verify_armored(&signed.signature, &signed.signed_payload, trusted_keys)
        .with_context(|| format!("verifying tag '{}'", signed.tag.name))?;
    verify_name_binding(&signed.tag, expected_name)?;
    Ok(signed)
}

/// Render an unsigned tag payload for the given pointer.
///
/// `target_type` must be `commit` (release tag) or `tag` (channel
/// partition). Like [`super::sshsig::sign_armored`], this exists for
/// fixture construction and the future hosted-key path — production
/// signing is client-side.
///
/// # Errors
///
/// Returns an error for any other target type.
pub fn render_tag_payload(
    name: &str,
    target_oid: &str,
    target_type: &str,
    message: &str,
    when: i64,
) -> Result<String> {
    if target_type != "commit" && target_type != "tag" {
        bail!("unsupported tag target type '{target_type}'");
    }
    Ok(format!(
        "object {target_oid}\ntype {target_type}\ntag {name}\ntagger AOS Registry <registry@aos> {when} +0000\n\n{message}\n",
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tagobject::TagTarget;
    use super::*;

    fn signed_payload(name: &str, target_type: &str) -> Vec<u8> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let body =
            render_tag_payload(name, &"ab".repeat(32), target_type, "msg", 1770000000).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), &key);
        format!("{body}{armor}\n").into_bytes()
    }

    fn trusted() -> Vec<String> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        vec![sshsig::trusted_key_line("t", &key.verifying_key())]
    }

    #[test]
    fn verify_accepts_valid_partition_payload() {
        let payload = signed_payload("stable", "tag");
        let signed = verify_signed_tag(&payload, "stable", &trusted()).unwrap();
        assert_eq!(signed.tag.target_type, TagTarget::Tag);
    }

    #[test]
    fn verify_rejects_name_replay() {
        let payload = signed_payload("stable", "tag");
        assert!(verify_signed_tag(&payload, "testing", &trusted()).is_err());
    }

    #[test]
    fn verify_rejects_payload_tamper() {
        let mut payload = signed_payload("stable", "tag");
        // Flip a byte inside the signed region (the target oid).
        payload[8] = b'f';
        assert!(verify_signed_tag(&payload, "stable", &trusted()).is_err());
    }

    #[test]
    fn parse_requires_signature_block() {
        let body = render_tag_payload("1.2.3", &"ab".repeat(32), "commit", "m", 0).unwrap();
        assert!(parse_signed_tag(body.as_bytes()).is_err());
    }
}
