//! Checks the actual sorted Value receipt without allocating a second DTO.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Hash<'a> {
    algorithm: &'a str,
    digest: &'a str,
    domain: &'a str,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Reference<'a> {
    hash: Hash<'a>,
    length: u64,
    media_type: &'a str,
}

fn decimal(input: &[u8]) -> Result<u64, ProviderError> {
    let value = plain_string(input)?;
    if value.is_empty()
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

fn identifier(input: &[u8]) -> Result<(), ProviderError> {
    let value = plain_string(input)?;
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(invalid());
    }
    Ok(())
}

fn hash<'a>(input: &'a [u8], domain: &str) -> Result<Hash<'a>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let algorithm = plain_string(fields.named("algorithm")?)?;
    let digest = plain_string(fields.named("digest")?)?;
    let actual_domain = plain_string(fields.named("domain")?)?;
    fields.finish()?;
    if algorithm != "blake3-256"
        || actual_domain != domain
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(Hash {
        algorithm,
        digest,
        domain: actual_domain,
    })
}

fn reference(input: &[u8]) -> Result<Reference<'_>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let hash = hash(fields.named("hash")?, "cnp.blob.v1")?;
    let length = decimal(fields.named("length")?)?;
    let media_type = plain_string(fields.named("media_type")?)?;
    fields.finish()?;
    if media_type.is_empty()
        || media_type.len() > 128
        || !media_type.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(invalid());
    }
    Ok(Reference {
        hash,
        length,
        media_type,
    })
}

fn request(input: &[u8]) -> Result<[Reference<'_>; 3], ProviderError> {
    let mut fields = Fields::object(input)?;
    identifier(fields.named("capture_operation_id")?)?;
    let _ = hash(fields.named("capture_request_hash")?, "cnp.request.v1")?;
    identifier(fields.named("capture_request_id")?)?;
    let _ = hash(
        fields.named("capture_terminal_hash")?,
        PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
    )?;
    if decimal(fields.named("capture_terminal_sequence")?)? == 0 {
        return Err(invalid());
    }
    let anchor = reference(fields.named("native_anchor_ref")?)?;
    let control = reference(fields.named("native_control_ref")?)?;
    let snapshot = reference(fields.named("native_snapshot_ref")?)?;
    if plain_string(fields.named("schema")?)?
        != PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA
    {
        return Err(invalid());
    }
    let capture = reference(fields.named("settled_capture_request")?)?;
    fields.finish()?;
    if capture.media_type != "application/json"
        || anchor == control
        || anchor == snapshot
        || control == snapshot
    {
        return Err(invalid());
    }
    Ok([anchor, control, snapshot])
}

pub(super) fn check(input: &[u8]) -> Result<(), ProviderError> {
    // The live owner stores a serde_json::Value. Its map serializer sorts keys;
    // the typed request/receipt serializers have a different emitted order.
    let mut fields = Fields::object(input)?;
    let prior = request(fields.named("capture")?)?;
    let capacity = decimal(fields.named("native_after_capacity")?)?;
    let after = reference(fields.named("native_after_ref")?)?;
    if plain_string(fields.named("schema")?)?
        != PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA
    {
        return Err(invalid());
    }
    fields.finish()?;
    if capacity < after.length || prior.contains(&after) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_rejects_noncanonical_or_overflowing_values() {
        assert_eq!(decimal(br#""12""#).unwrap(), 12);
        for raw in [
            br#""01""#.as_slice(),
            br#""+1""#,
            br#""18446744073709551616""#,
            b"12",
        ] {
            assert!(decimal(raw).is_err());
        }
    }

    #[test]
    fn receipt_refuses_unknown_or_reordered_value_fields() {
        for raw in [
            br#"{"extra":null}"#.as_slice(),
            br#"{"schema":"other","capture":null}"#,
        ] {
            assert!(check(raw).is_err());
        }
    }
}
