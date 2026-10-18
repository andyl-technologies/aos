//! Reads the defining fixed invocation DATA without a temporary JSON owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Fields, plain_string};

impl PacketNativeInvocationPurposeData {
    /// Reads exact emitted fields into the existing allocation-free DATA type.
    ///
    /// # Errors
    /// Refuses unknown/reordered fields, invalid bounded identifiers, hashes,
    /// source/target owner disagreement or zero original owner generation.
    pub(crate) fn read_settled17_data(input: &[u8]) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("schema")?)? != SCHEMA {
            return Err(invalid());
        }
        let purpose = plain_string(fields.named("purpose")?)?;
        let source = fields.named("source")?;
        let target = read_target(fields.named("target")?)?;
        fields.finish()?;
        let purpose = match purpose {
            "original_execution" if source == b"null" => Purpose::Original,
            "restoration_target" => {
                let mut fields = Fields::object(source)?;
                let runtime = read_reference(fields.named("runtime")?)?;
                let native_state = read_reference(fields.named("native_state")?)?;
                let owner = read_identifier(fields.named("owner")?)?;
                fields.finish()?;
                if owner != target.owner {
                    return Err(invalid());
                }
                Purpose::Restoration(SourceData {
                    runtime,
                    native_state,
                    owner,
                })
            }
            _ => return Err(invalid()),
        };
        Ok(Self { target, purpose })
    }
}

fn read_hash(input: &[u8]) -> Result<HashData, ProviderError> {
    let mut fields = Fields::object(input)?;
    if plain_string(fields.named("algorithm")?)? != "blake3-256" {
        return Err(invalid());
    }
    let domain = Text::new(plain_string(fields.named("domain")?)?)?;
    let digest = plain_string(fields.named("digest")?)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let digest = Text::new(digest)?;
    fields.finish()?;
    Ok(HashData {
        algorithm: "blake3-256",
        domain,
        digest,
    })
}

fn read_decimal(input: &[u8]) -> Result<Decimal, ProviderError> {
    let text = plain_string(input)?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    Ok(Decimal(text.parse().map_err(|_| invalid())?))
}

fn read_identifier(input: &[u8]) -> Result<Text, ProviderError> {
    let text = plain_string(input)?;
    if text.is_empty()
        || !text.as_bytes()[0].is_ascii_alphanumeric()
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(invalid());
    }
    Text::new(text)
}

fn read_reference(input: &[u8]) -> Result<ReferenceData, ProviderError> {
    let mut fields = Fields::object(input)?;
    let hash = read_hash(fields.named("hash")?)?;
    let length = read_decimal(fields.named("length")?)?;
    let media_type = read_media(fields.named("media_type")?)?;
    if hash.domain.text()? != "cnp.blob.v1" {
        return Err(invalid());
    }
    fields.finish()?;
    Ok(ReferenceData {
        hash,
        length,
        media_type,
    })
}

fn read_target(input: &[u8]) -> Result<TargetData, ProviderError> {
    let mut fields = Fields::object(input)?;
    let target = TargetData {
        world: read_hash(fields.named("world")?)?,
        binding: read_hash(fields.named("binding")?)?,
        node: read_identifier(fields.named("node")?)?,
        owner: read_identifier(fields.named("owner")?)?,
        session: read_identifier(fields.named("session")?)?,
        incarnation: read_identifier(fields.named("incarnation")?)?,
        owner_generation: read_decimal(fields.named("owner_generation")?)?,
        prepared_token: read_identifier(fields.named("prepared_token")?)?,
        admission: read_identifier(fields.named("admission")?)?,
    };
    fields.finish()?;
    if target.world.domain.text()? != "cnp.world-binding.v1"
        || target.binding.domain.text()? != "cnp.node-binding.v1"
        || target.owner_generation.0 == 0
    {
        return Err(invalid());
    }
    Ok(target)
}

// Printable ASCII media types can contain JSON-escaped quotes/backslashes.
// Decode into the defining inline bank without serde's dynamic string scratch.
fn read_media(input: &[u8]) -> Result<Text, ProviderError> {
    if input.len() < 2 || input.first() != Some(&b'"') || input.last() != Some(&b'"') {
        return Err(invalid());
    }
    let mut bytes = [0; 128];
    let mut length = 0usize;
    let mut cursor = 1usize;
    while cursor < input.len() - 1 {
        let mut byte = input[cursor];
        cursor += 1;
        if byte == b'\\' {
            byte = *input.get(cursor).ok_or_else(invalid)?;
            cursor += 1;
            if !matches!(byte, b'"' | b'\\') {
                return Err(invalid());
            }
        } else if byte == b'"' {
            return Err(invalid());
        }
        if !(0x20..=0x7e).contains(&byte) || length == bytes.len() {
            return Err(invalid());
        }
        bytes[length] = byte;
        length += 1;
    }
    if cursor != input.len() - 1 || length == 0 {
        return Err(invalid());
    }
    Ok(Text {
        bytes,
        length: length as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_media_preserves_emitted_quote_and_backslash_escapes() -> Result<(), ProviderError> {
        let text = read_media(br#""application/example;note=\"literal\\bank\"""#)?;
        assert_eq!(text.text()?, "application/example;note=\"literal\\bank\"");
        assert!(read_media(br#""application/example\n""#).is_err());
        assert!(read_media(br#""application/example\u002f""#).is_err());
        Ok(())
    }
}
