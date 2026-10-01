//! Encodes application audit data inside ordinary signed commit messages.
//!
//! This data is not a bucket record or a new immutable object type. The message
//! carries a canonical CBOR array as hexadecimal so ordinary commit inspection
//! preserves the exact domain registration and deletion event:
//!
//! ```text
//! domain-route-v1:<hex([domain, state, subject, token-id, roots, intent])>
//! state = 0 (active), 1 (pending), 2 (completed)
//! root = [domain, reference, node-digest, absolute-path]
//! ```

use super::Error;
use crate::domain::DomainDeletionEvent;
use terrane_core::{cbor, identity::Digest, tree_format};

const PREFIX: &str = "domain-route-v1:";

/// Holds decoded domain-route message fields without granting authority.
pub(super) struct RouteMessage {
    /// Canonical domain named by the message.
    pub(super) domain: String,
    /// Registered active, pending or completed state number.
    pub(super) state: u64,
    /// Subject recorded for the route event.
    pub(super) subject: String,
    /// Token identifier recorded for the route event.
    pub(super) token_id: [u8; 16],
    /// Canonical encoded affected-root array.
    pub(super) event: Vec<u8>,
    /// Intent commit digest bytes, or an empty value when absent.
    pub(super) intent: Vec<u8>,
}

/// Encodes a route event as a canonical commit-message payload.
///
/// # Errors
/// Returns an identity error when an affected root lacks a Terrane-v1 digest.
pub(super) fn encode(
    event: &DomainDeletionEvent,
    state: u64,
    intent: Option<Digest>,
) -> Result<String, Error> {
    let mut roots = Vec::new();
    cbor::write_array(&mut roots, event.roots.len());
    for root in &event.roots {
        cbor::write_array(&mut roots, 4);
        cbor::write_text(&mut roots, &root.domain);
        cbor::write_text(&mut roots, &root.reference);
        cbor::write_bytes(&mut roots, &root.root.terrane_v1_digest()?);
        cbor::write_bytes(&mut roots, &root.path);
    }
    let mut payload = Vec::new();
    cbor::write_array(&mut payload, 6);
    cbor::write_text(&mut payload, &event.domain);
    cbor::write_uint(&mut payload, state);
    cbor::write_text(&mut payload, &event.subject);
    cbor::write_bytes(&mut payload, &event.token_id);
    payload.extend(roots);
    cbor::write_bytes(
        &mut payload,
        intent.as_ref().map_or(&[], |value| value.as_slice()),
    );
    Ok(format!(
        "{PREFIX}{}",
        payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

/// Decodes and validates the canonical route-message payload.
///
/// # Errors
/// Rejects malformed, oversized or noncanonical payloads and invalid fields.
pub(super) fn decode(message: &str) -> Result<RouteMessage, Error> {
    let hex = message.strip_prefix(PREFIX).ok_or(Error::Unrealizable)?;
    if hex.len() % 2 != 0 || hex.len() > 2 * 1024 * 1024 {
        return Err(Error::Unrealizable);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        if pair
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
        {
            return Err(Error::Unrealizable);
        }
        let pair = std::str::from_utf8(pair).map_err(|_| Error::Unrealizable)?;
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| Error::Unrealizable)?);
    }
    let mut decoder = cbor::Decoder::new(&bytes);
    let invalid = |_| Error::Unrealizable;
    if decoder.array(6).map_err(invalid)? != 6 {
        return Err(Error::Unrealizable);
    }
    let domain = decoder.text(65536).map_err(invalid)?.to_owned();
    crate::domain::control_ref_name(&domain)?;
    let state = decoder.uint().map_err(invalid)?;
    if state > 2 {
        return Err(Error::Unrealizable);
    }
    let subject = decoder.text(65536).map_err(invalid)?.to_owned();
    let token_id = decoder
        .bytes(16)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| Error::Unrealizable)?;
    let start = decoder.position();
    let count = decoder.array(65536).map_err(invalid)?;
    for _ in 0..count {
        if decoder.array(4).map_err(invalid)? != 4 {
            return Err(Error::Unrealizable);
        }
        let root_domain = decoder.text(65536).map_err(invalid)?;
        if root_domain != domain {
            return Err(Error::Unrealizable);
        }
        terrane_core::refs::RefName::parse(decoder.text(65536).map_err(invalid)?)
            .map_err(|_| Error::Unrealizable)?;
        if decoder.bytes(32).map_err(invalid)?.len() != 32 {
            return Err(Error::Unrealizable);
        }
        let path = decoder.bytes(65536).map_err(invalid)?;
        if path != b"/" {
            tree_format::validate_key(path.strip_prefix(b"/").ok_or(Error::PathEscape)?)?;
        }
    }
    let event = bytes[start..decoder.position()].to_vec();
    let intent = decoder.bytes(32).map_err(invalid)?.to_vec();
    if (state == 2 && intent.len() != 32)
        || (state != 2 && !intent.is_empty())
        || (state == 0 && count != 0)
    {
        return Err(Error::Unrealizable);
    }
    decoder.finish().map_err(invalid)?;
    Ok(RouteMessage {
        domain,
        state,
        subject,
        token_id,
        event,
        intent,
    })
}

/// Reports whether a message begins with the registered route prefix.
pub(super) fn is_route(message: &str) -> bool {
    message.starts_with(PREFIX)
}
