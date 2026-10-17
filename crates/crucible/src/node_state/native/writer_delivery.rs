//! Joins the exact original controller delivery to retained native bodies.
//!
//! The JSON fields borrow the already credited whole source body. Base64 and
//! hexadecimal comparisons stream over original bytes, so validation does not
//! allocate decoded copies. This module supplies semantic preservation data;
//! the installed source factory and actual live takeover remain separate.
//!
//! ```text
//! capture-writer-final.v3 -> original request projection, earlier account,
//!                          final account, final exchange, control history, seal
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAXIMUM_DELIVERY_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_NATIVE_STORAGE_BYTES: u64 = 8 * 1024 * 1024;
const CONTROL_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery<'a> {
    kind: &'a str,
    schema: &'a str,
    capture: &'a str,
    request_projection_sha256: &'a str,
    checkpoint_status: &'a str,
    native_finalized: bool,
    native_account_bytes: &'a str,
    earlier_history_sha256: &'a str,
    history_media_type: &'a str,
    history_length: &'a str,
    history_sha256: &'a str,
    history_base64: &'a str,
    terminal_park_media_type: &'a str,
    terminal_park_length: &'a str,
    terminal_park_sha256: &'a str,
    terminal_park_base64: &'a str,
    native_exchange_sha256: &'a str,
    control_history_sha256: &'a str,
    original_role_frames: &'a str,
}

#[derive(Serialize)]
struct RequestProjection<'a> {
    // Field order matches the selected controller's canonical sorted request.
    capture: &'a str,
    kind: &'static str,
}

pub(super) struct OriginalWriterDelivery<'a> {
    body: &'a [u8],
    native_account_bytes: u64,
}

impl<'a> OriginalWriterDelivery<'a> {
    pub(super) fn parse(
        body: &'a [u8],
        capture: &str,
        earlier: &[u8],
        final_history: &[u8],
        exchange: &[u8],
        control_history: &[u8],
        terminal_park: &[u8],
    ) -> Result<Self, &'static str> {
        if body.is_empty()
            || body.len() > MAXIMUM_DELIVERY_BYTES
            || capture.is_empty()
            || capture.len() > 128
            || capture.contains('\0')
        {
            return Err("original delivery or capture exceeds its borrowed credit");
        }
        // The opaque codec uses the source Id grammar: 1..128 ASCII bytes
        // from [A-Za-z0-9][A-Za-z0-9._:/-]*. Its selected JSON producer therefore
        // emits this capture label without string escaping.
        // Borrowed strings reject escaped replacements rather than allocating
        // decoded field storage. The selected producer emits plain ASCII keys,
        // base64 and digest strings; archive objects retain the original JSON.
        let delivery: Delivery<'_> = serde_json::from_slice(body)
            .map_err(|_| "original delivery grammar or borrowed fields differ")?;
        let native_account_bytes = canonical_number(delivery.native_account_bytes)?;
        if delivery.kind != "writer_final_debits"
            || delivery.schema != "crucible.dmtcp.capture-writer-final.v3"
            || delivery.capture != capture
            || delivery.checkpoint_status != "1"
            || !delivery.native_finalized
            || native_account_bytes == 0
            || native_account_bytes > MAXIMUM_NATIVE_STORAGE_BYTES
            || delivery.history_media_type != "application/vnd.crucible.dmtcp-writer-history.v1"
            || canonical_number(delivery.history_length)? != final_history.len() as u64
            || delivery.terminal_park_media_type
                != "application/vnd.crucible.dmtcp-terminal-control-park.v1"
            || canonical_number(delivery.terminal_park_length)? != 64
            || terminal_park.len() != 64
            || control_history.len() > 5 * 1024 * 1024
        {
            return Err("delivery changed the original capture or selected geometry");
        }
        let frames = 1 + control_history.len().div_ceil(CONTROL_CHUNK_BYTES);
        if canonical_number(delivery.original_role_frames)? != frames as u64 {
            return Err("delivery omitted or changed original role frame geometry");
        }

        // The source codec's capture identity determines this closed projection;
        // no observed answer, hash supplied by a caller or decoded DTO does so.
        // At most 128 capture bytes, sixfold JSON escaping and fixed syntax fit
        // the original 1024-byte request credit before serialization allocation.
        let projection = serde_json::to_vec(&RequestProjection {
            capture,
            kind: "capture",
        })
        .map_err(|_| "original closed capture projection encoding failed")?;
        if projection.len() > 1024
            || !digest_matches(&projection, delivery.request_projection_sha256)
            || !digest_matches(earlier, delivery.earlier_history_sha256)
            || !digest_matches(final_history, delivery.history_sha256)
            || !digest_matches(terminal_park, delivery.terminal_park_sha256)
            || !digest_matches(exchange, delivery.native_exchange_sha256)
            || !digest_matches(control_history, delivery.control_history_sha256)
            || !base64_matches(final_history, delivery.history_base64)
            || !base64_matches(terminal_park, delivery.terminal_park_base64)
        {
            return Err("delivery differs from complete retained original bodies");
        }
        Ok(Self {
            body,
            native_account_bytes,
        })
    }

    pub(super) fn body(&self) -> &'a [u8] {
        self.body
    }

    // This is the original measured getter value, not admitted native capacity.
    // The installed verifier must compare it with its exact current compiled
    // profile before any Child or operational adoption can be authorized.
    pub(super) fn native_account_bytes(&self) -> u64 {
        self.native_account_bytes
    }
}

fn canonical_number(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() || text.len() > 20 || (text.len() > 1 && text.starts_with('0')) {
        return Err("delivery decimal scalar is not canonical");
    }
    text.bytes().try_fold(0u64, |value, digit| {
        if !digit.is_ascii_digit() {
            return Err("delivery decimal scalar contains a foreign byte");
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or("delivery decimal scalar overflows")
    })
}

fn digest_matches(body: &[u8], encoded: &str) -> bool {
    const HEX: &[u8] = b"0123456789abcdef";
    if encoded.len() != 64 {
        return false;
    }
    let digest = Sha256::digest(body);
    digest
        .iter()
        .zip(encoded.as_bytes().as_chunks::<2>().0)
        .all(|(byte, pair)| {
            pair[0] == HEX[usize::from(byte >> 4)] && pair[1] == HEX[usize::from(byte & 15)]
        })
}

fn base64_matches(body: &[u8], encoded: &str) -> bool {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let Some(extent) = body
        .len()
        .checked_add(2)
        .map(|length| length / 3)
        .and_then(|groups| groups.checked_mul(4))
    else {
        return false;
    };
    if extent != encoded.len() {
        return false;
    }
    body.chunks(3)
        .zip(encoded.as_bytes().as_chunks::<4>().0)
        .all(|(raw, actual)| {
            let first = raw[0];
            let second = raw.get(1).copied().unwrap_or(0);
            let third = raw.get(2).copied().unwrap_or(0);
            let expected = [
                ALPHABET[usize::from(first >> 2)],
                ALPHABET[usize::from(((first & 3) << 4) | (second >> 4))],
                if raw.len() > 1 {
                    ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))]
                } else {
                    b'='
                },
                if raw.len() > 2 {
                    ALPHABET[usize::from(third & 63)]
                } else {
                    b'='
                },
            ];
            *actual == expected
        })
}

#[cfg(test)]
#[path = "writer_delivery_tests.rs"]
mod tests;
