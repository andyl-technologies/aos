//! Bounded canonical base64 and original PIO/MMIO geometry validation.
//!
//! The byte encoding has one canonical spelling, including padding:
//!
//! ```text
//! AAEC/w== decodes to four binary octets: 00 01 02 ff.
//! ```

use super::{QmpError, QmpKvmResponseBytesObservation, QmpKvmResponseBytesPayloadKind, malformed};

#[cfg(test)]
pub(super) fn decode(encoded: &str) -> Result<Vec<u8>, QmpError> {
    decode_into(encoded, Vec::new())
}

pub(super) fn decode_into(encoded: &str, mut decoded: Vec<u8>) -> Result<Vec<u8>, QmpError> {
    if encoded.len() > 5464 || !encoded.len().is_multiple_of(4) {
        return Err(malformed(
            "canonical native payload has invalid base64 length",
        ));
    }
    let padding = usize::from(encoded.ends_with('=')) + usize::from(encoded.ends_with("=="));
    let capacity = encoded.len() / 4 * 3 - padding;
    if capacity > 4096 {
        return Err(malformed(
            "canonical decoded native payload exceeds capacity",
        ));
    }
    decoded.clear();
    decoded
        .try_reserve_exact(capacity)
        .map_err(|_| malformed("canonical payload copy credit is unavailable"))?;
    for (index, group) in encoded.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let a = symbol(group[0])?;
        let b = symbol(group[1])?;
        let last = index + 1 == encoded.len() / 4;
        decoded.push((a << 2) | (b >> 4));
        if group[2] == b'=' {
            if !last || group[3] != b'=' || b & 15 != 0 {
                return Err(malformed("canonical native payload changed padding bits"));
            }
        } else {
            let c = symbol(group[2])?;
            decoded.push((b << 4) | (c >> 2));
            if group[3] == b'=' {
                if !last || c & 3 != 0 {
                    return Err(malformed("canonical native payload changed padding bits"));
                }
            } else {
                let d = symbol(group[3])?;
                decoded.push((c << 6) | d);
            }
        }
        if decoded.len() > 4096 {
            return Err(malformed(
                "canonical decoded native payload exceeds capacity",
            ));
        }
    }
    Ok(decoded)
}

fn symbol(byte: u8) -> Result<u8, QmpError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(malformed(
            "canonical native payload contains a foreign base64 symbol",
        )),
    }
}

pub(super) fn validate(
    observed: &QmpKvmResponseBytesObservation,
    bytes: &[u8],
) -> Result<(), QmpError> {
    if usize::try_from(observed.data_length).ok() != Some(bytes.len()) {
        return Err(malformed(
            "canonical payload byte count differs from its retained data",
        ));
    }
    let echo = observed.payload_kind == QmpKvmResponseBytesPayloadKind::OriginalRequest;
    let fragment = echo || matches!(observed.native_phase, 1 | 2);
    if !fragment {
        if observed.reason != 0
            || observed.address != 0
            || observed.data_offset != 0
            || observed.length != 0
            || observed.count != 0
            || observed.size != 0
            || observed.direction != 0
            || observed.data_length != 0
        {
            return Err(malformed(
                "non-fragment native facts contain unowned response geometry",
            ));
        }
        return Ok(());
    }

    let total = match observed.reason {
        6 if (1..=8).contains(&observed.length)
            && observed.count == 0
            && observed.size == 0
            && observed.data_offset == 0 =>
        {
            observed.length
        }
        2 if observed.length == 0
            && observed.address <= u64::from(u16::MAX)
            && observed.count > 0
            && matches!(observed.size, 1 | 2 | 4)
            && observed.count <= 4096 / observed.size =>
        {
            observed.count * observed.size
        }
        _ => {
            return Err(malformed(
                "canonical response has unsupported original geometry",
            ));
        }
    };
    if observed.direction > 1 || observed.data_offset.checked_add(u64::from(total)).is_none() {
        return Err(malformed(
            "canonical response direction or mapped extent is invalid",
        ));
    }
    // Native fragments publish guest write bytes; unknown echoes preserve only
    // the original handler's read-reply input, never authenticated native output.
    let expected = if (observed.direction == 1) != echo {
        total
    } else {
        0
    };
    if observed.data_length != expected {
        return Err(malformed(
            "canonical payload changed its native-versus-input classification",
        ));
    }
    if !echo
        && (observed.pending_sequence == 0
            || observed.consumed_sequence >= observed.pending_sequence)
    {
        return Err(malformed(
            "canonical pending fragment lacks original sequence custody",
        ));
    }
    Ok(())
}
