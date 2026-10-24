//! Borrows complete source histories and owns only pre-admitted output buffers.

use std::io::{self, Write};

use serde::{Serialize, Serializer, ser::SerializeSeq};

use crate::node_contract::{ActivationRecord, OwnerIdentity};
use crucible_node_format::{HashRef, Id, Position, U64};

pub(super) struct Sequence<F>(pub(super) F);

impl<F, I> Serialize for Sequence<F>
where
    F: Fn() -> I,
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for item in (self.0)() {
            sequence.serialize_element(&item)?;
        }
        sequence.end()
    }
}

pub(super) struct ByteCredit(pub(super) usize);

impl Serialize for ByteCredit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0))?;
        for _ in 0..self.0 {
            sequence.serialize_element(&255u8)?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
pub(super) struct Activation<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: &'a [OwnerIdentity],
    boundary: Position,
}

impl<'a> From<&'a ActivationRecord> for Activation<'a> {
    fn from(record: &'a ActivationRecord) -> Self {
        Self {
            generation: record.generation,
            activation_id: &record.activation_id,
            world_binding_hash: &record.world_binding_hash,
            owners: &record.owners,
            boundary: record.boundary,
        }
    }
}

pub(super) struct Counter {
    maximum: usize,
    used: usize,
}

impl Counter {
    pub(super) fn new(maximum: usize) -> Self {
        Self { maximum, used: 0 }
    }

    pub(super) fn used(&self) -> usize {
        self.used
    }
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| io::Error::other("complete original history exceeds selected credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct Buffer {
    maximum: usize,
    bytes: Vec<u8>,
}

impl Buffer {
    pub(super) fn new(maximum: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self { maximum, bytes })
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other("original history output exceeds selected credit"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Counts borrowed serde JSON using the authoritative JCS numeric encoder.
///
/// Strings and delimiters have identical byte lengths in both encoders. Only
/// number tokens need translation; their fixed scratch is independent of the
/// complete history size and survives arbitrary sink write boundaries.
pub(super) struct CanonicalCounter {
    credit: Counter,
    number: [u8; 64],
    number_length: usize,
    in_string: bool,
    escaped: bool,
}

impl CanonicalCounter {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            credit: Counter::new(maximum),
            number: [0; 64],
            number_length: 0,
            in_string: false,
            escaped: false,
        }
    }

    pub(super) fn finish(mut self) -> io::Result<usize> {
        self.finish_number()?;
        if self.in_string || self.escaped {
            return Err(io::Error::other(
                "borrowed history has an incomplete string",
            ));
        }
        Ok(self.credit.used())
    }

    fn finish_number(&mut self) -> io::Result<()> {
        if self.number_length == 0 {
            return Ok(());
        }
        let token =
            std::str::from_utf8(&self.number[..self.number_length]).map_err(io::Error::other)?;
        // Rust's correctly rounded decimal parser recovers the serializer's
        // binary64 value. Integer tokens take the same binary64 conversion as
        // Number::as_f64 in JCS; serde_json's optional approximate float parser
        // must not introduce a different rounding before this size admission.
        let number = token.parse::<f64>().map_err(io::Error::other)?;
        let number = serde_json::Number::from_f64(number)
            .ok_or_else(|| io::Error::other("borrowed history number is not finite"))?;
        // Do not duplicate the JCS rounding or exponent rules. This tiny Value
        // reaches the same numeric branch that writes the final history body.
        crucible_node_format::canonical::canonical_json_to_writer(
            &serde_json::Value::Number(number),
            &mut self.credit,
        )
        .map_err(io::Error::other)?;
        self.number_length = 0;
        Ok(())
    }

    fn write_byte(&mut self, byte: u8) -> io::Result<()> {
        if self.in_string {
            self.credit.write_all(&[byte])?;
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
            return Ok(());
        }
        if self.number_length != 0 {
            if matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                return self.push_number(byte);
            }
            self.finish_number()?;
        }
        if matches!(byte, b'0'..=b'9' | b'-') {
            return self.push_number(byte);
        }
        self.in_string = byte == b'"';
        self.credit.write_all(&[byte])
    }

    fn push_number(&mut self, byte: u8) -> io::Result<()> {
        let slot = self.number.get_mut(self.number_length).ok_or_else(|| {
            io::Error::other("borrowed history number exceeds bounded token scratch")
        })?;
        *slot = byte;
        self.number_length += 1;
        Ok(())
    }
}

impl Write for CanonicalCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for &byte in bytes {
            self.write_byte(byte)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // A flush is not end of JSON: a number may continue in the next write.
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    #[test]
    fn canonical_credit_matches_numbers_across_every_write_boundary() {
        let value = json!({
            "numbers": [1e20, 1e-6, 1e-7, -0.0, 1.234e30, -1.234e-30, 1.2345678901234567,
                18446744073709551615u64],
            "quoted": "digits 1e+20 and escaped \\\" -0.0 ",
        });
        let original = serde_json::to_vec(&value).unwrap();
        let expected = canonical::canonical_json(&value).unwrap().len();
        assert!(original.len() < expected);

        for split in 0..=original.len() {
            let mut credit = CanonicalCounter::new(expected);
            credit.write_all(&original[..split]).unwrap();
            credit.flush().unwrap();
            credit.write_all(&original[split..]).unwrap();
            assert_eq!(credit.finish().unwrap(), expected, "split {split}");
        }
        let mut credit = CanonicalCounter::new(expected);
        for byte in original {
            credit.write_all(&[byte]).unwrap();
        }
        assert_eq!(credit.finish().unwrap(), expected);
    }

    #[test]
    fn final_number_and_tiny_credit_use_authoritative_numeric_size() {
        let value = json!(1e20);
        let expected = canonical::canonical_json(&value).unwrap().len();
        assert_eq!(expected, 21);
        let mut admitted = CanonicalCounter::new(expected);
        serde_json::to_writer(&mut admitted, &value).unwrap();
        admitted.flush().unwrap();
        assert_eq!(admitted.finish().unwrap(), expected);

        let mut refused = CanonicalCounter::new(expected - 1);
        serde_json::to_writer(&mut refused, &value).unwrap();
        assert!(refused.finish().is_err());
        let mut exhausted = CanonicalCounter::new(usize::MAX);
        assert!(exhausted.write_all(&[b'1'; 65]).is_err());
    }
}
