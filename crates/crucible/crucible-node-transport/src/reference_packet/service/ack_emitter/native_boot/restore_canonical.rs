//! Counts bounded native restoration data before constructing canonical banks.
//!
//! The caller separately precharges its typed/DOM, UTF16 sorting and bank phases
//! under the selected Source admission. These extent checks grant no allocation,
//! restoration or whole-memory authority; every original owner stays outside.

use crate::ProviderError;
use crucible_node_format::{ContractError, canonical};
use serde::Serialize;
use std::io::{self, Write};

pub(super) fn bounded_canonical(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    // This capped serde pass allocates no DOM or output bank. The separately
    // admitted DOM is built only after this first finite extent check succeeds.
    crate::connection::serialized_credit(value, maximum)?;
    let value = serde_json::to_value(value).map_err(ContractError::from)?;
    let mut count = BoundedWriter {
        output: None,
        used: 0,
        maximum,
    };
    canonical::canonical_json_to_writer(&value, &mut count)?;
    let extent = count.used;

    let mut output = Vec::new();
    output.try_reserve_exact(extent).map_err(|_| exhausted())?;
    if output.capacity() != extent {
        return Err(exhausted());
    }
    let written = {
        let mut writer = BoundedWriter {
            output: Some(&mut output),
            used: 0,
            maximum: extent,
        };
        canonical::canonical_json_to_writer(&value, &mut writer)?;
        writer.used
    };
    if written != extent {
        return Err(exhausted());
    }
    if output.len() != extent {
        return Err(exhausted());
    }
    Ok(output)
}

struct BoundedWriter<'a> {
    output: Option<&'a mut Vec<u8>>,
    used: usize,
    maximum: usize,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .used
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::other("native canonical extent exceeds reservation"))?;
        if let Some(output) = self.output.as_mut() {
            // A changed count cannot trigger Vec growth or append partial data.
            if output.len() != self.used || next > output.capacity() {
                return Err(io::Error::other("native canonical bank differs"));
            }
            output.extend_from_slice(bytes);
        }
        self.used = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native bounded canonical bank")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Finite encoder controls intentionally panic on failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn canonical_bank_exact_limit_and_one_short_preserve_actual_encoding() {
        let value = serde_json::json!({"z":"\u{0001}\"\\", "a":["18446744073709551615"]});
        let expected = canonical::canonical_json(&value).unwrap();
        let actual = bounded_canonical(&value, expected.len()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.capacity(), expected.len());
        assert!(bounded_canonical(&value, expected.len() - 1).is_err());
    }

    #[test]
    fn raw_extent_refusal_precedes_owned_value_construction() {
        struct Probe<'a>(&'a Cell<usize>);
        impl Serialize for Probe<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.set(self.0.get() + 1);
                "bounded-native-value".serialize(serializer)
            }
        }
        let calls = Cell::new(0);
        assert!(bounded_canonical(&Probe(&calls), 1).is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn bounded_writer_rejects_growth_before_changing_the_same_bank() {
        let mut output = Vec::with_capacity(3);
        {
            let mut writer = BoundedWriter {
                output: Some(&mut output),
                used: 0,
                maximum: 3,
            };
            writer.write_all(b"ab").unwrap();
            assert!(writer.write_all(b"cd").is_err());
            assert_eq!(writer.used, 2);
        }
        assert_eq!(output, b"ab");
    }
}
