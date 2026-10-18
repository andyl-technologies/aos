//! Counts canonical CBOR before admitting its exact prefixed output allocation.

use std::io::{self, Write};

use serde::Serialize;

/// A bounded canonical encoder's static failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CborEncodeError {
    /// The serializer or its second-pass length did not match the counted form.
    #[error("malformed canonical CBOR encoding")]
    Malformed,
    /// The actual encoded extent exceeds its unchanged format limit.
    #[error("canonical CBOR encoding exceeds its format limit")]
    Limit,
    /// The same original refused the output before its allocation.
    #[error("original canonical CBOR output admission refused")]
    Admission,
    /// Fallible output allocation failed after admission.
    #[error("canonical CBOR output allocation failed")]
    Allocation,
}

struct Counter {
    bytes: usize,
    maximum: usize,
    exceeded: bool,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.maximum)
        else {
            self.exceeded = true;
            return Err(io::ErrorKind::InvalidData.into());
        };
        self.bytes = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Reserved<'a> {
    bytes: &'a mut Vec<u8>,
    total: usize,
}

impl Write for Reserved<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.total.saturating_sub(self.bytes.len()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encodes one prefixed canonical CBOR value after admitting its counted extent.
///
/// The maximum bounds the payload, independently of original resource credit.
/// The second pass writes only into the exact reservation. Nested serializers
/// must separately admit any private allocations they perform.
///
/// # Errors
/// Returns a malformed or changed encoding, format overflow, actual original
/// refusal before allocation, or a fallible allocation failure.
pub fn to_cbor_vec_prefixed<T: Serialize>(
    value: &T,
    prefix: &[u8],
    maximum_payload: usize,
) -> Result<Vec<u8>, CborEncodeError> {
    let mut counter = Counter {
        bytes: 0,
        maximum: maximum_payload,
        exceeded: false,
    };
    if ciborium::ser::into_writer(value, &mut counter).is_err() {
        return Err(if counter.exceeded {
            CborEncodeError::Limit
        } else {
            CborEncodeError::Malformed
        });
    }
    let total = prefix
        .len()
        .checked_add(counter.bytes)
        .ok_or(CborEncodeError::Limit)?;
    super::charge_array::<u8>(total).map_err(|_| CborEncodeError::Admission)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| CborEncodeError::Allocation)?;
    bytes.extend_from_slice(prefix);
    let mut writer = Reserved {
        bytes: &mut bytes,
        total,
    };
    ciborium::ser::into_writer(value, &mut writer).map_err(|_| CborEncodeError::Malformed)?;
    if bytes.len() != total {
        return Err(CborEncodeError::Malformed);
    }
    Ok(bytes)
}
