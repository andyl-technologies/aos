//! Serializes borrowed octets using the existing unpadded Bytes representation.
//!
//! ```json
//! "_wAB"
//! ```
//! This view owns no octets and offers no decoder. The caller separately admits
//! the encoder String, output, and serializer work before calling the writer.

use super::*;

struct BorrowedBytesData<'a>(&'a [u8]);

impl Serialize for BorrowedBytesData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl Bytes {
    /// Borrows octets for serialization with the existing exact Bytes encoding.
    ///
    /// Creating this view allocates nothing and does not clone a Vec into Bytes.
    /// Serialization uses the same URL-safe unpadded encoder as an owned Bytes
    /// value. The caller separately admits its temporary String and output.
    pub fn borrowed_serialization_data(bytes: &[u8]) -> impl Serialize + '_ {
        BorrowedBytesData(bytes)
    }

    /// Reports the encoder String's requested bytes for these borrowed octets.
    ///
    /// This pure extent excludes output, serializer work, allocator rounding and
    /// retained source backing. It grants no allocation or restoration right.
    ///
    /// # Errors
    /// Returns [`ContractError::Overflow`] when the encoded extent cannot fit.
    pub fn borrowed_serialization_temporary_bytes_data(
        bytes: &[u8],
    ) -> Result<usize, ContractError> {
        base64::encoded_len(bytes.len(), false).ok_or(ContractError::Overflow)
    }

    /// Names the direct borrowed view and encoder String headers.
    ///
    /// Dynamic temporary and output backing are independently admitted terms.
    pub fn borrowed_serialization_counter_scratch_data() -> usize {
        std::mem::size_of::<BorrowedBytesData<'static>>()
            + std::mem::size_of::<&[u8]>()
            + std::mem::size_of::<String>()
            + std::mem::size_of::<&str>()
            + std::mem::size_of::<Result<usize, ContractError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_octets_match_owned_bytes_at_empty_and_partial_chunk_boundaries() {
        for length in [0, 1, 2, 3, 4, 5, 6, 63, 64, 65] {
            let octets = (0..length)
                .map(|index| [0xff, 0x00, 0x01, 0xfb][index % 4])
                .collect::<Vec<_>>();
            let borrowed = Bytes::borrowed_serialization_data(&octets);
            let owned = Bytes::new(octets.clone());

            let actual = serde_json::to_vec(&borrowed).unwrap();
            let expected = serde_json::to_vec(&owned).unwrap();
            assert_eq!(actual, expected, "length {length}");
            assert_eq!(
                actual.len(),
                Bytes::borrowed_serialization_temporary_bytes_data(&octets).unwrap() + 2,
                "only the quoted base64 string is emitted"
            );
            assert_eq!(owned.as_slice(), octets);
        }
    }
}
