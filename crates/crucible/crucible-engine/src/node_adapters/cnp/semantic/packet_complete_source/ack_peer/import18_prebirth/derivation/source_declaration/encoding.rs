//! Encodes the genuine borrowed declaration into its caller-retained raw bank.
//!
//! The original worker's SourceBirth bytes remain opaque. The temporary Value
//! belongs only to the new three-field declaration; no response DOM or live
//! Source is reconstructed. Every failed output allocation and partial write
//! remains in the caller's original output slot.

use super::*;
use crucible_node_format::canonical::canonical_json_to_writer;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    native_import18_source_declaration_encoding_construction_data,
    native_import18_source_declaration_encoding_counter_scratch_data,
};
use std::io::Write;
use std::mem::align_of;

impl PacketCompleteSemanticSource {
    /// Names the original loan and allocation-free encoding quote workspace.
    ///
    /// Callers admit this row before quoting the genuine borrowed bank. The
    /// resulting encoding row independently covers its actual output and work.
    pub fn native_import18_declaration_encoding_quote_construction_data() -> [usize; 3] {
        let [_, transient, scratch] = Self::native_import18_source_declaration_construction_data();
        [
            0,
            transient,
            scratch
                + native_import18_source_declaration_encoding_counter_scratch_data()
                + size_of::<[usize; 3]>() * 2
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<usize>(),
        ]
    }

    /// Quotes canonical encoding of this same genuine original declaration.
    ///
    /// The retained axis covers the new raw bank only. The original Source,
    /// Birth, worker result and caller's inline output slot remain separately
    /// retained. The row is DATA and grants no Initial, Recipe or native startup.
    ///
    /// # Errors
    /// Refuses original custody loss, conflicting loans, projection overflow or
    /// a complete encoding construction above the independent restriction.
    pub fn native_import18_declaration_encoding_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let row = encoding_row(&loan, maximum);
        let current = loan.authenticate();
        row.and_then(|row| current.map(|()| row))
    }

    /// Writes the canonical declaration once into a retained output slot.
    ///
    /// Callers admit the complete defining encoding row before entry. An
    /// occupied output refuses without alteration. Once installed, the slot
    /// retains empty, overcapacity and partially written allocations on error.
    /// This method issues serialized DATA only and creates no native member.
    ///
    /// # Errors
    /// Refuses occupied output, original custody loss, allocation or encoding
    /// failure, a changed executable or a bank above the admitted restriction.
    pub fn encode_native_import18_source_declaration_into_data(
        &self,
        maximum: usize,
        output: &mut Option<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let loan = self.original_source_declaration_loan()?;
        let row = encoding_row(&loan, maximum)?;
        *output = Some(Vec::new());
        let bank = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let encoded = (|| {
            bank.try_reserve_exact(row[0])
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if bank.capacity() != row[0] {
                return Err(RuntimeError::ResourceLimit);
            }
            let value = serde_json::to_value(&loan).map_err(|_| RuntimeError::ResourceLimit)?;
            canonical_json_to_writer(&value, &mut BankWriter { bank })
                .map_err(|_| RuntimeError::ResourceLimit)
        })();
        // A canonical writer failure still receives the terminal original
        // measurement. Preserve the first failure and all output bytes.
        let current = loan.authenticate();
        encoded.and(current)
    }
}

fn encoding_row(
    loan: &OriginalSourceDeclarationLoan<'_>,
    maximum: usize,
) -> Result<[usize; 3], RuntimeError> {
    let mut row =
        native_import18_source_declaration_encoding_construction_data(&loan.declaration, maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
    let [_, loan_transient, quote_scratch] =
        PacketCompleteSemanticSource::native_import18_declaration_encoding_quote_construction_data(
        );
    row[1] = row[1]
        .checked_add(loan_transient)
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<Option<Vec<u8>>>()))
        .and_then(|bytes| bytes.checked_add(serializer_refusal_storage()))
        .ok_or(RuntimeError::ResourceLimit)?;
    row[2] = row[2]
        .checked_add(quote_scratch)
        .and_then(|bytes| bytes.checked_add(encoding_controls()))
        .ok_or(RuntimeError::ResourceLimit)?;
    let peak = row.into_iter().try_fold(0usize, |total, bytes| {
        total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
    })?;
    if peak > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(row)
}

// The pinned serde_json error owns ErrorCode plus two usize coordinates.
// Message(Box<str>) and Io(io::Error) are its only payload-bearing variants;
// a full usize tag and per-field alignment padding bound that private layout.
// These two actual guard messages are formatted into a String and then Box<str>.
fn serializer_refusal_storage() -> usize {
    let alignment = align_of::<Box<str>>()
        .max(align_of::<std::io::Error>())
        .max(align_of::<usize>());
    size_of::<Box<str>>().max(size_of::<std::io::Error>())
        + size_of::<usize>() * 3
        + (alignment - 1) * 4
        + UNAVAILABLE.len().max(CHANGED.len()) * 2
}

fn encoding_controls() -> usize {
    size_of::<&OriginalSourceDeclarationLoan<'static>>()
        + size_of::<&mut Option<Vec<u8>>>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<Option<&mut Vec<u8>>>()
        + size_of::<Result<&mut Vec<u8>, RuntimeError>>()
        + size_of::<BankWriter<'static>>()
        + size_of::<&mut BankWriter<'static>>()
        + size_of::<&serde_json::Value>()
        + size_of::<&[u8]>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<Result<(), RuntimeError>>() * 4
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<std::io::ErrorKind>()
        + size_of::<usize>() * 3
}

struct BankWriter<'a> {
    bank: &'a mut Vec<u8>,
}

impl Write for BankWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bank
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.bank.capacity())
        {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_keeps_accepted_prefix_without_reallocating_after_refusal() {
        let mut bank = Vec::with_capacity(3);
        let capacity = bank.capacity();
        let mut writer = BankWriter { bank: &mut bank };
        assert!(writer.write_all(b"ab").is_ok());
        assert!(writer.write_all(b"cd").is_err());
        assert_eq!(bank, b"ab");
        assert_eq!(bank.capacity(), capacity);
    }
}
