//! Decodes one compiled userfaultfd aggregate request without lending resources.
//!
//! ```text
//! CRUCUFD1 | BE32(schema1,length64)
//! BE64(body_bytes,body_alignment,event_offset,event_bytes,event_alignment)
//! BE32(descriptor_journal_count2,reserved0)
//! ```
//!
//! The receipt is an interior of the whole body. Only the whole body is an
//! allocation request; these numerical facts cannot create a native endpoint,
//! descriptor window, metadata borrower, operation or mapping authority.
// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;

use super::NativeConstructorReadError;

pub(super) const SECTION: &[u8] = b".qemu.crucible.userfaultfd-constructor";
pub(super) const DECLARATION_BYTES: usize = 64;

/// Describes a compiler-derived whole-body request and its interior receipt.
///
/// Only the final-file reader publishes this observation. It authenticates
/// request geometry, not the descriptor table or the payer's allocation grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserfaultfdConstructorRequest {
    body: Layout,
    event_offset: usize,
    event: Layout,
    descriptor_journals: u32,
}

impl UserfaultfdConstructorRequest {
    /// Returns the whole-body layout, already including the event and pause wait.
    pub(crate) fn body_layout(&self) -> Layout {
        self.body
    }

    /// Returns the actual compiled descriptor-journal count, not available slots.
    pub(crate) fn descriptor_journals(&self) -> u32 {
        self.descriptor_journals
    }
}

/// Decodes one whole-body request and checks its interior receipt layout.
///
/// # Errors
/// Refuses unknown editions, journal counts or reserved fields, zero or
/// unrepresentable layouts, invalid alignments and an interior outside the body.
pub(super) fn decode_declaration(
    bytes: &[u8; DECLARATION_BYTES],
) -> Result<UserfaultfdConstructorRequest, NativeConstructorReadError> {
    if bytes[..8] != *b"CRUCUFD1"
        || word(bytes, 8) != 1
        || word(bytes, 12) != DECLARATION_BYTES as u32
        || word(bytes, 56) != 2
        || word(bytes, 60) != 0
    {
        return Err(NativeConstructorReadError::Invalid(
            "userfaultfd declaration edition or journals",
        ));
    }
    let body = layout(bytes, 16, 24)?;
    let event_offset = usize::try_from(wide(bytes, 32))
        .map_err(|_| NativeConstructorReadError::Invalid("userfaultfd interior offset"))?;
    let event = layout(bytes, 40, 48)?;
    if event.align() > body.align()
        || !event_offset.is_multiple_of(event.align())
        || event_offset
            .checked_add(event.size())
            .is_none_or(|end| end > body.size())
    {
        return Err(NativeConstructorReadError::Invalid(
            "userfaultfd receipt outside whole body",
        ));
    }

    Ok(UserfaultfdConstructorRequest {
        body,
        event_offset,
        event,
        descriptor_journals: word(bytes, 56),
    })
}

fn layout(
    bytes: &[u8; DECLARATION_BYTES],
    size_offset: usize,
    alignment_offset: usize,
) -> Result<Layout, NativeConstructorReadError> {
    let size = usize::try_from(wide(bytes, size_offset))
        .map_err(|_| NativeConstructorReadError::Invalid("userfaultfd request size"))?;
    let alignment = usize::try_from(wide(bytes, alignment_offset))
        .map_err(|_| NativeConstructorReadError::Invalid("userfaultfd request alignment"))?;
    if size == 0 || !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        return Err(NativeConstructorReadError::Invalid(
            "userfaultfd compiled layout",
        ));
    }
    Layout::from_size_align(size, alignment)
        .map_err(|_| NativeConstructorReadError::Invalid("userfaultfd unrepresentable layout"))
}

fn word(bytes: &[u8; DECLARATION_BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(value)
}

fn wide(bytes: &[u8; DECLARATION_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> [u8; DECLARATION_BYTES] {
        let mut bytes = [0; DECLARATION_BYTES];
        bytes[..8].copy_from_slice(b"CRUCUFD1");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&64_u32.to_be_bytes());
        for (offset, value) in [(16, 512_u64), (24, 64), (32, 128), (40, 128), (48, 8)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[56..60].copy_from_slice(&2_u32.to_be_bytes());
        bytes
    }

    #[test]
    fn interior_receipt_is_descriptive_and_not_another_allocation() {
        // These byte fixtures test format arithmetic, not native compiled sizes.
        let result = decode_declaration(&declaration());
        assert!(result.is_ok());
        let Ok(request) = result else { return };

        assert_eq!(request.body_layout().size(), 512);
        assert_eq!(request.body_layout().align(), 64);
        assert_eq!(request.descriptor_journals(), 2);
        assert_eq!(request.event_offset, 128);
        assert_eq!(request.event.size(), 128);
    }

    #[test]
    fn bad_editions_journal_counts_reserved_fields_and_layouts_refuse() {
        for (offset, value) in [
            (8, 0_u32),
            (8, 2),
            (12, 63),
            (56, 0),
            (56, 1),
            (56, 3),
            (60, 1),
        ] {
            let mut bytes = declaration();
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(decode_declaration(&bytes).is_err());
        }
        for (offset, value) in [
            (16, 0_u64),
            (16, 513),
            (16, u64::MAX),
            (24, 0),
            (24, 3),
            (24, 1_u64 << 63),
            (32, 129),
            (32, u64::MAX),
            (32, 448),
            (40, 0),
            (40, u64::MAX),
            (48, 0),
            (48, 3),
            (48, 256),
        ] {
            let mut bytes = declaration();
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(decode_declaration(&bytes).is_err());
        }
        let mut bytes = declaration();
        bytes[0] ^= 1;
        assert!(decode_declaration(&bytes).is_err());
    }
}
