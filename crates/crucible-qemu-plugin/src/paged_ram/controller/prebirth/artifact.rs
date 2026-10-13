//! Emits configured installer request geometry as immutable artifact data.
//!
//! The package extractor reads this section without loading the plugin. Its
//! numeric fields describe requested allocations, not allocator backing or an
//! issued purpose. Final artifact and compiler/configuration binding belongs to
//! the external build producer; no self-hash is placed inside the image. The
//! final-output transform fills the zero machine placeholder from that same
//! ELF before validating and hashing the final record. Zero is never an
//! installable record or an inferred target identity.
//!
//! ```text
//! .qemu.crucible.control = "CRUCCTL1" || BE32(1, 248, ELF machine, 7)
//!   || seven { BE32(kind, reserved=0) || BE64(size, alignment, count=1) }
//! ```
// SPDX-License-Identifier: GPL-2.0-only

use super::{InstallerControlAllocationKind, configured_control_layouts};

const RECORD_BYTES: usize = 248;

// The one final-output transform stamps this placeholder with the numeric
// e_machine from the same final ELF before hashing and sidecar publication.
// Ordinary extraction and native loading refuse an unstamped zero field.
const UNFINALIZED_ELF_MACHINE: u32 = 0;

/// Contains the configured numeric request record for build-time extraction.
// SAFETY: the globally unique exported symbol roots this immutable byte section
// in the cdylib export set, including links that discard unreferenced sections.
// The record has no relocations, addresses, callbacks or initialization hook;
// consumers inspect the final ELF rather than linking or loading this symbol.
#[used]
#[unsafe(export_name = "crucible_installer_layout_requests_v1")]
#[unsafe(link_section = ".qemu.crucible.control")]
pub static INSTALLER_LAYOUT_REQUESTS: [u8; RECORD_BYTES] = encoded_requests();

const fn encoded_requests() -> [u8; RECORD_BYTES] {
    let mut record = [0; RECORD_BYTES];
    let Some(layouts) = configured_control_layouts() else {
        return record;
    };
    if usize::BITS > 64 {
        return record;
    }

    let magic = *b"CRUCCTL1";
    let mut index = 0;
    while index < magic.len() {
        record[index] = magic[index];
        index += 1;
    }
    write_u32(&mut record, 8, 1);
    write_u32(&mut record, 12, RECORD_BYTES as u32);
    write_u32(&mut record, 16, UNFINALIZED_ELF_MACHINE);
    write_u32(&mut record, 20, 7);
    index = 0;
    while index < layouts.len() {
        let offset = 24 + index * 32;
        write_u32(
            &mut record,
            offset,
            kind_code(super::ALLOCATION_KINDS[index]),
        );
        write_u64(&mut record, offset + 8, layouts[index].size() as u64);
        write_u64(&mut record, offset + 16, layouts[index].align() as u64);
        write_u64(&mut record, offset + 24, 1);
        index += 1;
    }
    record
}

const fn kind_code(kind: InstallerControlAllocationKind) -> u32 {
    match kind {
        InstallerControlAllocationKind::Controller => 1,
        InstallerControlAllocationKind::ControllerState => 2,
        InstallerControlAllocationKind::Cancellation => 3,
        InstallerControlAllocationKind::OperationRegistry => 4,
        InstallerControlAllocationKind::PagerOwner => 5,
        InstallerControlAllocationKind::PagingCounters => 6,
        InstallerControlAllocationKind::ActiveServiceSlot => 7,
    }
}

const fn write_u32(record: &mut [u8; RECORD_BYTES], offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    let mut index = 0;
    while index < bytes.len() {
        record[offset + index] = bytes[index];
        index += 1;
    }
}

const fn write_u64(record: &mut [u8; RECORD_BYTES], offset: usize, value: u64) {
    let bytes = value.to_be_bytes();
    let mut index = 0;
    while index < bytes.len() {
        record[offset + index] = bytes[index];
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinalized_numeric_record_matches_the_same_nominal_requests() {
        let nominal = super::super::required_control_requests().unwrap();
        let record = &INSTALLER_LAYOUT_REQUESTS;

        assert_eq!(record.len(), 248);
        assert_eq!(&record[..8], b"CRUCCTL1");
        assert_eq!(&record[8..12], &1_u32.to_be_bytes());
        assert_eq!(&record[12..16], &248_u32.to_be_bytes());
        // The build transform must fill this field before installed artifact
        // acceptance. This test proves configured geometry, not finalization.
        assert_eq!(&record[16..20], &[0; 4]);
        assert_eq!(&record[20..24], &7_u32.to_be_bytes());
        for (index, request) in nominal.allocations().iter().enumerate() {
            let offset = 24 + index * 32;
            assert_eq!(
                u32::from_be_bytes(record[offset..offset + 4].try_into().unwrap()),
                kind_code(request.kind())
            );
            assert_eq!(&record[offset + 4..offset + 8], &[0; 4]);
            assert_eq!(
                u64::from_be_bytes(record[offset + 8..offset + 16].try_into().unwrap()),
                request.size()
            );
            assert_eq!(
                u64::from_be_bytes(record[offset + 16..offset + 24].try_into().unwrap()),
                request.alignment()
            );
            assert_eq!(
                u64::from_be_bytes(record[offset + 24..offset + 32].try_into().unwrap()),
                request.count()
            );
        }
        assert_eq!(
            nominal.required_bytes().unwrap(),
            nominal
                .allocations()
                .iter()
                .map(|request| request.size())
                .sum::<u64>()
        );
    }
}
