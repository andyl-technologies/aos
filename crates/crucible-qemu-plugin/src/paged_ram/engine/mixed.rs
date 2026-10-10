//! Validates native placement authority without changing portable RAM identity.
//!
//! Resident pinned regions retain their exact logical extent. In particular,
//! their partial host pages never become registration or discard ranges.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::NativeArena;
use crate::ram_error::RamError;
use crucible_ram::RegionDescriptor;

const PAGEABLE: u64 = 1;
const PINNED: u64 = 2;
const IMMUTABLE_FILE: u64 = 4;
const HOST_READONLY: u64 = 8;
const PINNED_FILE: u64 = PINNED | IMMUTABLE_FILE;
const READONLY_FILE: u64 = PINNED_FILE | HOST_READONLY;

/// Distinguishes removable mappings from bytes held resident by native authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArenaPlacement {
    /// Owns complete private anonymous host pages eligible for fault service.
    Pageable,
    /// Owns a static resident range excluded from registration and removal.
    ResidentPinned {
        /// Prevents restoration from writing through a read-only mapping.
        readonly: bool,
    },
}

/// Checks native placement metadata against the separately authenticated owner.
///
/// # Errors
/// Returns an error for unknown flags, mismatched ownership or geometry,
/// invalid addresses, or incomplete removable host pages.
pub(super) fn validate_arena(
    arena: &NativeArena,
    descriptor: &RegionDescriptor,
    index: u32,
    generation: u64,
) -> Result<ArenaPlacement, RamError> {
    if arena.schema != 1
        || arena.region_index != index
        || generation == 0
        || arena.topology_generation != generation
        || arena.logical_length != descriptor.logical_length()
        || arena.mapping_length != arena.logical_length
        || arena.host_address == 0
        || arena.mapping_length == 0
        || arena
            .host_address
            .checked_add(arena.mapping_length)
            .and_then(|end| usize::try_from(end).ok())
            .is_none()
    {
        return Err(RamError::Invariant(
            "native RAM arena ownership or extent changed",
        ));
    }
    match arena.flags {
        PAGEABLE
            if arena.host_address.is_multiple_of(super::PAGE_BYTES as u64)
                && arena
                    .mapping_length
                    .is_multiple_of(super::PAGE_BYTES as u64) =>
        {
            Ok(ArenaPlacement::Pageable)
        }
        PINNED | PINNED_FILE => Ok(ArenaPlacement::ResidentPinned { readonly: false }),
        READONLY_FILE => Ok(ArenaPlacement::ResidentPinned { readonly: true }),
        _ => Err(RamError::Invariant(
            "native RAM arena placement authority refused",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_ram::RegionClass;

    fn arena(length: u64, flags: u64) -> (NativeArena, RegionDescriptor) {
        let descriptor =
            RegionDescriptor::new("device.firmware", RegionClass::MutableDevice, length)
                .expect("valid conservative firmware owner");
        (
            NativeArena {
                schema: 1,
                region_index: 0,
                topology_generation: 1,
                host_address: 0x10000,
                mapping_length: length,
                logical_length: length,
                flags,
            },
            descriptor,
        )
    }

    #[test]
    fn partial_unaligned_ranges_require_pinned_authority() {
        let (mut native, descriptor) = arena(4099, PINNED);
        native.host_address += 13;
        assert_eq!(
            validate_arena(&native, &descriptor, 0, 1).expect("pinned range"),
            ArenaPlacement::ResidentPinned { readonly: false }
        );

        native.flags = PAGEABLE;
        assert!(validate_arena(&native, &descriptor, 0, 1).is_err());
    }

    #[test]
    fn readonly_requires_explicit_immutable_file_authority() {
        let (mut native, descriptor) = arena(4096, PINNED | HOST_READONLY);
        assert!(validate_arena(&native, &descriptor, 0, 1).is_err());
        native.flags |= IMMUTABLE_FILE;
        assert_eq!(
            validate_arena(&native, &descriptor, 0, 1).expect("sealed read-only file"),
            ArenaPlacement::ResidentPinned { readonly: true }
        );
        assert_eq!(descriptor.class(), RegionClass::MutableDevice);
        assert_eq!(descriptor.class().coverage_mask(), 7);
    }

    #[test]
    fn unknown_or_combined_placement_flags_and_stale_extents_are_refused() {
        for flags in [
            0,
            PAGEABLE | PINNED,
            IMMUTABLE_FILE,
            PAGEABLE | IMMUTABLE_FILE,
            16,
        ] {
            let (native, descriptor) = arena(4096, flags);
            assert!(validate_arena(&native, &descriptor, 0, 1).is_err());
        }
        let (mut native, descriptor) = arena(4096, PAGEABLE);
        assert_eq!(
            validate_arena(&native, &descriptor, 0, 1).expect("full anonymous page"),
            ArenaPlacement::Pageable
        );
        assert!(validate_arena(&native, &descriptor, 0, 2).is_err());
        native.mapping_length += 4096;
        assert!(validate_arena(&native, &descriptor, 0, 1).is_err());
    }
}
