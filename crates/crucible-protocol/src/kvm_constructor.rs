//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Distinct source-correlated KVM selection before accelerator birth.
//!
//! These immutable public bytes select finite constructor and requested
//! quantized policies. Parsing does not authenticate native ownership, satisfy
//! the requested clock/window/stop/output contract, or issue source Ready.
//! Native issuers must retain the original descriptors, process incarnation and
//! actual kernel/QEMU objects; unsupported execution remains closed.
//!
//! ```text
//! Header512: CRKVM001, BE version1/header512/full extent/backend2/ISA1/SMP4,
//! scope/digests, RAM/assets/seed/RTC, complete argv geometry, finite policies.
//! Capability32[9], Asset64[4], machine/CPU/cmdline, length-prefixed argv.
//! Ready uses backend kind3; SIM Launch2 and TCG registration are separate.
//! ```

use sha2::{Digest, Sha256};

use crate::whole_control::WholeControlError;

/// Bounds the complete sealed KVM prebirth descriptor.
pub const KVM_PREBIRTH_MAX_BYTES: usize = 65_536;
/// Counts every fixed public prebirth header byte.
pub const KVM_PREBIRTH_HEADER_BYTES: usize = 512;

const CAPABILITY_BYTES: usize = 9 * 32;
const ASSET_BYTES: usize = 4 * 64;
const FIXED_BYTES: usize = KVM_PREBIRTH_HEADER_BYTES + CAPABILITY_BYTES + ASSET_BYTES;
const CAPABILITIES: [(u32, u64, u64, u64); 9] = [
    (0xa033, 64, 128, 4),
    (0xa034, 1, 0, 1),
    (0xa035, 4, 576, 4),
    (0xa036, 256, 0, 128),
    (0xa037, 64, 0, 0),
    (0xa038, 16, 0, 16),
    (0xa039, 1, 0, 38),
    (0xa040, 256, 104, 0),
    (0xa041, 4096, 80, 1),
];

/// Correlates one original fully sealed image without conveying close custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KvmConstructorAsset {
    /// Distinguishes an original descriptor from explicitly absent input.
    pub present: bool,
    /// Names the inherited original FD, or UINT32_MAX when absent.
    pub inherited_fd: u32,
    /// Counts the complete source image bytes, not its descriptor metadata.
    pub byte_length: u64,
    /// Commits every original image byte using SHA-256.
    pub sha256: [u8; 32],
}

/// Borrows a completely validated immutable KVM prebirth descriptor.
///
/// Capability numbers and digest equality are correlations. The source must
/// independently check actual implementations, constructor objects and finite
/// allocation geometry before effects. Inactive Kernel41 observation is not
/// the requested active quantized clock contract.
pub struct KvmPrebirthSelection<'a> {
    body: &'a [u8],
    /// Borrows the exact requested canonical machine name.
    pub machine: &'a str,
    /// Borrows the full original CPU argument, including disabled features.
    pub cpu_argument: &'a str,
    /// Borrows every original kernel command-line byte.
    pub command_line: &'a str,
    /// Borrows the complete length-prefixed original argument inventory.
    pub argv: KvmConstructorArgv<'a>,
    /// Retains kernel, initrd, effective firmware and entropy correlations.
    pub assets: [KvmConstructorAsset; 4],
}

impl<'a> KvmPrebirthSelection<'a> {
    /// Checks the complete selected descriptor without allocation or effects.
    ///
    /// # Errors
    /// Rejects unsupported editions, malformed extents, reserved fields,
    /// changed commitments, invalid canonical geometry or nonfinite budgets.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if !(FIXED_BYTES..=KVM_PREBIRTH_MAX_BYTES).contains(&body.len())
            || body[..8] != *b"CRKVM001"
            || u32_at(body, 8)? != 1
            || u32_at(body, 12)? != KVM_PREBIRTH_HEADER_BYTES as u32
            || u32_at(body, 16)? as usize != body.len()
            || u32_at(body, 20)? != 2
            || u32_at(body, 24)? != 1
            || u32_at(body, 28)? != 4
            || body[488..512] != [0; 24]
        {
            return Err(WholeControlError::Body);
        }
        for offset in [32, 64, 96, 128, 160] {
            if body[offset..offset + 32] == [0; 32] {
                return Err(WholeControlError::Body);
            }
        }
        validate_geometry(body)?;
        validate_capabilities(body)?;

        let mut assets = [KvmConstructorAsset {
            present: false,
            inherited_fd: u32::MAX,
            byte_length: 0,
            sha256: [0; 32],
        }; 4];
        let mut retained_extent = u64_at(body, 256)?;
        for (index, asset) in assets.iter_mut().enumerate() {
            let offset = KVM_PREBIRTH_HEADER_BYTES + CAPABILITY_BYTES + index * 64;
            let row = &body[offset..offset + 64];
            let role = u16::from_be_bytes([row[0], row[1]]);
            let presence = u16::from_be_bytes([row[2], row[3]]);
            let fd = u32_at(row, 4)?;
            let length = u64_at(row, 8)?;
            let digest = array32(row, 16)?;
            if role != index as u16 + 1
                || presence > 1
                || row[48..64] != [0; 16]
                || (presence == 0 && (fd != u32::MAX || length != 0 || digest != [0; 32]))
                || (presence == 1 && (fd != 10 + index as u32 || length == 0 || digest == [0; 32]))
            {
                return Err(WholeControlError::Body);
            }
            *asset = KvmConstructorAsset {
                present: presence == 1,
                inherited_fd: fd,
                byte_length: length,
                sha256: digest,
            };
            retained_extent = retained_extent
                .checked_add(length)
                .ok_or(WholeControlError::Budget)?;
        }
        if !assets[0].present
            || !assets[2].present
            || !assets[3].present
            || assets[3].byte_length != 32
        {
            return Err(WholeControlError::Body);
        }
        retained_extent
            .checked_add(u64_at(body, 416)?)
            .and_then(|extent| extent.checked_add(u64_at(body, 424).ok()?))
            .ok_or(WholeControlError::Budget)?;

        let lengths = [
            u32_at(body, 316)?,
            u32_at(body, 320)?,
            u32_at(body, 324)?,
            u32_at(body, 328)?,
        ];
        if lengths[0] > 128 || lengths[1] > 128 || lengths[2] > 3072 {
            return Err(WholeControlError::Body);
        }
        let mut cursor = FIXED_BYTES;
        let mut strings = [""; 3];
        for (string, length) in strings.iter_mut().zip(lengths) {
            let end = cursor
                .checked_add(length as usize)
                .ok_or(WholeControlError::Body)?;
            let bytes = body.get(cursor..end).ok_or(WholeControlError::Body)?;
            *string = std::str::from_utf8(bytes).map_err(|_| WholeControlError::Body)?;
            if bytes.contains(&0) {
                return Err(WholeControlError::Body);
            }
            cursor = end;
        }
        if strings[0] != "pc-q35-9.2"
            || strings[1] != "qemu64,-rdrand,-rdseed"
            || Sha256::digest(strings[2].as_bytes()).as_slice() != &body[224..256]
        {
            return Err(WholeControlError::Body);
        }
        let argv_bytes = body.get(cursor..).ok_or(WholeControlError::Body)?;
        if argv_bytes.len() != lengths[3] as usize
            || Sha256::digest(argv_bytes).as_slice() != &body[192..224]
        {
            return Err(WholeControlError::Body);
        }
        let argv = KvmConstructorArgv::decode(argv_bytes, u32_at(body, 332)?)?;
        Ok(Self {
            body,
            machine: strings[0],
            cpu_argument: strings[1],
            command_line: strings[2],
            argv,
            assets,
        })
    }

    /// Borrows every immutable original descriptor byte.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Computes the descriptor's distinct public SHA-256 domain commitment.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"CRUCIBLE-KVM-PREBIRTH-V1\0");
        hash.update(self.body);
        hash.finalize().into()
    }

    /// Borrows the selected opaque backend profile digest.
    pub fn profile_digest(&self) -> &[u8] {
        &self.body[64..96]
    }
}

/// Borrows a completely checked original length-prefixed argument inventory.
#[derive(Clone, Copy)]
pub struct KvmConstructorArgv<'a> {
    body: &'a [u8],
    count: u32,
}

impl<'a> KvmConstructorArgv<'a> {
    fn decode(body: &'a [u8], count: u32) -> Result<Self, WholeControlError> {
        if !(1..=256).contains(&count) {
            return Err(WholeControlError::Body);
        }
        let mut cursor = 0usize;
        for _ in 0..count {
            let length = u32_at(body, cursor)? as usize;
            cursor = cursor.checked_add(4).ok_or(WholeControlError::Body)?;
            let end = cursor.checked_add(length).ok_or(WholeControlError::Body)?;
            let bytes = body.get(cursor..end).ok_or(WholeControlError::Body)?;
            if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
                return Err(WholeControlError::Body);
            }
            cursor = end;
        }
        if cursor != body.len() {
            return Err(WholeControlError::Body);
        }
        Ok(Self { body, count })
    }

    /// Borrows the complete original length-prefixed argument bytes.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Counts the original arguments without truncation or coalescing.
    pub const fn len(&self) -> u32 {
        self.count
    }

    /// Reports whether the original inventory contains no arguments.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

fn validate_geometry(body: &[u8]) -> Result<(), WholeControlError> {
    let ram_length = u64_at(body, 256)?;
    let ram_offset = u64_at(body, 272)?;
    let ram_kind = u32_at(body, 280)?;
    let ram_fd = u32_at(body, 284)?;
    if ram_length == 0
        || !ram_length.is_multiple_of(4096)
        || u64_at(body, 264)? != 0
        || !ram_offset.is_multiple_of(4096)
        || ram_offset.checked_add(ram_length).is_none()
        || !matches!(
            (ram_kind, ram_fd, ram_offset),
            (1, 14..=1024, _) | (2, u32::MAX, 0)
        )
        || u64_at(body, 296)? != 1_767_225_600
        || !(1..=5000).contains(&u32_at(body, 304)?)
        || u32_at(body, 308)? != 9
        || u32_at(body, 312)? != 4
        || u32_at(body, 352)? != 1
        || u32_at(body, 356)? != 1
        || u32_at(body, 360)? != 1
        || u32_at(body, 364)? != 1
        || !(1..=65_536).contains(&u64_at(body, 368)?)
        || !(8..=65_536).contains(&u64_at(body, 376)?)
        || u64_at(body, 336)? == 0
        || u64_at(body, 344)? >= u64_at(body, 336)?
        || u64_at(body, 344)?.checked_add(u64_at(body, 336)?).is_none()
        || u64_at(body, 472)? != 1_048_576
        || u32_at(body, 480)? != 2
        || u32_at(body, 484)? != 24
    {
        return Err(WholeControlError::Body);
    }
    for offset in [400, 408, 416, 424, 432, 440, 448, 456, 464] {
        if u64_at(body, offset)? == 0 {
            return Err(WholeControlError::Budget);
        }
    }
    let output_capacity = u64_at(body, 368)?
        .checked_mul(u64_at(body, 376)?)
        .ok_or(WholeControlError::Budget)?;
    let aggregate_bytes = u64_at(body, 384)?;
    let aggregate_records = u64_at(body, 392)?;
    if aggregate_bytes == 0
        || aggregate_records == 0
        || aggregate_bytes > output_capacity
        || aggregate_records > aggregate_bytes
    {
        return Err(WholeControlError::Budget);
    }

    // This portable floor retains every selected full output body, the fixed
    // Ready344/two ACK128/three header24 exchange, and the complete descriptor.
    // Actual source admission additionally accounts its private typed inputs,
    // allocator geometry, actor banks and callback/kernel metadata.
    let wire_floor = output_capacity
        .checked_add(344 + 2 * 128 + 3 * 24)
        .and_then(|extent| extent.checked_add(body.len() as u64))
        .ok_or(WholeControlError::Budget)?;
    if u64_at(body, 416)? < wire_floor || u64_at(body, 424)? < wire_floor {
        return Err(WholeControlError::Budget);
    }
    Ok(())
}

fn validate_capabilities(body: &[u8]) -> Result<(), WholeControlError> {
    for (index, (id, maximum, envelope, cardinality)) in CAPABILITIES.into_iter().enumerate() {
        let offset = KVM_PREBIRTH_HEADER_BYTES + index * 32;
        let operations = u64_at(body, offset + 8)?;
        if u32_at(body, offset)? != id
            || u32_at(body, offset + 4)? != 2
            || (index == 0 && !(1..=maximum).contains(&operations))
            || (index != 0 && operations != maximum)
            || u64_at(body, offset + 16)? != envelope
            || u64_at(body, offset + 24)? != cardinality
        {
            return Err(WholeControlError::Body);
        }
    }
    Ok(())
}

fn u32_at(body: &[u8], offset: usize) -> Result<u32, WholeControlError> {
    let end = offset.checked_add(4).ok_or(WholeControlError::Body)?;
    let bytes = body.get(offset..end).ok_or(WholeControlError::Body)?;
    let bytes = <[u8; 4]>::try_from(bytes).map_err(|_| WholeControlError::Body)?;
    Ok(u32::from_be_bytes(bytes))
}

fn u64_at(body: &[u8], offset: usize) -> Result<u64, WholeControlError> {
    let end = offset.checked_add(8).ok_or(WholeControlError::Body)?;
    let bytes = body.get(offset..end).ok_or(WholeControlError::Body)?;
    let bytes = <[u8; 8]>::try_from(bytes).map_err(|_| WholeControlError::Body)?;
    Ok(u64::from_be_bytes(bytes))
}

fn array32(body: &[u8], offset: usize) -> Result<[u8; 32], WholeControlError> {
    let end = offset.checked_add(32).ok_or(WholeControlError::Body)?;
    <[u8; 32]>::try_from(body.get(offset..end).ok_or(WholeControlError::Body)?)
        .map_err(|_| WholeControlError::Body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // crucible-lint: allow panic-shortcut -- Codec controls fail on malformed public bytes.
    #[allow(clippy::unwrap_used)]
    #[test]
    fn complete_constructor_fixture_is_borrowed_and_backend_domain_is_distinct() {
        let body = include_bytes!("kvm_constructor/testdata/prebirth-v1.bin");
        let selection = KvmPrebirthSelection::decode(body).unwrap();

        assert_eq!(selection.body().as_ptr(), body.as_ptr());
        assert_eq!(selection.machine, "pc-q35-9.2");
        assert_eq!(selection.cpu_argument, "qemu64,-rdrand,-rdseed");
        assert_eq!(selection.argv.len(), 13);
        assert!(!selection.argv.is_empty());
        assert_eq!(selection.assets[3].byte_length, 32);
        assert_ne!(selection.digest(), <[u8; 32]>::from(Sha256::digest(body)));
    }

    #[test]
    fn partial_trailing_cross_backend_and_changed_control_shapes_are_refused() {
        let original = include_bytes!("kvm_constructor/testdata/prebirth-v1.bin");
        for length in 0..original.len() {
            assert!(KvmPrebirthSelection::decode(&original[..length]).is_err());
        }
        for offset in [
            8, 12, 16, 20, 24, 28, 280, 284, 304, 308, 312, 352, 356, 360, 364, 472, 480, 484, 488,
            512, 516, 528, 800, 848,
        ] {
            let mut changed = original.to_vec();
            changed[offset] ^= 1;
            assert!(
                KvmPrebirthSelection::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut changed = original.to_vec();
        changed.extend_from_slice(&[0]);
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
        for offset in [192, 224] {
            let mut changed = original.to_vec();
            changed[offset] ^= 1;
            assert!(KvmPrebirthSelection::decode(&changed).is_err());
        }
    }

    #[test]
    fn finite_budgets_grid_and_asset_extents_are_checked_before_exposure() {
        let original = include_bytes!("kvm_constructor/testdata/prebirth-v1.bin");
        for offset in [
            256, 336, 368, 376, 384, 392, 400, 408, 416, 424, 432, 440, 448, 456, 464,
        ] {
            let mut changed = original.to_vec();
            changed[offset..offset + 8].fill(0);
            assert!(
                KvmPrebirthSelection::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut changed = original.to_vec();
        changed[256..264].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
        let mut changed = original.to_vec();
        changed[344..352].copy_from_slice(&1_000_000u64.to_be_bytes());
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
        let mut changed = original.to_vec();
        changed[512 + 8..512 + 16].copy_from_slice(&65u64.to_be_bytes());
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
    }

    #[test]
    fn aggregate_publication_and_complete_retained_history_refuse_overflow_or_shortage() {
        let original = include_bytes!("kvm_constructor/testdata/prebirth-v1.bin");
        for offset in [384, 392] {
            let mut changed = original.to_vec();
            changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            assert!(KvmPrebirthSelection::decode(&changed).is_err());
        }
        let output_capacity = 16 * 65_536u64;
        let floor = output_capacity + 344 + 2 * 128 + 3 * 24 + original.len() as u64;
        for offset in [416, 424] {
            let mut changed = original.to_vec();
            changed[offset..offset + 8].copy_from_slice(&(floor - 1).to_be_bytes());
            assert!(KvmPrebirthSelection::decode(&changed).is_err());
            changed[offset..offset + 8].copy_from_slice(&floor.to_be_bytes());
            assert!(KvmPrebirthSelection::decode(&changed).is_ok());
        }
        let mut changed = original.to_vec();
        changed[424..432].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
    }

    #[test]
    fn argument_overflow_nul_and_unknown_editions_remain_shape_errors() {
        let original = include_bytes!("kvm_constructor/testdata/prebirth-v1.bin");
        let mut changed = original.to_vec();
        let argv_start = changed.len() - u32_at(&changed, 328).unwrap_or_default() as usize;
        changed[argv_start..argv_start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let digest = Sha256::digest(&changed[argv_start..]);
        changed[192..224].copy_from_slice(&digest);
        assert!(KvmPrebirthSelection::decode(&changed).is_err());

        let mut changed = original.to_vec();
        changed[argv_start + 4] = 0;
        let digest = Sha256::digest(&changed[argv_start..]);
        changed[192..224].copy_from_slice(&digest);
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
        let mut changed = original.to_vec();
        changed[512 + 4..512 + 8].copy_from_slice(&3u32.to_be_bytes());
        assert!(KvmPrebirthSelection::decode(&changed).is_err());
    }
}
