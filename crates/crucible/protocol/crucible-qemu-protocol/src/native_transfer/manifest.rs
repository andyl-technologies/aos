//! Borrows the complete proposed prebirth producer and immutable artifact manifest.
//!
//! ```text
//! CRUCNPM1 | schema1:u32 | total:u32 | header[240] |
//! artifacts[N][128] | producers[16][192] | exact-launch[16..16384]
//! ```
//!
//! All integers are big endian. A successful parse checks syntax and arithmetic;
//! actual compiled producer bounds, retained aliases, payment, kernel contracts
//! and launcher/recipient ownership still require their genuine owning operations.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{NativeLiabilityDisposition, NativeTransfer, read32, read64, read_identity};
use crate::runtime_artifact::RuntimeArtifactPair;
use sha2::{Digest, Sha256};

/// Bounds the complete manifest, including its largest exact launch record.
pub const NATIVE_PROFILE_MANIFEST_MAX_BYTES: usize = 23808;

/// Counts the complete ordered producer inventory in this manifest edition.
pub const NATIVE_PROFILE_PRODUCERS: usize = 16;

const HEADER_BYTES: usize = 256;
const ARTIFACT_BYTES: usize = 128;
const PRODUCER_BYTES: usize = 192;
const MAX_LAUNCH_BYTES: usize = 16384;

/// Refuses malformed complete manifest descriptions without constructing an owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid prebirth native-profile manifest")]
pub struct NativeProfileDecodeError;

/// Describes one exact immutable artifact and its selected dependency roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProfileArtifact {
    /// Gives the consecutive artifact role, from one through the active count.
    pub role: u32,
    /// Gives the exact positive file length within the signed file-offset ABI.
    pub file_len: u64,
    /// Identifies the actual retained artifact child, without authenticating it.
    pub child: [u8; 32],
    /// Digests the complete immutable artifact, including its ELF headers.
    pub sha256: [u8; 32],
    /// Names selected dependencies by their zero-based role bits.
    pub dependency_roles: u32,
    /// Digests the actual compiled ELF/profile layout.
    pub layout_sha256: [u8; 32],
}

impl NativeProfileArtifact {
    fn read(bytes: &[u8]) -> Self {
        Self {
            role: read32(bytes, 0),
            file_len: read64(bytes, 8),
            child: read_identity(bytes, 16),
            sha256: read_identity(bytes, 48),
            dependency_roles: read32(bytes, 80),
            layout_sha256: read_identity(bytes, 88),
        }
    }
}

/// Describes the finite maxima of one actual compiled producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProducerLimits {
    /// Bounds native memory use under its actual liability assignment.
    pub memory_bytes: u64,
    /// Bounds independently retained virtual address space.
    pub virtual_bytes: u64,
    /// Bounds independently retained backing quota.
    pub backing_bytes: u64,
    /// Bounds concurrent tasks created by this producer.
    pub maximum_tasks: u64,
    /// Bounds concurrent descriptors held by this producer.
    pub maximum_descriptors: u64,
    /// Bounds cumulative requested bytes, including the selected failure paths.
    pub cumulative_request_bytes: u64,
    /// Bounds a single request, never exceeding the cumulative amount.
    pub single_request_bytes: u64,
    /// Gives the producer's nonzero power-of-two alignment.
    pub alignment: u64,
}

/// Describes one producer category without proving its implementation or payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProfileProducer {
    /// Gives the fixed ordered producer category, from one through sixteen.
    pub kind: u32,
    /// Describes required or genuinely unreachable producer paths.
    pub disposition: NativeLiabilityDisposition,
    /// Gives the actual compiled producer edition; zero denotes unselected.
    pub edition: u64,
    /// Identifies the canonical producer child; zero denotes unselected.
    pub child: [u8; 32],
    /// Digests the producer implementation or immutable artifact.
    pub implementation_sha256: [u8; 32],
    /// Digests the compiled layout and enforced limits.
    pub layout_sha256: [u8; 32],
    /// Describes independent resource and checked allocation dimensions.
    pub limits: NativeProducerLimits,
    /// Names its containing transfer liability row, or zero when unselected.
    pub liability_kind: u32,
}

impl NativeProfileProducer {
    pub(super) fn read(bytes: &[u8]) -> Self {
        Self {
            kind: read32(bytes, 0),
            disposition: if read32(bytes, 4) == 1 {
                NativeLiabilityDisposition::Required
            } else {
                NativeLiabilityDisposition::Unselected
            },
            edition: read64(bytes, 8),
            child: read_identity(bytes, 16),
            implementation_sha256: read_identity(bytes, 48),
            layout_sha256: read_identity(bytes, 80),
            limits: NativeProducerLimits {
                memory_bytes: read64(bytes, 112),
                virtual_bytes: read64(bytes, 120),
                backing_bytes: read64(bytes, 128),
                maximum_tasks: read64(bytes, 136),
                maximum_descriptors: read64(bytes, 144),
                cumulative_request_bytes: read64(bytes, 152),
                single_request_bytes: read64(bytes, 160),
                alignment: read64(bytes, 168),
            },
            liability_kind: read32(bytes, 176),
        }
    }
}

/// Borrows one syntactically checked complete proposed profile manifest.
///
/// The original bytes remain borrowed, including non-UTF-8 argument/environment
/// bytes. This value creates no copies, aliases, resource holders or execution
/// permission and recognizes no accepting compiled profile edition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProfileManifest<'a> {
    bytes: &'a [u8],
    artifacts_end: usize,
    producers_end: usize,
    arguments_end: usize,
}

impl<'a> NativeProfileManifest<'a> {
    /// Borrows the exact complete bytes after bounded structural validation.
    ///
    /// # Errors
    /// Refuses unsupported framing, row counts/order, artifact identities,
    /// producer bounds, reserved bytes, launch totals, NULs and duplicate
    /// environment names. It does not authenticate the described producers.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, NativeProfileDecodeError> {
        if !(HEADER_BYTES..=NATIVE_PROFILE_MANIFEST_MAX_BYTES).contains(&bytes.len())
            || bytes[..8] != *b"CRUCNPM1"
            || read32(bytes, 8) != 1
            || read32(bytes, 12) as usize != bytes.len()
            || !(2..=32).contains(&read32(bytes, 208))
            || read32(bytes, 212) != NATIVE_PROFILE_PRODUCERS as u32
            || !(16..=MAX_LAUNCH_BYTES).contains(&(read32(bytes, 216) as usize))
            || read32(bytes, 220) != 4096
        {
            return Err(NativeProfileDecodeError);
        }
        for offset in [16, 24, 32, 40] {
            if matches!(read64(bytes, offset), 0 | u64::MAX) {
                return Err(NativeProfileDecodeError);
            }
        }
        for offset in [48, 80, 112, 144, 176, 224] {
            if read_identity(bytes, offset) == [0; 32] {
                return Err(NativeProfileDecodeError);
            }
        }

        // Counts are already small, but retain checked arithmetic at the public
        // extent boundary so later edition changes cannot make slicing wrap.
        let artifact_count = read32(bytes, 208) as usize;
        let artifacts_end = artifact_count
            .checked_mul(ARTIFACT_BYTES)
            .and_then(|size| HEADER_BYTES.checked_add(size))
            .ok_or(NativeProfileDecodeError)?;
        let producers_end = NATIVE_PROFILE_PRODUCERS
            .checked_mul(PRODUCER_BYTES)
            .and_then(|size| artifacts_end.checked_add(size))
            .ok_or(NativeProfileDecodeError)?;
        if producers_end.checked_add(read32(bytes, 216) as usize) != Some(bytes.len()) {
            return Err(NativeProfileDecodeError);
        }
        validate_artifacts(&bytes[HEADER_BYTES..artifacts_end], artifact_count)?;
        validate_producers(&bytes[artifacts_end..producers_end])?;
        let arguments_end = producers_end + validate_launch(&bytes[producers_end..])?;
        Ok(Self {
            bytes,
            artifacts_end,
            producers_end,
            arguments_end,
        })
    }

    /// Returns the complete unchanged encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Iterates exact immutable artifact descriptions in their validated role order.
    pub fn artifacts(&self) -> impl ExactSizeIterator<Item = NativeProfileArtifact> + '_ {
        let (rows, _) = self.bytes[HEADER_BYTES..self.artifacts_end].as_chunks::<ARTIFACT_BYTES>();
        rows.iter().map(|bytes| NativeProfileArtifact::read(bytes))
    }

    /// Iterates the sixteen validated producer descriptions without granting custody.
    pub fn producers(&self) -> impl ExactSizeIterator<Item = NativeProfileProducer> + '_ {
        let (rows, _) =
            self.bytes[self.artifacts_end..self.producers_end].as_chunks::<PRODUCER_BYTES>();
        rows.iter().map(|bytes| NativeProfileProducer::read(bytes))
    }

    /// Iterates the exact non-NUL argument bytes without requiring UTF-8.
    pub fn arguments(&self) -> impl Iterator<Item = &'a [u8]> {
        validated_strings(&self.bytes[self.producers_end + 16..self.arguments_end])
    }

    /// Iterates the exact environment entries, retaining their validated unique names.
    pub fn environment(&self) -> impl Iterator<Item = &'a [u8]> {
        validated_strings(&self.bytes[self.arguments_end..])
    }

    /// Corroborates exact transfer, runtime and complete manifest descriptions.
    ///
    /// This matches bytes and typed coordinates only. The genuine payer must
    /// still authenticate every selected artifact and producer and perform the
    /// actual retained-parent transition before launch.
    ///
    /// # Errors
    /// Refuses a foreign transfer, different full manifest digest, missing QEMU
    /// artifact roles or libc/loader identities inconsistent with RuntimePair192.
    pub fn corroborate_transfer(
        &self,
        transfer: &NativeTransfer,
        runtime: &RuntimeArtifactPair,
    ) -> Result<(), NativeProfileDecodeError> {
        transfer
            .corroborate_runtime(runtime)
            .map_err(|_| NativeProfileDecodeError)?;
        let c = transfer.coordinates;
        for (offset, expected) in [
            (16, c.profile_edition),
            (24, c.producer_request_epoch),
            (32, c.process_generation),
            (40, c.account_generation),
        ] {
            if read64(self.bytes, offset) != expected {
                return Err(NativeProfileDecodeError);
            }
        }
        for (offset, expected) in [
            (48, c.recipient),
            (80, c.parent),
            (112, c.launcher),
            (144, transfer.runtime_pair_sha256),
            (176, transfer.process_contract_sha256),
        ] {
            if read_identity(self.bytes, offset) != expected {
                return Err(NativeProfileDecodeError);
            }
        }
        let digest: [u8; 32] = Sha256::digest(self.bytes).into();
        if read32(self.bytes, 208) < 4
            || u64::from(read32(self.bytes, 208)) != transfer.artifact_count
            || digest != transfer.profile_manifest_sha256
        {
            return Err(NativeProfileDecodeError);
        }
        for (role, expected) in [(3, runtime.libc), (4, runtime.loader)] {
            let artifact = self
                .artifacts()
                .find(|artifact| artifact.role == role)
                .ok_or(NativeProfileDecodeError)?;
            if artifact.file_len != expected.file_len || artifact.sha256 != expected.sha256 {
                return Err(NativeProfileDecodeError);
            }
        }
        Ok(())
    }
}

fn validate_artifacts(bytes: &[u8], count: usize) -> Result<(), NativeProfileDecodeError> {
    let (rows, _) = bytes.as_chunks::<ARTIFACT_BYTES>();
    let active_roles = u32::MAX >> (32 - count);
    for (index, bytes) in rows.iter().enumerate() {
        let artifact = NativeProfileArtifact::read(bytes);
        if artifact.role as usize != index + 1
            || read32(bytes, 4) != 62
            || artifact.file_len == 0
            || artifact.file_len > i64::MAX as u64
            || artifact.child == [0; 32]
            || artifact.sha256 == [0; 32]
            || artifact.layout_sha256 == [0; 32]
            || artifact.dependency_roles & !active_roles != 0
            || artifact.dependency_roles & (1_u32 << index) != 0
            || read32(bytes, 84) != artifact.role
            || bytes[120..].iter().any(|byte| *byte != 0)
            || rows[..index]
                .iter()
                .any(|previous| read_identity(previous, 16) == artifact.child)
        {
            return Err(NativeProfileDecodeError);
        }
    }
    Ok(())
}

pub(super) fn validate_producers(bytes: &[u8]) -> Result<(), NativeProfileDecodeError> {
    let (rows, _) = bytes.as_chunks::<PRODUCER_BYTES>();
    for (index, bytes) in rows.iter().enumerate() {
        let kind = index as u32 + 1;
        if read32(bytes, 0) != kind
            || read32(bytes, 180) != 1
            || bytes[184..].iter().any(|byte| *byte != 0)
        {
            return Err(NativeProfileDecodeError);
        }
        match read32(bytes, 4) {
            1 => {
                let row = NativeProfileProducer::read(bytes);
                let limits = row.limits;
                let no_requests =
                    limits.cumulative_request_bytes == 0 && limits.single_request_bytes == 0;
                let finite_requests = limits.single_request_bytes > 0
                    && limits.single_request_bytes <= limits.cumulative_request_bytes;
                if matches!(row.edition, 0 | u64::MAX)
                    || row.child == [0; 32]
                    || row.implementation_sha256 == [0; 32]
                    || row.layout_sha256 == [0; 32]
                    || !limits.alignment.is_power_of_two()
                    || !(1..=10).contains(&row.liability_kind)
                    || !(no_requests || finite_requests)
                {
                    return Err(NativeProfileDecodeError);
                }
            }
            2 => {
                if matches!(kind, 1..=8 | 11 | 12 | 15 | 16)
                    || bytes[8..168].iter().any(|byte| *byte != 0)
                    || read64(bytes, 168) != 1
                    || read32(bytes, 176) != 0
                {
                    return Err(NativeProfileDecodeError);
                }
            }
            _ => return Err(NativeProfileDecodeError),
        }
    }
    Ok(())
}

fn validate_launch(bytes: &[u8]) -> Result<usize, NativeProfileDecodeError> {
    let argc = read32(bytes, 0);
    let envc = read32(bytes, 4);
    if !(1..=128).contains(&argc) || envc > 64 {
        return Err(NativeProfileDecodeError);
    }
    let mut remaining = &bytes[16..];
    for _ in 0..argc {
        read_string(&mut remaining)?;
    }
    let arguments_end = bytes.len() - remaining.len();
    let environment = remaining;
    if arguments_end - 16 != read32(bytes, 8) as usize {
        return Err(NativeProfileDecodeError);
    }
    for _ in 0..envc {
        let previous_bytes = environment.len() - remaining.len();
        let entry = read_string(&mut remaining)?;
        let equals = entry
            .iter()
            .position(|byte| *byte == b'=')
            .filter(|index| *index != 0)
            .ok_or(NativeProfileDecodeError)?;
        let name = &entry[..equals];
        for previous in validated_strings(&environment[..previous_bytes]) {
            if previous.get(name.len()) == Some(&b'=') && previous[..name.len()] == *name {
                return Err(NativeProfileDecodeError);
            }
        }
    }
    if !remaining.is_empty() || environment.len() != read32(bytes, 12) as usize {
        return Err(NativeProfileDecodeError);
    }
    Ok(arguments_end)
}

fn read_string<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], NativeProfileDecodeError> {
    if remaining.len() < 4 {
        return Err(NativeProfileDecodeError);
    }
    let length = read32(remaining, 0) as usize;
    if !(1..=4096).contains(&length) || length > remaining.len() - 4 {
        return Err(NativeProfileDecodeError);
    }
    let value = &remaining[4..4 + length];
    if value.contains(&0) {
        return Err(NativeProfileDecodeError);
    }
    *remaining = &remaining[4 + length..];
    Ok(value)
}

// These slices contain only complete strings already checked by validate_launch.
fn validated_strings(mut bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let length = read32(bytes, 0) as usize;
        let value = &bytes[4..4 + length];
        bytes = &bytes[4 + length..];
        Some(value)
    })
}

#[cfg(test)]
pub(super) mod tests;
