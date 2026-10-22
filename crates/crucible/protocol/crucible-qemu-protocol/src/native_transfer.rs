//! Describes a proposed prebirth containing-process resource transfer.
//!
//! ```text
//! CRUCNPL1 | schema1:u32 | bytes1472:u32 | fixed-header[496] | liabilities[10][96]
//! All integers are big endian; reserved bytes are zero.
//! ```
//!
//! The record corroborates a transition by real retained owners. Decoding it
//! cannot reserve resources, authenticate a profile, move a loan, authorize
//! execution or establish that the launcher's actual child has been reaped.
//! Setup ten and plan thirteen do not accept this separately proposed record.
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{Digest, Sha256};

use crate::runtime_artifact::RuntimeArtifactPair;

/// Contains the complete fixed transfer record, including its ten liability rows.
pub const NATIVE_TRANSFER_BYTES: usize = 1472;

/// Counts the independently described physical liability categories.
pub const NATIVE_LIABILITY_COUNT: usize = 10;

/// Bounds the separately specified complete immutable artifact roster.
///
/// This storage ceiling does not establish that any selected dependency closure
/// fits, that its manifest is authenticated or that its resources are funded.
pub const NATIVE_TRANSFER_MAX_ARTIFACTS: u64 = 32;

const HEADER_BYTES: usize = 512;
const LIABILITY_BYTES: usize = 96;

/// Refuses malformed transfer descriptions without allocating diagnostic storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid prebirth native-transfer description")]
pub struct NativeTransferDecodeError;

/// Names one physical producer category in the fixed liability order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeLiabilityKind {
    /// Retains immutable artifact backing independently of its mapped aliases.
    ArtifactBacking = 1,
    /// Covers mapped image pages and their worst-case private copies.
    ImageAndPrivateCopies = 2,
    /// Covers actual kernel mapping and accounting producers.
    KernelMappings = 3,
    /// Covers complete initial TLS, TCB, DTV and their controls.
    InitialTls = 4,
    /// Covers the containing Main stack and its guards.
    MainStack = 5,
    /// Covers fixed Source, preexec, getter and ownership history storage.
    FixedControl = 6,
    /// Covers finite dynamic application and translation mappings.
    DynamicMappings = 7,
    /// Covers bounded worker stacks, TLS and controls.
    WorkerStorage = 8,
    /// Retains independently protected progress capacity.
    Progress = 9,
    /// Retains independently protected physical terminal capacity.
    PhysicalTerminal = 10,
}

impl NativeLiabilityKind {
    fn decode(tag: u32) -> Result<Self, NativeTransferDecodeError> {
        match tag {
            1 => Ok(Self::ArtifactBacking),
            2 => Ok(Self::ImageAndPrivateCopies),
            3 => Ok(Self::KernelMappings),
            4 => Ok(Self::InitialTls),
            5 => Ok(Self::MainStack),
            6 => Ok(Self::FixedControl),
            7 => Ok(Self::DynamicMappings),
            8 => Ok(Self::WorkerStorage),
            9 => Ok(Self::Progress),
            10 => Ok(Self::PhysicalTerminal),
            _ => Err(NativeTransferDecodeError),
        }
    }
}

/// Distinguishes required producers from categories genuinely excluded by a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeLiabilityDisposition {
    /// Requires an actual producer child and a positive finite memory charge.
    Required = 1,
    /// Describes a category made unreachable by the actual complete profile.
    Unselected = 2,
}

/// Describes one independently retained process-reap liability.
///
/// Zero in a resource dimension means the actual complete producer proves that
/// dimension absent. A numerical observation does not provide that proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeLiability {
    /// Names the exact physical producer category.
    pub kind: NativeLiabilityKind,
    /// Describes whether this category actually participates in the profile.
    pub disposition: NativeLiabilityDisposition,
    /// Bounds worst-case native memory use by this actual producer.
    pub memory_bytes: u64,
    /// Bounds independently retained virtual address space.
    pub virtual_bytes: u64,
    /// Bounds independently retained filesystem or backing quota.
    pub backing_bytes: u64,
    /// Bounds the actual maximum concurrent task count.
    pub maximum_tasks: u64,
    /// Bounds the actual maximum concurrent descriptor count.
    pub maximum_descriptors: u64,
    /// Gives the nonzero power-of-two producer alignment.
    pub alignment: u64,
    /// Identifies the actual canonical producing child, rather than its caller.
    pub producer: [u8; 32],
}

impl NativeLiability {
    fn validate(&self) -> Result<(), NativeTransferDecodeError> {
        if !self.alignment.is_power_of_two() {
            return Err(NativeTransferDecodeError);
        }

        match self.disposition {
            NativeLiabilityDisposition::Required => {
                if self.memory_bytes == 0 || self.producer == [0; 32] {
                    return Err(NativeTransferDecodeError);
                }
            }
            NativeLiabilityDisposition::Unselected => {
                if self.memory_bytes != 0
                    || self.virtual_bytes != 0
                    || self.backing_bytes != 0
                    || self.maximum_tasks != 0
                    || self.maximum_descriptors != 0
                    || self.alignment != 1
                    || self.producer != [0; 32]
                {
                    return Err(NativeTransferDecodeError);
                }
            }
        }
        Ok(())
    }

    fn encode_into(&self, bytes: &mut [u8]) {
        put32(bytes, 0, self.kind as u32);
        put32(bytes, 4, self.disposition as u32);
        put32(bytes, 8, 1); // This edition retains every row until process reap.
        for (offset, value) in [
            (16, self.memory_bytes),
            (24, self.virtual_bytes),
            (32, self.backing_bytes),
            (40, self.maximum_tasks),
            (48, self.maximum_descriptors),
            (56, self.alignment),
        ] {
            put64(bytes, offset, value);
        }
        bytes[64..96].copy_from_slice(&self.producer);
    }

    fn decode(bytes: &[u8]) -> Result<Self, NativeTransferDecodeError> {
        if read32(bytes, 8) != 1 || read32(bytes, 12) != 0 {
            return Err(NativeTransferDecodeError);
        }
        let disposition = match read32(bytes, 4) {
            1 => NativeLiabilityDisposition::Required,
            2 => NativeLiabilityDisposition::Unselected,
            _ => return Err(NativeTransferDecodeError),
        };
        let row = Self {
            kind: NativeLiabilityKind::decode(read32(bytes, 0))?,
            disposition,
            memory_bytes: read64(bytes, 16),
            virtual_bytes: read64(bytes, 24),
            backing_bytes: read64(bytes, 32),
            maximum_tasks: read64(bytes, 40),
            maximum_descriptors: read64(bytes, 48),
            alignment: read64(bytes, 56),
            producer: read_identity(bytes, 64),
        };
        row.validate()?;
        Ok(row)
    }
}

/// Correlates descriptions with the real issuer, containing parent and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransferCoordinates {
    /// Gives the actual issuer's nonwrapping incarnation.
    pub issuer_epoch: u64,
    /// Gives the actual containing parent's nonwrapping incarnation.
    pub parent_epoch: u64,
    /// Gives the actual subloan's nonwrapping incarnation.
    pub loan_epoch: u64,
    /// Gives the containing process incarnation.
    pub process_generation: u64,
    /// Gives the containing account generation.
    pub account_generation: u64,
    /// Identifies the actual finite producer request incarnation.
    pub producer_request_epoch: u64,
    /// Identifies this request within its actual retained issuer.
    pub request_sequence: u64,
    /// Selects the actual complete finite profile edition.
    pub profile_edition: u64,
    /// Identifies the real containing resource parent.
    pub parent: [u8; 32],
    /// Identifies the real issuer retaining that parent.
    pub issuer: [u8; 32],
    /// Identifies the exact Source assignment receiving the local borrower.
    pub recipient: [u8; 32],
    /// Identifies the actual launcher retaining the kernel child's reap duty.
    pub launcher: [u8; 32],
    /// Identifies the actual canonical subloan.
    pub loan: [u8; 32],
    /// Identifies the independent physical cleanup holder.
    pub cleanup_holder: [u8; 32],
    /// Gives that physical cleanup holder's nonwrapping incarnation.
    pub cleanup_epoch: u64,
}

/// Describes disjoint containing memory charges and their contained purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransferMemory {
    /// Gives the original containing gross-process memory extent.
    pub gross_bytes: u64,
    /// Gives the amount assigned once to this native subloan.
    pub native_bytes: u64,
    /// Gives the disjoint amount retained outside this subloan.
    pub retained_bytes: u64,
    /// Describes the already issued fixed floor contained within native memory.
    pub fixed_floor_bytes: u64,
    /// Describes the protected progress partition contained within native memory.
    pub progress_bytes: u64,
    /// Describes the protected physical-terminal partition within native memory.
    pub physical_terminal_bytes: u64,
    /// Describes creator/history memory contained within the outside amount.
    pub creator_history_bytes: u64,
}

/// Describes an existing prebirth native subloan without constructing its holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransfer {
    /// Correlates actual parent, borrower, issuer and retained cleanup incarnations.
    pub coordinates: NativeTransferCoordinates,
    /// Digests the exact independently encoded RuntimePair192.
    pub runtime_pair_sha256: [u8; 32],
    /// Digests the complete immutable producer/profile manifest.
    pub profile_manifest_sha256: [u8; 32],
    /// Digests the exact containing issued process-contract material.
    pub process_contract_sha256: [u8; 32],
    /// Describes disjoint charges and contained protected purpose partitions.
    pub memory: NativeTransferMemory,
    /// Records the actual authenticated kernel page size.
    pub page_size: u64,
    /// Counts artifacts named by the actual complete profile manifest.
    pub artifact_count: u64,
    /// Digests the actual bounded paid-probe result, including its retained reap.
    pub paid_probe_sha256: [u8; 32],
    /// Describes all ten physical producer categories in their exact kind order.
    pub liabilities: [NativeLiability; NATIVE_LIABILITY_COUNT],
}

impl NativeTransfer {
    fn validate(&self) -> Result<(), NativeTransferDecodeError> {
        let c = &self.coordinates;
        for epoch in [
            c.issuer_epoch,
            c.parent_epoch,
            c.loan_epoch,
            c.process_generation,
            c.account_generation,
            c.producer_request_epoch,
            c.request_sequence,
            c.profile_edition,
            c.cleanup_epoch,
        ] {
            if epoch == 0 || epoch == u64::MAX {
                return Err(NativeTransferDecodeError);
            }
        }
        for identity in [
            c.parent,
            c.issuer,
            c.recipient,
            c.launcher,
            c.loan,
            c.cleanup_holder,
            self.runtime_pair_sha256,
            self.profile_manifest_sha256,
            self.process_contract_sha256,
            self.paid_probe_sha256,
        ] {
            if identity == [0; 32] {
                return Err(NativeTransferDecodeError);
            }
        }

        let memory = self.memory;
        if memory.gross_bytes == 0
            || memory.native_bytes == 0
            || memory.retained_bytes == 0
            || memory.creator_history_bytes == 0
            || memory.native_bytes.checked_add(memory.retained_bytes) != Some(memory.gross_bytes)
            || memory.creator_history_bytes > memory.retained_bytes
            || self.page_size != 4096
            || !(2..=NATIVE_TRANSFER_MAX_ARTIFACTS).contains(&self.artifact_count)
        {
            return Err(NativeTransferDecodeError);
        }

        let mut total = 0_u64;
        for (index, liability) in self.liabilities.iter().enumerate() {
            liability.validate()?;
            if liability.kind as usize != index + 1 {
                return Err(NativeTransferDecodeError);
            }
            total = total
                .checked_add(liability.memory_bytes)
                .ok_or(NativeTransferDecodeError)?;
        }
        for index in [5, 8, 9] {
            if self.liabilities[index].disposition != NativeLiabilityDisposition::Required {
                return Err(NativeTransferDecodeError);
            }
        }
        if total != memory.native_bytes
            || self.liabilities[5].memory_bytes != memory.fixed_floor_bytes
            || self.liabilities[8].memory_bytes != memory.progress_bytes
            || self.liabilities[9].memory_bytes != memory.physical_terminal_bytes
        {
            return Err(NativeTransferDecodeError);
        }
        Ok(())
    }

    /// Encodes the fixed description without allocating or moving resources.
    ///
    /// # Errors
    /// Refuses malformed coordinates, absent identities, unsupported row order,
    /// inconsistent purpose partitions, absent compulsory rows, unsupported
    /// page/artifact bounds, invalid alignments and arithmetic overflow.
    pub fn encode(&self) -> Result<[u8; NATIVE_TRANSFER_BYTES], NativeTransferDecodeError> {
        self.validate()?;
        let mut bytes = [0; NATIVE_TRANSFER_BYTES];
        bytes[..8].copy_from_slice(b"CRUCNPL1");
        put32(&mut bytes, 8, 1);
        put32(&mut bytes, 12, NATIVE_TRANSFER_BYTES as u32);

        let c = &self.coordinates;
        let m = self.memory;
        for (offset, value) in [
            (16, c.issuer_epoch),
            (24, c.parent_epoch),
            (32, c.loan_epoch),
            (40, c.process_generation),
            (48, c.account_generation),
            (56, c.producer_request_epoch),
            (64, c.request_sequence),
            (72, c.profile_edition),
            (368, c.cleanup_epoch),
            (376, m.gross_bytes),
            (384, m.native_bytes),
            (392, m.retained_bytes),
            (400, m.fixed_floor_bytes),
            (408, m.progress_bytes),
            (416, m.physical_terminal_bytes),
            (424, m.creator_history_bytes),
            (432, self.page_size),
            (440, NATIVE_LIABILITY_COUNT as u64),
            (448, self.artifact_count),
        ] {
            put64(&mut bytes, offset, value);
        }
        for (offset, identity) in [
            (80, c.parent),
            (112, c.issuer),
            (144, c.recipient),
            (176, c.launcher),
            (208, c.loan),
            (240, self.runtime_pair_sha256),
            (272, self.profile_manifest_sha256),
            (304, self.process_contract_sha256),
            (336, c.cleanup_holder),
            (456, self.paid_probe_sha256),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&identity);
        }
        let (rows, _) = bytes[HEADER_BYTES..].as_chunks_mut::<LIABILITY_BYTES>();
        for (liability, destination) in self.liabilities.iter().zip(rows) {
            liability.encode_into(destination);
        }
        Ok(bytes)
    }

    /// Decodes the exact fixed layout without authenticating its described owners.
    ///
    /// # Errors
    /// Refuses truncation, trailing bytes, changed schema, unknown tags, nonzero
    /// reserved bytes and any description rejected by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeTransferDecodeError> {
        if bytes.len() != NATIVE_TRANSFER_BYTES
            || bytes[..8] != *b"CRUCNPL1"
            || read32(bytes, 8) != 1
            || read32(bytes, 12) != NATIVE_TRANSFER_BYTES as u32
            || read64(bytes, 440) != NATIVE_LIABILITY_COUNT as u64
            || bytes[488..512].iter().any(|byte| *byte != 0)
        {
            return Err(NativeTransferDecodeError);
        }

        let first = NativeLiability::decode(&bytes[HEADER_BYTES..HEADER_BYTES + LIABILITY_BYTES])?;
        let mut liabilities = [first; NATIVE_LIABILITY_COUNT];
        let (rows, _) = bytes[HEADER_BYTES..].as_chunks::<LIABILITY_BYTES>();
        for (liability, source) in liabilities.iter_mut().zip(rows) {
            *liability = NativeLiability::decode(source)?;
        }
        let record = Self {
            coordinates: NativeTransferCoordinates {
                issuer_epoch: read64(bytes, 16),
                parent_epoch: read64(bytes, 24),
                loan_epoch: read64(bytes, 32),
                process_generation: read64(bytes, 40),
                account_generation: read64(bytes, 48),
                producer_request_epoch: read64(bytes, 56),
                request_sequence: read64(bytes, 64),
                profile_edition: read64(bytes, 72),
                parent: read_identity(bytes, 80),
                issuer: read_identity(bytes, 112),
                recipient: read_identity(bytes, 144),
                launcher: read_identity(bytes, 176),
                loan: read_identity(bytes, 208),
                cleanup_holder: read_identity(bytes, 336),
                cleanup_epoch: read64(bytes, 368),
            },
            runtime_pair_sha256: read_identity(bytes, 240),
            profile_manifest_sha256: read_identity(bytes, 272),
            process_contract_sha256: read_identity(bytes, 304),
            memory: NativeTransferMemory {
                gross_bytes: read64(bytes, 376),
                native_bytes: read64(bytes, 384),
                retained_bytes: read64(bytes, 392),
                fixed_floor_bytes: read64(bytes, 400),
                progress_bytes: read64(bytes, 408),
                physical_terminal_bytes: read64(bytes, 416),
                creator_history_bytes: read64(bytes, 424),
            },
            page_size: read64(bytes, 432),
            artifact_count: read64(bytes, 448),
            paid_probe_sha256: read_identity(bytes, 456),
            liabilities,
        };
        record.validate()?;
        Ok(record)
    }

    /// Corroborates the description against the exact separately encoded runtime pair.
    ///
    /// This checks bytes and correlation only. It cannot authenticate an issuer,
    /// move retained custody or authorize the actual selected runtime's execution.
    ///
    /// # Errors
    /// Refuses a malformed pair, different process/account/Source recipient or a
    /// digest that does not cover the complete exact RuntimePair192 encoding.
    pub fn corroborate_runtime(
        &self,
        pair: &RuntimeArtifactPair,
    ) -> Result<(), NativeTransferDecodeError> {
        self.validate()?;
        let bytes = pair.encode().map_err(|_| NativeTransferDecodeError)?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if pair.process_generation != self.coordinates.process_generation
            || pair.account_generation != self.coordinates.account_generation
            || pair.source_assignment != self.coordinates.recipient
            || digest != self.runtime_pair_sha256
        {
            return Err(NativeTransferDecodeError);
        }
        Ok(())
    }
}

// Every caller establishes the exact containing record or row before reading.
fn read32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(word)
}

fn read64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(word)
}

fn read_identity(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut identity = [0; 32];
    identity.copy_from_slice(&bytes[offset..offset + 32]);
    identity
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
