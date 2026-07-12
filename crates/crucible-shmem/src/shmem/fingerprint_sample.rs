//! Plugin-to-host single-VM fingerprint sample slot.
//!
//! Unlike the streaming coverage ring, single-VM fingerprint samples are read
//! synchronously by the host at scheduler boundaries it already controls, so
//! one fixed per-node slot is sufficient. When fingerprint sampling is enabled
//! at setup, the plugin computes the exact register, guest-RAM, and device-state
//! digests for the current icount and publishes them into its node's slot under
//! a generation seqlock; the host reads the slot after the quantum boundary.
//!
//! The slot is the wire authority for the Rust-plugin single-VM fingerprint
//! stream (`crucible.qemu.rust-plugin-fingerprint.v1`). It mirrors the material
//! the canonical `SingleVmFingerprintStream` compares, so the host consumer maps
//! one slot snapshot to one fingerprint sample without a schema translation.
//!
//! Fingerprint-sample slot wire layout:
//!
//! ```text
//! offset  size  field
//! 0       4     sample_gen (even = stable, odd = writing)
//! 4       4     reserved (zero)
//! 8       W*8   payload words (little-endian u64)
//! ```
//!
//! The payload words pack, in order: `sample_icount`, `vcpu_count`,
//! `rr_current_vcpu`, `rr_position_in_quantum`, `rr_switch_quantum`,
//! `component_failures`, `ram_bytes`, `device_state_bytes`, the 32-byte
//! `ram_digest`, `device_state_digest`, and `device_state_schema_digest` (four
//! words each), then one 6-word block per tracked vCPU carrying the 32-byte
//! register digest, `register_file_bytes`, and `retired_instruction_count`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// SHA-256/BLAKE3 digest width, in bytes, for every fingerprint component.
pub const FINGERPRINT_DIGEST_BYTES: usize = 32;
/// Number of little-endian words in one component digest.
pub const FINGERPRINT_DIGEST_WORDS: usize = FINGERPRINT_DIGEST_BYTES / 8;
/// Maximum number of vCPUs one fingerprint sample slot can carry.
///
/// The single-VM fingerprint scenarios pin two vCPUs and the N-vCPU expansion
/// pins four; eight leaves deterministic headroom without inflating the slot.
pub const FINGERPRINT_SAMPLE_MAX_VCPUS: usize = 8;
/// Number of payload words describing one tracked vCPU.
const FINGERPRINT_SAMPLE_VCPU_WORDS: usize = FINGERPRINT_DIGEST_WORDS + 2;
/// Number of fixed payload words that precede the per-vCPU blocks.
const FINGERPRINT_SAMPLE_HEADER_WORDS: usize = 6 + FINGERPRINT_DIGEST_WORDS * 3 + 2;
/// Total number of little-endian payload words in one slot.
pub const FINGERPRINT_SAMPLE_WORDS: usize =
    FINGERPRINT_SAMPLE_HEADER_WORDS + FINGERPRINT_SAMPLE_MAX_VCPUS * FINGERPRINT_SAMPLE_VCPU_WORDS;

// Fixed payload word indices.
const WORD_SAMPLE_ICOUNT: usize = 0;
const WORD_VCPU_COUNT: usize = 1;
const WORD_RR_CURRENT_VCPU: usize = 2;
const WORD_RR_POSITION: usize = 3;
const WORD_RR_QUANTUM: usize = 4;
const WORD_COMPONENT_FAILURES: usize = 5;
const WORD_RAM_BYTES: usize = 6;
const WORD_DEVICE_STATE_BYTES: usize = 7;
const WORD_RAM_DIGEST: usize = 8;
const WORD_DEVICE_STATE_DIGEST: usize = WORD_RAM_DIGEST + FINGERPRINT_DIGEST_WORDS;
const WORD_DEVICE_STATE_SCHEMA_DIGEST: usize = WORD_DEVICE_STATE_DIGEST + FINGERPRINT_DIGEST_WORDS;
const WORD_VCPU_BASE: usize = WORD_DEVICE_STATE_SCHEMA_DIGEST + FINGERPRINT_DIGEST_WORDS;

const _: () = assert!(WORD_VCPU_BASE == FINGERPRINT_SAMPLE_HEADER_WORDS);

/// One tracked vCPU's contribution to a fingerprint sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FingerprintSampleVcpu {
    /// Content digest of the vCPU's canonical architectural register file.
    pub register_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    /// Canonical register-file byte count the digest covers.
    pub register_file_bytes: u64,
    /// Aggregate retired-instruction count observed for the vCPU.
    pub retired_instruction_count: u64,
}

/// A tear-free snapshot of one node's fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintSample {
    /// Aggregate icount at which every component below was sampled.
    pub sample_icount: u64,
    /// Number of tracked vCPUs; entries beyond this are unpopulated.
    pub vcpu_count: u32,
    /// Round-robin cursor's current vCPU index.
    pub rr_current_vcpu: u32,
    /// Round-robin cursor position within the switch quantum.
    pub rr_position_in_quantum: u64,
    /// Pinned round-robin switch quantum in node-icount units.
    pub rr_switch_quantum: u64,
    /// Bitset of components whose plugin-side capture failed (0 on success).
    pub component_failures: u32,
    /// Byte count covered by [`Self::ram_digest`].
    pub ram_bytes: u64,
    /// Content digest of the guest's writable RAM.
    pub ram_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    /// Byte count covered by [`Self::device_state_digest`].
    pub device_state_bytes: u64,
    /// Content digest of the serialized current non-RAM device VMState.
    pub device_state_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    /// Content digest of the registered non-RAM VMState section schema.
    pub device_state_schema_digest: [u8; FINGERPRINT_DIGEST_BYTES],
    /// Per-vCPU material; only the first [`Self::vcpu_count`] entries are valid.
    pub vcpus: [FingerprintSampleVcpu; FINGERPRINT_SAMPLE_MAX_VCPUS],
}

impl Default for FingerprintSample {
    fn default() -> Self {
        Self {
            sample_icount: 0,
            vcpu_count: 0,
            rr_current_vcpu: 0,
            rr_position_in_quantum: 0,
            rr_switch_quantum: 0,
            component_failures: 0,
            ram_bytes: 0,
            ram_digest: [0; FINGERPRINT_DIGEST_BYTES],
            device_state_bytes: 0,
            device_state_digest: [0; FINGERPRINT_DIGEST_BYTES],
            device_state_schema_digest: [0; FINGERPRINT_DIGEST_BYTES],
            vcpus: [FingerprintSampleVcpu {
                register_digest: [0; FINGERPRINT_DIGEST_BYTES],
                register_file_bytes: 0,
                retired_instruction_count: 0,
            }; FINGERPRINT_SAMPLE_MAX_VCPUS],
        }
    }
}

/// Error raised when building a [`FingerprintSample`] for publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FingerprintSampleError {
    /// The requested vCPU count exceeds [`FINGERPRINT_SAMPLE_MAX_VCPUS`].
    #[error("fingerprint sample vcpu count {requested} exceeds slot capacity {capacity}")]
    TooManyVcpus {
        /// vCPU count the caller requested.
        requested: u32,
        /// Fixed slot capacity.
        capacity: u32,
    },
}

impl FingerprintSample {
    /// Validates a sample against the fixed slot capacity.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSampleError::TooManyVcpus`] when `vcpu_count`
    /// exceeds [`FINGERPRINT_SAMPLE_MAX_VCPUS`].
    pub fn validate(self) -> Result<Self, FingerprintSampleError> {
        if self.vcpu_count as usize > FINGERPRINT_SAMPLE_MAX_VCPUS {
            return Err(FingerprintSampleError::TooManyVcpus {
                requested: self.vcpu_count,
                capacity: FINGERPRINT_SAMPLE_MAX_VCPUS as u32,
            });
        }
        Ok(self)
    }
}

/// Fixed per-node slot carrying the latest published fingerprint sample.
#[derive(Debug)]
#[repr(C, align(128))]
pub struct FingerprintSampleSlot {
    sample_gen: AtomicU32,
    _reserved: u32,
    words: [AtomicU64; FINGERPRINT_SAMPLE_WORDS],
}

/// Byte offset of [`FingerprintSampleSlot`]'s generation seqlock.
pub const FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET: usize =
    core::mem::offset_of!(FingerprintSampleSlot, sample_gen);
/// Byte offset of [`FingerprintSampleSlot`]'s reserved word.
pub const FINGERPRINT_SAMPLE_SLOT_RESERVED_OFFSET: usize =
    core::mem::offset_of!(FingerprintSampleSlot, _reserved);
/// Byte offset of [`FingerprintSampleSlot`]'s payload words.
pub const FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET: usize =
    core::mem::offset_of!(FingerprintSampleSlot, words);
/// Wire size of one [`FingerprintSampleSlot`].
pub const FINGERPRINT_SAMPLE_SLOT_SIZE: usize = core::mem::size_of::<FingerprintSampleSlot>();
/// Wire alignment of one [`FingerprintSampleSlot`].
pub const FINGERPRINT_SAMPLE_SLOT_ALIGN: usize = core::mem::align_of::<FingerprintSampleSlot>();

const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET == 0);
const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_RESERVED_OFFSET == 4);
const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET == 8);
const _: () = assert!(FINGERPRINT_SAMPLE_SLOT_ALIGN == 128);

impl Default for FingerprintSampleSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintSampleSlot {
    /// Builds an unpublished, zeroed fingerprint sample slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sample_gen: AtomicU32::new(0),
            _reserved: 0,
            words: [const { AtomicU64::new(0) }; FINGERPRINT_SAMPLE_WORDS],
        }
    }

    /// Returns the current published generation (0 before any publication).
    #[must_use]
    pub fn published_generation(&self) -> u32 {
        self.sample_gen.load(Ordering::Acquire)
    }

    /// Publishes `sample` into the slot under the generation seqlock.
    ///
    /// The write bumps the generation to an odd value, stores every payload
    /// word with release ordering, then bumps the generation to the next even
    /// value so a concurrent reader either observes the complete new sample or
    /// retries.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSampleError`] when the sample fails
    /// [`FingerprintSample::validate`].
    pub fn publish(&self, sample: &FingerprintSample) -> Result<(), FingerprintSampleError> {
        let sample = sample.validate()?;
        self.sample_gen.fetch_add(1, Ordering::AcqRel);
        let mut words = [0_u64; FINGERPRINT_SAMPLE_WORDS];
        pack_sample(&sample, &mut words);
        for (slot, value) in self.words.iter().zip(words) {
            slot.store(value, Ordering::Release);
        }
        self.sample_gen.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Returns a tear-free snapshot, or `None` if nothing was ever published.
    ///
    /// The read retries until it observes a stable even generation, so it never
    /// returns a torn mix of two publications.
    #[must_use]
    pub fn snapshot(&self) -> Option<FingerprintSample> {
        loop {
            let before = self.sample_gen.load(Ordering::Acquire);
            if before == 0 {
                return None;
            }
            if before & 1 == 1 {
                core::hint::spin_loop();
                continue;
            }
            let mut words = [0_u64; FINGERPRINT_SAMPLE_WORDS];
            for (value, slot) in words.iter_mut().zip(self.words.iter()) {
                *value = slot.load(Ordering::Acquire);
            }
            let after = self.sample_gen.load(Ordering::Acquire);
            if before == after {
                return Some(unpack_sample(&words));
            }
            core::hint::spin_loop();
        }
    }
}

fn digest_to_words(digest: &[u8; FINGERPRINT_DIGEST_BYTES], out: &mut [u64]) {
    for (word, chunk) in out.iter_mut().zip(digest.chunks_exact(8)) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        *word = u64::from_le_bytes(bytes);
    }
}

fn words_to_digest(words: &[u64]) -> [u8; FINGERPRINT_DIGEST_BYTES] {
    let mut digest = [0_u8; FINGERPRINT_DIGEST_BYTES];
    for (chunk, word) in digest.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn pack_sample(sample: &FingerprintSample, words: &mut [u64; FINGERPRINT_SAMPLE_WORDS]) {
    words[WORD_SAMPLE_ICOUNT] = sample.sample_icount;
    words[WORD_VCPU_COUNT] = u64::from(sample.vcpu_count);
    words[WORD_RR_CURRENT_VCPU] = u64::from(sample.rr_current_vcpu);
    words[WORD_RR_POSITION] = sample.rr_position_in_quantum;
    words[WORD_RR_QUANTUM] = sample.rr_switch_quantum;
    words[WORD_COMPONENT_FAILURES] = u64::from(sample.component_failures);
    words[WORD_RAM_BYTES] = sample.ram_bytes;
    words[WORD_DEVICE_STATE_BYTES] = sample.device_state_bytes;
    digest_to_words(
        &sample.ram_digest,
        &mut words[WORD_RAM_DIGEST..WORD_RAM_DIGEST + FINGERPRINT_DIGEST_WORDS],
    );
    digest_to_words(
        &sample.device_state_digest,
        &mut words[WORD_DEVICE_STATE_DIGEST..WORD_DEVICE_STATE_DIGEST + FINGERPRINT_DIGEST_WORDS],
    );
    digest_to_words(
        &sample.device_state_schema_digest,
        &mut words[WORD_DEVICE_STATE_SCHEMA_DIGEST
            ..WORD_DEVICE_STATE_SCHEMA_DIGEST + FINGERPRINT_DIGEST_WORDS],
    );
    for (index, vcpu) in sample.vcpus.iter().enumerate() {
        let base = WORD_VCPU_BASE + index * FINGERPRINT_SAMPLE_VCPU_WORDS;
        digest_to_words(
            &vcpu.register_digest,
            &mut words[base..base + FINGERPRINT_DIGEST_WORDS],
        );
        words[base + FINGERPRINT_DIGEST_WORDS] = vcpu.register_file_bytes;
        words[base + FINGERPRINT_DIGEST_WORDS + 1] = vcpu.retired_instruction_count;
    }
}

fn unpack_sample(words: &[u64; FINGERPRINT_SAMPLE_WORDS]) -> FingerprintSample {
    let mut sample = FingerprintSample {
        sample_icount: words[WORD_SAMPLE_ICOUNT],
        vcpu_count: words[WORD_VCPU_COUNT] as u32,
        rr_current_vcpu: words[WORD_RR_CURRENT_VCPU] as u32,
        rr_position_in_quantum: words[WORD_RR_POSITION],
        rr_switch_quantum: words[WORD_RR_QUANTUM],
        component_failures: words[WORD_COMPONENT_FAILURES] as u32,
        ram_bytes: words[WORD_RAM_BYTES],
        device_state_bytes: words[WORD_DEVICE_STATE_BYTES],
        ram_digest: words_to_digest(
            &words[WORD_RAM_DIGEST..WORD_RAM_DIGEST + FINGERPRINT_DIGEST_WORDS],
        ),
        device_state_digest: words_to_digest(
            &words[WORD_DEVICE_STATE_DIGEST..WORD_DEVICE_STATE_DIGEST + FINGERPRINT_DIGEST_WORDS],
        ),
        device_state_schema_digest: words_to_digest(
            &words[WORD_DEVICE_STATE_SCHEMA_DIGEST
                ..WORD_DEVICE_STATE_SCHEMA_DIGEST + FINGERPRINT_DIGEST_WORDS],
        ),
        vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
    };
    for (index, vcpu) in sample.vcpus.iter_mut().enumerate() {
        let base = WORD_VCPU_BASE + index * FINGERPRINT_SAMPLE_VCPU_WORDS;
        vcpu.register_digest = words_to_digest(&words[base..base + FINGERPRINT_DIGEST_WORDS]);
        vcpu.register_file_bytes = words[base + FINGERPRINT_DIGEST_WORDS];
        vcpu.retired_instruction_count = words[base + FINGERPRINT_DIGEST_WORDS + 1];
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> [u8; FINGERPRINT_DIGEST_BYTES] {
        let mut out = [0_u8; FINGERPRINT_DIGEST_BYTES];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }

    fn sample() -> FingerprintSample {
        let mut sample = FingerprintSample {
            sample_icount: 100_000,
            vcpu_count: 2,
            rr_current_vcpu: 1,
            rr_position_in_quantum: 17,
            rr_switch_quantum: 4096,
            component_failures: 0,
            ram_bytes: 64 * 1024 * 1024,
            ram_digest: digest(0x10),
            device_state_bytes: 4096,
            device_state_digest: digest(0x20),
            device_state_schema_digest: digest(0x30),
            vcpus: [FingerprintSampleVcpu::default(); FINGERPRINT_SAMPLE_MAX_VCPUS],
        };
        sample.vcpus[0] = FingerprintSampleVcpu {
            register_digest: digest(0x40),
            register_file_bytes: 512,
            retired_instruction_count: 100_000,
        };
        sample.vcpus[1] = FingerprintSampleVcpu {
            register_digest: digest(0x50),
            register_file_bytes: 512,
            retired_instruction_count: 100_000,
        };
        sample
    }

    #[test]
    fn unpublished_slot_snapshots_to_none() {
        let slot = FingerprintSampleSlot::new();
        assert_eq!(slot.published_generation(), 0);
        assert_eq!(slot.snapshot(), None);
    }

    #[test]
    fn publish_then_snapshot_round_trips_every_field() {
        let slot = FingerprintSampleSlot::new();
        let published = sample();
        if let Err(error) = slot.publish(&published) {
            panic!("sample within capacity: {error}");
        }
        assert_eq!(slot.published_generation(), 2);
        assert_eq!(slot.snapshot(), Some(published));
    }

    #[test]
    fn republish_advances_generation_and_replaces_sample() {
        let slot = FingerprintSampleSlot::new();
        if let Err(error) = slot.publish(&sample()) {
            panic!("first publish: {error}");
        }
        let mut second = sample();
        second.sample_icount = 200_000;
        if let Err(error) = slot.publish(&second) {
            panic!("second publish: {error}");
        }
        assert_eq!(slot.published_generation(), 4);
        assert_eq!(slot.snapshot(), Some(second));
    }

    #[test]
    fn over_capacity_vcpu_count_is_rejected() {
        let slot = FingerprintSampleSlot::new();
        let mut invalid = sample();
        invalid.vcpu_count = FINGERPRINT_SAMPLE_MAX_VCPUS as u32 + 1;
        assert_eq!(
            slot.publish(&invalid),
            Err(FingerprintSampleError::TooManyVcpus {
                requested: FINGERPRINT_SAMPLE_MAX_VCPUS as u32 + 1,
                capacity: FINGERPRINT_SAMPLE_MAX_VCPUS as u32,
            })
        );
    }
}
