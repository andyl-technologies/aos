//! Fixed-seed lookup tables for process-private mapping registration.
//!
//! RFC-0010 engineering standards STD-11/STD-13 require fixed-seed,
//! annotated lookup maps even outside simulation ordering paths.
//!
//! Hash tables preserve fallible capacity reservation before mmap and mapping
//! replacement. BTreeMap cannot reserve an insertion before those effects.
//! Registry order never enters simulation state, schedules, logs or wire bytes:
//! address lookup has one matching nonoverlapping VMA, and weak-domain cleanup
//! removes only expired entries without invoking simulation callbacks.

use std::hash::{BuildHasherDefault, Hasher};

// crucible-lint: allow nondeterminism -- Fixed-seed registry lookup; reservation precedes effects.
#[allow(clippy::disallowed_types)]
use std::collections::HashMap;

/// Preserves fallible reservation with deterministic private lookup hashing.
// crucible-lint: allow nondeterminism -- Fixed-seed private lookup; no simulation order escapes.
#[allow(clippy::disallowed_types)]
pub(super) type RegistryMap<Key, Value> = HashMap<Key, Value, BuildHasherDefault<RegistryHasher>>;

/// Hashes private registration keys from one constant seed without host entropy.
pub(super) struct RegistryHasher(u64);

impl Default for RegistryHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for RegistryHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write(&value.to_le_bytes());
    }
}
