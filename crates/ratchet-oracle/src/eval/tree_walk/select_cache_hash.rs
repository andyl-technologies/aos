//! Fast integer-key hashing for the per-site attribute select-cache maps.
//!
//! The tree-walk evaluator keys three polymorphic inline-cache (PIC) maps -
//! flat, projected-shaped, and HAMT select caches - by the tuple
//! `(module id, inline-cache site id, path index)`. Every attribute select
//! probes the corresponding map, so the map lookup sits on the evaluator's
//! hottest path.
//!
//! A `BTreeMap` keyed by that tuple pays an `O(log n)` chain of tuple
//! comparisons with pointer chasing between B-tree nodes on every select. The
//! keys are small integers, so a hash map with a cheap integer mixer is the
//! better fit. The standard-library `HashMap` default hasher (SipHash) is
//! DoS-resistant but computes a full keyed hash; these keys are internal and
//! never attacker-chosen, so this module supplies a minimal
//! [Firefox `FxHash`][fxhash]-style multiply-rotate mixer instead.
//!
//! Only point `entry`/`get`/`values` operations are used against these maps and
//! the terminal-state telemetry that iterates `values()` accumulates
//! order-independent counter sums, so replacing the ordered `BTreeMap` with an
//! unordered [`SelectCacheMap`] changes neither evaluation results nor recorded
//! statistics.
//!
//! [fxhash]: https://github.com/rust-lang/rustc-hash

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Multiply constant for the `FxHash`-style integer mixer (the 64-bit variant).
const SELECT_CACHE_HASH_MULTIPLIER: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// Rotate applied to the running hash before each mixed word.
const SELECT_CACHE_HASH_ROTATE: u32 = 5;

/// A minimal `FxHash`-style hasher specialized for small integer keys.
///
/// Each mixed word rotates the running state, xors in the word, and multiplies
/// by [`SELECT_CACHE_HASH_MULTIPLIER`]. The integer `write_*` methods mix one
/// word directly; the byte-slice fallback mixes each byte, which is only reached
/// for key components that are not fixed-width integers (none today).
#[derive(Default)]
pub(in crate::eval::tree_walk) struct SelectCacheHasher {
    hash: u64,
}

impl SelectCacheHasher {
    /// Mixes one 64-bit word into the running hash.
    #[inline]
    fn add_word(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(SELECT_CACHE_HASH_ROTATE) ^ word)
            .wrapping_mul(SELECT_CACHE_HASH_MULTIPLIER);
    }
}

impl Hasher for SelectCacheHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.add_word(u64::from(byte));
        }
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.add_word(u64::from(value));
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.add_word(value);
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.add_word(value as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// A `HashMap` specialization using [`SelectCacheHasher`] for select-cache maps.
pub(in crate::eval::tree_walk) type SelectCacheMap<K, V> =
    HashMap<K, V, BuildHasherDefault<SelectCacheHasher>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_select_keys_do_not_all_collide() {
        let mut map: SelectCacheMap<(u32, u32, usize), u32> = SelectCacheMap::default();
        for module in 0..4u32 {
            for site in 0..8u32 {
                for path in 0..4usize {
                    map.insert((module, site, path), module + site);
                }
            }
        }
        assert_eq!(map.len(), 4 * 8 * 4);
        assert_eq!(map.get(&(3, 7, 3)).copied(), Some(10));
        assert_eq!(map.get(&(0, 0, 0)).copied(), Some(0));
        assert_eq!(map.get(&(4, 0, 0)), None);
    }

    #[test]
    fn mixer_distinguishes_component_permutations() {
        // A pure additive mixer would collide (1,2,3) with (3,2,1); the rotate
        // step must keep component order significant.
        let mut map: SelectCacheMap<(u32, u32, usize), &'static str> = SelectCacheMap::default();
        map.insert((1, 2, 3), "a");
        map.insert((3, 2, 1), "b");
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&(1, 2, 3)).copied(), Some("a"));
        assert_eq!(map.get(&(3, 2, 1)).copied(), Some("b"));
    }
}
