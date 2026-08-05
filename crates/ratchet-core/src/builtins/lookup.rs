//! Compile-time perfect-hash lookup table for builtin name resolution.

use super::*;

const BUILTIN_LOOKUP_PRIMARY_SEED: u32 = 0x811c_9dc5;
const BUILTIN_LOOKUP_SECONDARY_SEED: u32 = 0x9e37_79b9;
pub(crate) const BUILTIN_LOOKUP_EMPTY_SLOT: u16 = u16::MAX;

#[derive(Clone, Copy, Debug)]
pub struct BuiltinLookupTable<const N: usize> {
    pub(super) displacements: [u16; N],
    pub(super) slots: [u16; N],
}

#[derive(Clone, Copy, Debug)]
struct BuiltinLookupBuckets<const N: usize> {
    sizes: [usize; N],
    members: [[u16; N]; N],
    order: [usize; N],
}

impl<const N: usize> BuiltinLookupTable<N> {
    pub(super) const fn build(declarations: &[Builtin]) -> Self {
        assert!(declarations.len() == N);

        let mut lookup = Self {
            displacements: [0; N],
            slots: [BUILTIN_LOOKUP_EMPTY_SLOT; N],
        };
        let buckets = BuiltinLookupBuckets::build(declarations);
        let mut order_index = 0;
        while order_index < N {
            let bucket = buckets.order[order_index];
            if buckets.sizes[bucket] > 0 {
                let displacement = lookup.find_displacement(declarations, &buckets, bucket);
                lookup.displacements[bucket] = displacement;
                lookup.place_bucket(declarations, &buckets, bucket, displacement);
            }
            order_index += 1;
        }
        lookup.assert_complete();
        lookup
    }

    pub(super) fn candidate_index(&self, name: &[u8]) -> Option<usize> {
        if name.is_empty() || N == 0 {
            return None;
        }
        let bucket = builtin_lookup_primary_bucket::<N>(name);
        let displacement = self.displacements[bucket];
        let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
        let index = self.slots[slot];
        (index != BUILTIN_LOOKUP_EMPTY_SLOT).then_some(usize::from(index))
    }

    const fn find_displacement(
        &self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
    ) -> u16 {
        let mut displacement = 0;
        while displacement < BUILTIN_LOOKUP_EMPTY_SLOT {
            if self.displacement_fits(declarations, buckets, bucket, displacement) {
                return displacement;
            }
            displacement += 1;
        }
        panic!("unable to build builtin lookup table");
    }

    const fn displacement_fits(
        &self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
        displacement: u16,
    ) -> bool {
        let mut member_offset = 0;
        while member_offset < buckets.sizes[bucket] {
            let declaration_index = buckets.members[bucket][member_offset] as usize;
            let name = declarations[declaration_index].name();
            let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
            if self.slots[slot] != BUILTIN_LOOKUP_EMPTY_SLOT {
                return false;
            }

            let mut previous_member_offset = 0;
            while previous_member_offset < member_offset {
                let previous_declaration_index =
                    buckets.members[bucket][previous_member_offset] as usize;
                let previous_name = declarations[previous_declaration_index].name();
                let previous_slot = builtin_lookup_secondary_slot::<N>(previous_name, displacement);
                if previous_slot == slot {
                    return false;
                }
                previous_member_offset += 1;
            }
            member_offset += 1;
        }
        true
    }

    const fn place_bucket(
        &mut self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
        displacement: u16,
    ) {
        let mut member_offset = 0;
        while member_offset < buckets.sizes[bucket] {
            let declaration_index = buckets.members[bucket][member_offset] as usize;
            let name = declarations[declaration_index].name();
            let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
            self.slots[slot] = declaration_index as u16;
            member_offset += 1;
        }
    }

    const fn assert_complete(&self) {
        let mut seen = [false; N];
        let mut slot = 0;
        while slot < N {
            let index = self.slots[slot];
            assert!(index != BUILTIN_LOOKUP_EMPTY_SLOT);
            let index = index as usize;
            assert!(index < N);
            assert!(!seen[index]);
            seen[index] = true;
            slot += 1;
        }

        let mut index = 0;
        while index < N {
            assert!(seen[index]);
            index += 1;
        }
    }
}

impl<const N: usize> BuiltinLookupBuckets<N> {
    const fn build(declarations: &[Builtin]) -> Self {
        assert!(declarations.len() == N);
        assert!(declarations.len() <= BUILTIN_LOOKUP_EMPTY_SLOT as usize);

        let mut sizes = [0; N];
        let mut members = [[BUILTIN_LOOKUP_EMPTY_SLOT; N]; N];
        let mut declaration_index = 0;
        while declaration_index < declarations.len() {
            let bucket = builtin_lookup_primary_bucket::<N>(declarations[declaration_index].name());
            let member_offset = sizes[bucket];
            members[bucket][member_offset] = declaration_index as u16;
            sizes[bucket] += 1;
            declaration_index += 1;
        }

        let order = builtin_lookup_bucket_order::<N>(sizes);
        Self {
            sizes,
            members,
            order,
        }
    }
}

const fn builtin_lookup_bucket_order<const N: usize>(bucket_sizes: [usize; N]) -> [usize; N] {
    let mut order = [0; N];
    let mut index = 0;
    while index < N {
        order[index] = index;
        index += 1;
    }

    let mut pass = 0;
    while pass < N {
        let mut index = 1;
        while index < N - pass {
            let left = order[index - 1];
            let right = order[index];
            if bucket_sizes[left] < bucket_sizes[right] {
                order[index - 1] = right;
                order[index] = left;
            }
            index += 1;
        }
        pass += 1;
    }

    order
}

const fn builtin_lookup_primary_bucket<const N: usize>(name: &[u8]) -> usize {
    builtin_lookup_hash(name, BUILTIN_LOOKUP_PRIMARY_SEED) % N
}

const fn builtin_lookup_secondary_slot<const N: usize>(name: &[u8], displacement: u16) -> usize {
    builtin_lookup_hash(name, BUILTIN_LOOKUP_SECONDARY_SEED ^ displacement as u32) % N
}

const fn builtin_lookup_hash(name: &[u8], seed: u32) -> usize {
    let mut hash = seed;
    let mut index = 0;
    while index < name.len() {
        hash ^= name[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash as usize
}
