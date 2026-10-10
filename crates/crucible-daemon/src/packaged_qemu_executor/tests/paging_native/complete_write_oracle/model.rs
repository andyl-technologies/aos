//! Independent instruction-count and full-window CPU writer oracle.
//!
//! The input is the authored profile and actual stopped raw coordinate, never
//! the guest counter or the native dirty bitmap. The failed CAS target remains
//! unchanged, and its actual returned value/ZF witness is checked separately.

mod extended;

const STARTUP: u64 = 2062;
const SEED: u32 = 0x51f1_5eed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Store,
    Exchange,
    CompareExchange64,
    FailedCompareExchange32,
    Vector128,
    LockedAdd,
    CompoundTwoStore,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Profile {
    pub name: &'static str,
    pub operation: Operation,
    pub offset: usize,
    pub width: usize,
    pub body_instructions: u64,
}

// Successful profiles retain progress only in EBP, so neither cross-page half
// can be covered by an unrelated loop store. Failed-CAS witnesses and its
// ordinary counter stay in page one; they make no hardware dirty/no-write claim.
pub(super) const PROFILES: [Profile; 28] = [
    Profile::new("scalar8", Operation::Store, 4160, 1, 1),
    Profile::new("scalar16", Operation::Store, 4160, 2, 1),
    Profile::new("scalar32", Operation::Store, 4160, 4, 1),
    Profile::new("unaligned32", Operation::Store, 4163, 4, 1),
    Profile::new("cross-page32", Operation::Store, 4093, 4, 1),
    Profile::new("exchange8", Operation::Exchange, 4160, 1, 1),
    Profile::new("exchange16", Operation::Exchange, 4160, 2, 1),
    Profile::new("exchange32", Operation::Exchange, 4160, 4, 1),
    Profile::new("unaligned-exchange32", Operation::Exchange, 4163, 4, 1),
    Profile::new("cross-page-exchange32", Operation::Exchange, 4093, 4, 1),
    Profile::new(
        "compare-exchange64",
        Operation::CompareExchange64,
        4224,
        8,
        5,
    ),
    Profile::new(
        "failed-compare-exchange32",
        Operation::FailedCompareExchange32,
        4224,
        4,
        6,
    ),
    Profile::new("vector128", Operation::Vector128, 4224, 16, 3),
    Profile::new("unaligned-vector128", Operation::Vector128, 4227, 16, 3),
    Profile::new("cross-page-vector128", Operation::Vector128, 4089, 16, 3),
    Profile::new("locked-add8", Operation::LockedAdd, 4160, 1, 1),
    Profile::new("locked-add16", Operation::LockedAdd, 4160, 2, 1),
    Profile::new("locked-add32", Operation::LockedAdd, 4160, 4, 1),
    Profile::new("unaligned-locked-add32", Operation::LockedAdd, 4163, 4, 1),
    Profile::new("cross-page-locked-add32", Operation::LockedAdd, 4093, 4, 1),
    Profile::new("locked-xadd32", Operation::LockedAdd, 4160, 4, 1),
    Profile::new("unaligned-locked-xadd32", Operation::LockedAdd, 4163, 4, 1),
    Profile::new("cross-page-locked-xadd32", Operation::LockedAdd, 4093, 4, 1),
    Profile::new(
        "successful-compare-exchange32",
        Operation::Store,
        4224,
        4,
        3,
    ),
    Profile::new(
        "cross-page-successful-compare-exchange32",
        Operation::Store,
        4093,
        4,
        3,
    ),
    Profile::new(
        "unaligned-compare-exchange64",
        Operation::CompareExchange64,
        4227,
        8,
        5,
    ),
    Profile::new(
        "cross-page-compare-exchange64",
        Operation::CompareExchange64,
        4093,
        8,
        5,
    ),
    Profile::new(
        "compound-two-store32",
        Operation::CompoundTwoStore,
        4088,
        20,
        3,
    ),
];

impl Profile {
    const fn new(
        name: &'static str,
        operation: Operation,
        offset: usize,
        width: usize,
        body_instructions: u64,
    ) -> Self {
        Self {
            name,
            operation,
            offset,
            width,
            body_instructions,
        }
    }

    pub(super) fn selected() -> Self {
        let name = std::env::var("CRUCIBLE_COMPLETE_WRITE_ORACLE_CASE")
            .expect("explicit closed CPU writer profile required");
        *PROFILES
            .iter()
            .find(|profile| profile.name == name)
            .expect("unknown CPU writer profile")
    }

    pub(super) fn expected(&self, raw: u64) -> Expected {
        let elapsed = raw.checked_sub(STARTUP).expect("writer startup completed");
        let loop_length = 7 + self.body_instructions;
        let completed = elapsed / loop_length;
        let partial = elapsed % loop_length;
        let mut accumulator = SEED;
        for _ in 0..completed {
            accumulator = mix(accumulator);
        }
        let previous = accumulator;
        if partial >= 1 {
            accumulator = accumulator.rotate_left(13);
        }
        if partial >= 2 {
            accumulator ^= 0x9e37_79b9;
        }
        if partial >= 3 {
            accumulator = accumulator.wrapping_add(0x6d2b_79f5);
        }

        let mut arena = vec![0x35; 8192];
        if matches!(
            self.operation,
            Operation::LockedAdd | Operation::CompoundTwoStore
        ) {
            extended::apply(self, completed, partial, &mut arena);
        } else if self.operation != Operation::FailedCompareExchange32 {
            let write_cut = 4 + self.body_instructions;
            let stored = if partial >= write_cut {
                Some(accumulator)
            } else if completed > 0 {
                Some(previous)
            } else {
                None
            };
            if let Some(value) = stored {
                for (index, byte) in arena[self.offset..self.offset + self.width]
                    .iter_mut()
                    .enumerate()
                {
                    *byte = value.to_le_bytes()[index % 4];
                }
            }
        } else {
            // CMPXCHG compares zero against 0x35353535, so it must return the
            // old value with ZF clear and preserve the target on every turn.
            if completed > 0 || partial >= 8 {
                arena[256..260].copy_from_slice(&0x3535_3535_u32.to_le_bytes());
            }
            if completed > 0 || partial >= 10 {
                arena[260] = 0;
            }
        }
        let increment_cut = 5 + self.body_instructions;
        let counter = u32::try_from(completed).expect("fixed horizon fits counter")
            + u32::from(partial >= increment_cut);
        if self.operation == Operation::FailedCompareExchange32
            && (completed > 0 || partial > increment_cut)
        {
            let stored_counter = u32::try_from(completed).expect("fixed horizon fits counter")
                + u32::from(partial > increment_cut);
            arena[16..20].copy_from_slice(&stored_counter.to_le_bytes());
        }
        Expected {
            arena,
            accumulator,
            counter,
        }
    }

    pub(super) fn require(&self, observed: &crucible_qemu::QemuCpuWriteObservation, raw: u64) {
        assert_eq!(
            PROFILES
                .get(observed.profile_index as usize)
                .map(|profile| profile.name),
            Some(self.name),
            "actual selected firmware identity; instruction manifest remains separately artifact-bound"
        );
        let expected = self.expected(raw);
        assert_eq!(
            observed.arena, expected.arena,
            "independent whole-two-page oracle: {}",
            self.name
        );
        for (name, value) in [("ESI", expected.accumulator), ("EBP", expected.counter)] {
            assert_eq!(
                observed_register(observed, name),
                Some(value),
                "independent stopped register: {name}"
            );
        }
    }

    pub(super) fn observed_counter(
        &self,
        observed: &crucible_qemu::QemuCpuWriteObservation,
    ) -> u32 {
        observed_register(observed, "EBP").expect("actual stopped progress register")
    }
}

fn observed_register(observed: &crucible_qemu::QemuCpuWriteObservation, name: &str) -> Option<u32> {
    observed.registers.split_whitespace().find_map(|field| {
        let (field_name, encoded) = field.split_once('=')?;
        (field_name == name)
            .then(|| u32::from_str_radix(encoded, 16).ok())
            .flatten()
    })
}

fn mix(value: u32) -> u32 {
    (value.rotate_left(13) ^ 0x9e37_79b9).wrapping_add(0x6d2b_79f5)
}

pub(super) struct Expected {
    pub arena: Vec<u8>,
    pub accumulator: u32,
    pub counter: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_operations_have_no_other_loop_store_on_either_target_page() {
        for profile in PROFILES {
            let observed = profile.expected(700_000);
            let second_page = &observed.arena[4096..];
            if profile.operation == Operation::FailedCompareExchange32 {
                assert!(second_page.iter().all(|byte| *byte == 0x35));
            } else {
                assert!(profile.offset + profile.width > 4096);
                assert_eq!(&observed.arena[16..20], &[0x35; 4]);
                assert_eq!(&observed.arena[256..261], &[0x35; 5]);
                assert!(second_page.iter().any(|byte| *byte != 0x35));
            }
        }
    }

    #[test]
    fn cross_page_store_changes_both_pages_and_only_its_authored_range() {
        let profile = PROFILES[4];
        let before = profile.expected(STARTUP + 4);
        let after = profile.expected(STARTUP + 5);
        assert!(before.arena.iter().all(|byte| *byte == 0x35));
        assert_eq!(&after.arena[4093..4097], &mix(SEED).to_le_bytes());
        assert!(after.arena[..4093].iter().all(|byte| *byte == 0x35));
        assert!(after.arena[4097..].iter().all(|byte| *byte == 0x35));
    }

    #[test]
    fn vector_and_atomic_widths_have_independent_partial_write_cuts() {
        for index in [10, 12, 13, 14] {
            let profile = PROFILES[index];
            let write_cut = STARTUP + 4 + profile.body_instructions;
            assert!(
                profile
                    .expected(write_cut - 1)
                    .arena
                    .iter()
                    .all(|byte| *byte == 0x35)
            );
            let after = profile.expected(write_cut);
            for (index, byte) in after.arena[profile.offset..profile.offset + profile.width]
                .iter()
                .enumerate()
            {
                assert_eq!(*byte, mix(SEED).to_le_bytes()[index % 4]);
            }
        }
    }

    #[test]
    fn failed_compare_exchange_preserves_target_and_requires_returned_value_and_flag() {
        let profile = PROFILES[11];
        let observed = profile.expected(1_400_000);
        assert_eq!(
            &observed.arena[profile.offset..profile.offset + profile.width],
            &[0x35; 4]
        );
        assert_eq!(&observed.arena[256..260], &0x3535_3535_u32.to_le_bytes());
        assert_eq!(observed.arena[260], 0);
        let mut forced_success = observed.arena.clone();
        forced_success[profile.offset..profile.offset + profile.width]
            .copy_from_slice(&observed.accumulator.to_le_bytes());
        assert_ne!(forced_success, observed.arena);
    }

    #[test]
    fn omitted_store_and_corruption_outside_selected_range_are_not_valid_evidence() {
        for profile in PROFILES {
            let observed = profile.expected(700_000);
            let mut omitted = observed.arena.clone();
            if profile.operation != Operation::FailedCompareExchange32 {
                omitted[profile.offset..profile.offset + profile.width].fill(0x35);
                assert_ne!(omitted, observed.arena);
            }
            let mut unrelated = observed.arena.clone();
            unrelated[8191] ^= 1;
            assert_ne!(unrelated, observed.arena);
        }
    }
}
