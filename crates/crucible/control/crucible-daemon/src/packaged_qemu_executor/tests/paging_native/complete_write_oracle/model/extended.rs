//! Independent byte effects for cumulative RMW and separately retired stores.
//!
//! No observed target bytes or dirty notifications enter this model. Arithmetic
//! wraps at the instruction operand width; each compound store has its own cut.

use super::{Operation, Profile, SEED, mix};

pub(super) fn apply(profile: &Profile, completed: u64, partial: u64, arena: &mut [u8]) {
    match profile.operation {
        Operation::LockedAdd => {
            let mut value = SEED;
            let mut total = 0x3535_3535_u32;
            for _ in 0..completed {
                value = mix(value);
                total = total.wrapping_add(value);
            }
            if partial >= 5 {
                total = total.wrapping_add(mix(value));
            }
            arena[profile.offset..profile.offset + profile.width]
                .copy_from_slice(&total.to_le_bytes()[..profile.width]);
        }
        Operation::CompoundTwoStore => {
            let mut value = SEED;
            for _ in 0..completed {
                value = mix(value);
            }
            if completed > 0 {
                arena[4088..4092].copy_from_slice(&value.to_le_bytes());
                arena[4104..4108].copy_from_slice(&(!value).to_le_bytes());
            }
            let next = mix(value);
            if partial >= 5 {
                arena[4088..4092].copy_from_slice(&next.to_le_bytes());
            }
            if partial >= 7 {
                arena[4104..4108].copy_from_slice(&(!next).to_le_bytes());
            }
        }
        _ => unreachable!("only extended byte effects enter this private helper"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PROFILES, STARTUP};
    use super::*;

    #[test]
    fn locked_add_and_xadd_accumulate_at_their_exact_operand_width() {
        for profile in &PROFILES[15..23] {
            let first = mix(SEED);
            let second = mix(first);
            let loop_length = 7 + profile.body_instructions;
            let before = profile.expected(STARTUP + loop_length + 4);
            let after = profile.expected(STARTUP + loop_length + 5);
            let first_sum = 0x3535_3535_u32.wrapping_add(first);
            let second_sum = first_sum.wrapping_add(second);

            assert_eq!(
                &before.arena[profile.offset..profile.offset + profile.width],
                &first_sum.to_le_bytes()[..profile.width]
            );
            assert_eq!(
                &after.arena[profile.offset..profile.offset + profile.width],
                &second_sum.to_le_bytes()[..profile.width]
            );
            assert!(
                after.arena[..profile.offset]
                    .iter()
                    .all(|byte| *byte == 0x35)
            );
            assert!(
                after.arena[profile.offset + profile.width..]
                    .iter()
                    .all(|byte| *byte == 0x35)
            );
        }
    }

    #[test]
    fn compound_stores_have_independent_first_second_and_next_turn_cuts() {
        let profile = PROFILES[27];
        let value = mix(SEED);
        let before = profile.expected(STARTUP + 4);
        let first = profile.expected(STARTUP + 5);
        let between = profile.expected(STARTUP + 6);
        let second = profile.expected(STARTUP + 7);
        assert!(before.arena.iter().all(|byte| *byte == 0x35));
        assert_eq!(&first.arena[4088..4092], &value.to_le_bytes());
        assert_eq!(&first.arena[4104..4108], &[0x35; 4]);
        assert_eq!(between.arena, first.arena);
        assert_eq!(&second.arena[4104..4108], &(!value).to_le_bytes());

        let next_first = profile.expected(STARTUP + 10 + 5);
        assert_eq!(&next_first.arena[4088..4092], &mix(value).to_le_bytes());
        assert_eq!(&next_first.arena[4104..4108], &(!value).to_le_bytes());
        for (index, byte) in next_first.arena.iter().enumerate() {
            if !(4088..4092).contains(&index) && !(4104..4108).contains(&index) {
                assert_eq!(*byte, 0x35);
            }
        }
    }

    #[test]
    fn successful_cas_requires_the_final_memory_instruction_and_full_width() {
        for profile in &PROFILES[23..27] {
            let cut = STARTUP + 4 + profile.body_instructions;
            assert!(
                profile
                    .expected(cut - 1)
                    .arena
                    .iter()
                    .all(|byte| *byte == 0x35)
            );
            let observed = profile.expected(cut);
            for (index, byte) in observed.arena[profile.offset..profile.offset + profile.width]
                .iter()
                .enumerate()
            {
                assert_eq!(*byte, mix(SEED).to_le_bytes()[index % 4]);
            }
        }
    }

    #[test]
    fn omission_of_any_extended_effect_disagrees_with_the_full_window_oracle() {
        for profile in &PROFILES[15..] {
            let expected = profile.expected(700_000);
            assert_ne!(expected.arena, vec![0x35; 8192], "{}", profile.name);
        }
    }
}
