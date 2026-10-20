//! Computes the fixed guest answer independently of observed native output.

/// Applies the source assembly's aligned XOR/add loop with exact register widths.
pub(super) fn expected_output() -> [u8; 8] {
    let mut arena = [0_u64; 262_144 / 8];
    let mut generator = 3_u32;
    let mut checksum = 0_u64;

    for _ in 0..20_000 {
        generator = generator
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        let index = ((generator & 262_136) / 8) as usize;
        arena[index] ^= u64::from(generator);
        checksum = checksum.wrapping_add(arena[index]);

        if generator & 1 != 0 {
            checksum = checksum.wrapping_add(19);
        }
    }

    checksum.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::expected_output;

    #[test]
    fn fixed_guest_uses_exact_register_widths_and_little_endian_store() {
        // This literal is derived from the source-only sparse mathematical
        // model, independently of any native execution or observed payload.
        assert_eq!(
            expected_output(),
            [0x62, 0x8d, 0xd9, 0xd1, 0xd2, 0x26, 0x00, 0x00]
        );
    }
}
