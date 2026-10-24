//! Pure kernel-text and admission-threshold vectors, without live ownership.
//!
//! These tests never open procfs, mint startup, reserve capacity, authenticate a
//! PID1 owner or construct a transport. All runtime observation is separate.

use super::*;

const SAMPLE: &[u8] = b"MemTotal:       4194304 kB\nMemFree:         524288 kB\nMemAvailable:   2097152 kB\nHugePages_Total: 0\n";

#[test]
fn ordinary_kernel_padding_and_unrelated_counts_preserve_selected_bytes() {
    let sample = parse_meminfo(SAMPLE).unwrap();

    assert_eq!(sample.total_bytes, 4 * 1024 * 1024 * 1024);
    assert_eq!(sample.available_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(sample.require_minimum(2 * 1024 * 1024 * 1024), Ok(()));
}

#[test]
fn observation_is_data_and_below_minimum_refuses_admission() {
    let sample = parse_meminfo(SAMPLE).unwrap();

    assert_eq!(
        sample.require_minimum(sample.available_bytes + 1),
        Err(Error::NodeMemoryPressure),
    );
    // Successful DATA comparison makes no claim about a later allocation.
    assert_eq!(sample.require_minimum(sample.available_bytes), Ok(()));
}

#[test]
fn zero_available_is_valid_observation_but_not_positive_minimum_admission() {
    let sample = parse_meminfo(b"MemTotal: 1024 kB\nMemAvailable: 0 kB\n").unwrap();

    assert_eq!(sample.available_bytes, 0);
    assert_eq!(sample.require_minimum(1), Err(Error::NodeMemoryPressure));
}

#[test]
fn selected_fields_refuse_missing_and_duplicates_in_either_order() {
    for bytes in [
        &b"MemTotal: 1024 kB\n"[..],
        &b"MemAvailable: 1024 kB\n"[..],
        &b"MemTotal: 1024 kB\nMemTotal: 1024 kB\nMemAvailable: 512 kB\n"[..],
        &b"MemAvailable: 512 kB\nMemTotal: 1024 kB\nMemAvailable: 512 kB\n"[..],
    ] {
        assert_eq!(parse_meminfo(bytes), Err(Error::NodeMemoryObservation));
    }

    assert_eq!(
        parse_meminfo(b"MemAvailable: 512 kB\nMemTotal: 1024 kB\n").unwrap(),
        NodeMemorySample {
            total_bytes: 1024 * 1024,
            available_bytes: 512 * 1024,
        },
    );
}

#[test]
fn source_text_refuses_truncation_non_ascii_nul_and_malformed_lines() {
    for bytes in [
        &b""[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB"[..],
        &b"MemTotal: 1024 kB\r\nMemAvailable: 512 kB\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB\nExtra: \0\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB\nExtra: \xff\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB\nunterminated-field\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB\n: 1\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 512 kB\nEmpty:\n"[..],
    ] {
        assert_eq!(parse_meminfo(bytes), Err(Error::NodeMemoryObservation));
    }
}

#[test]
fn byte_bound_includes_complete_input_and_never_accepts_the_sentinel() {
    let mut boundary = SAMPLE.to_vec();
    boundary.extend_from_slice(b"Other:");
    boundary.resize(MAXIMUM_MEMINFO_BYTES - 1, b'1');
    boundary.push(b'\n');

    assert_eq!(parse_meminfo(&boundary), parse_meminfo(SAMPLE));
    boundary.push(b'\n');
    assert_eq!(parse_meminfo(&boundary), Err(Error::NodeMemoryObservation));
}

#[test]
fn units_and_unsigned_decimal_are_exact_without_normalizing_foreign_numbers() {
    for value in [
        "1 B", "1 KB", "1 KiB", "1", "1 kB extra", "-1 kB", "+1 kB", "01 kB", "0x1 kB",
        "1.0 kB", "kB", "one kB",
    ] {
        assert_eq!(
            parse_kibibytes(value),
            Err(Error::NodeMemoryObservation),
            "{value}",
        );
    }

    assert_eq!(parse_kibibytes("\t 1   kB  "), Ok(1024));
    assert_eq!(parse_kibibytes("0 kB"), Ok(0));
}

#[test]
fn decimal_and_kibibyte_conversion_overflows_are_checked() {
    assert_eq!(parse_kibibytes("18014398509481983 kB"), Ok(u64::MAX - 1023));
    for value in ["18014398509481984 kB", "18446744073709551616 kB"] {
        assert_eq!(parse_kibibytes(value), Err(Error::NodeMemoryObservation));
    }
}

#[test]
fn impossible_total_and_available_geometry_is_rejected() {
    for bytes in [
        &b"MemTotal: 0 kB\nMemAvailable: 0 kB\n"[..],
        &b"MemTotal: 1024 kB\nMemAvailable: 1025 kB\n"[..],
    ] {
        assert_eq!(parse_meminfo(bytes), Err(Error::NodeMemoryObservation));
    }
}
