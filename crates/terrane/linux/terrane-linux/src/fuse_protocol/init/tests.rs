//! Checks version fallback, capability intersection and exact INIT bounds.

#![allow(clippy::unwrap_used)]

use super::*;

fn limits() -> Limits {
    Limits {
        request_bytes: 262144,
        readahead_bytes: 65536,
        background_requests: 8,
    }
}

fn offer(major: u32, minor: u32, flags: u32, flags2: u32) -> Vec<u8> {
    let length = if minor >= 36 && flags & EXTENDED != 0 {
        104
    } else {
        56
    };
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    bytes[4..8].copy_from_slice(&26_u32.to_ne_bytes());
    bytes[8..16].copy_from_slice(&1_u64.to_ne_bytes());
    bytes[40..44].copy_from_slice(&major.to_ne_bytes());
    bytes[44..48].copy_from_slice(&minor.to_ne_bytes());
    bytes[48..52].copy_from_slice(&131072_u32.to_ne_bytes());
    bytes[52..56].copy_from_slice(&flags.to_ne_bytes());
    if length == 104 {
        bytes[56..60].copy_from_slice(&flags2.to_ne_bytes());
    }
    bytes
}

fn run(bytes: &[u8], policy: Passthrough, ready: bool) -> Result<Initialization, Error> {
    negotiate(
        Request::parse(bytes, 262144).unwrap(),
        limits(),
        policy,
        ready,
    )
}

fn field(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn selects_only_implemented_capabilities_with_bounded_native_fields() {
    let bytes = offer(7, 45, !(1 << 31), u32::MAX);
    let response = run(&bytes, Passthrough::Require, true).unwrap();

    assert_eq!(response.selected(), Some((40, true)));
    let mut expected = [0; 64];
    put(&mut expected, 0, 7);
    put(&mut expected, 4, 40);
    put(&mut expected, 8, 65536);
    expected[16..18].copy_from_slice(&8_u16.to_ne_bytes());
    expected[18..20].copy_from_slice(&4_u16.to_ne_bytes());
    put(&mut expected, 20, 131072);
    put(&mut expected, 24, 1);
    put(&mut expected, 32, PASSTHROUGH | NO_EXPORT);
    put(&mut expected, 36, 1);
    assert_eq!(response.body(), expected);
}

#[test]
fn requires_both_local_and_kernel_passthrough_support() {
    for (minor, flags, flags2, ready) in [
        (40, EXTENDED, PASSTHROUGH, false),
        (40, EXTENDED, 0, true),
        (40, 0, 0, true),
        (39, EXTENDED, PASSTHROUGH, true),
    ] {
        let bytes = offer(7, minor, flags, flags2);
        assert_eq!(
            run(&bytes, Passthrough::Require, ready).unwrap_err(),
            Error::PassthroughUnavailable,
        );
        let fallback = run(&bytes, Passthrough::Auto, ready).unwrap();
        assert_eq!(fallback.selected(), Some((minor, false)));
        assert_eq!(field(fallback.body(), 32) & PASSTHROUGH, 0);
        assert_eq!(field(fallback.body(), 36), 0);
    }
}

#[test]
fn off_never_enables_offered_passthrough_or_writeback() {
    let bytes = offer(7, 40, EXTENDED | (1 << 16), PASSTHROUGH | NO_EXPORT);
    let response = run(&bytes, Passthrough::Off, true).unwrap();

    assert_eq!(response.selected(), Some((40, false)));
    assert_eq!(field(response.body(), 12), 0);
    assert_eq!(field(response.body(), 32), NO_EXPORT);
    assert_eq!(field(response.body(), 36), 0);
}

#[test]
fn negotiates_older_supported_read_protocols_without_extensions() {
    for minor in [31, 35, 36, 39] {
        let bytes = offer(7, minor, 0, 0);
        let response = run(&bytes, Passthrough::Auto, true).unwrap();

        assert_eq!(response.selected(), Some((minor, false)));
        assert_eq!(field(response.body(), 4), minor);
        assert_eq!(field(response.body(), 32), 0);
    }
    for (major, minor) in [(6, 40), (7, 30)] {
        assert_eq!(
            run(&offer(major, minor, 0, 0), Passthrough::Off, false).unwrap_err(),
            Error::Version
        );
    }
}

#[test]
fn newer_major_retries_without_interpreting_foreign_body() {
    let mut bytes = offer(8, 0, 0, 0);
    bytes.truncate(44);
    bytes[..4].copy_from_slice(&44_u32.to_ne_bytes());
    let response = run(&bytes, Passthrough::Require, false).unwrap();

    assert_eq!(response.selected(), None);
    assert_eq!(response.body().len(), 8);
    assert_eq!(field(response.body(), 0), 7);
    assert_eq!(field(response.body(), 4), 40);
}

#[test]
fn refuses_non_init_headers_truncation_reserved_data_and_extra_body() {
    for (offset, value) in [(4, 3_u64), (8, 0), (16, 1)] {
        let mut bytes = offer(7, 40, EXTENDED, 0);
        bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_ne_bytes());
        assert_eq!(
            run(&bytes, Passthrough::Off, false).unwrap_err(),
            Error::Encoding
        );
    }
    for length in [40, 43, 44, 47, 48, 55, 56, 60, 103, 105] {
        let mut bytes = offer(7, 40, EXTENDED, 0);
        bytes.resize(length, 0);
        bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        assert_eq!(
            run(&bytes, Passthrough::Off, false).unwrap_err(),
            Error::Encoding
        );
    }
    for offset in 60..104 {
        let mut bytes = offer(7, 40, EXTENDED, 0);
        bytes[offset] = 1;
        assert_eq!(
            run(&bytes, Passthrough::Off, false).unwrap_err(),
            Error::Encoding
        );
    }
    let mut bytes = offer(7, 40, 0, 0);
    bytes.resize(104, 0);
    bytes[..4].copy_from_slice(&104_u32.to_ne_bytes());
    assert_eq!(
        run(&bytes, Passthrough::Off, false).unwrap_err(),
        Error::Encoding
    );
}

#[test]
fn caps_device_write_size_and_readahead_without_buffer_growth() {
    let bytes = offer(7, 40, EXTENDED, 0);
    let request = Request::parse(&bytes, 262144).unwrap();
    let limits = Limits {
        request_bytes: 8192,
        readahead_bytes: 1,
        background_requests: 1,
    };
    let response = negotiate(request, limits, Passthrough::Off, false).unwrap();

    assert_eq!(field(response.body(), 8), 1);
    assert_eq!(field(response.body(), 20), 4096);
    assert_eq!(&response.body()[16..18], &1_u16.to_ne_bytes());
    assert_eq!(&response.body()[18..20], &1_u16.to_ne_bytes());
    for limits in [
        Limits {
            request_bytes: 8191,
            ..limits
        },
        Limits {
            background_requests: 0,
            ..limits
        },
    ] {
        assert_eq!(
            negotiate(request, limits, Passthrough::Off, false).unwrap_err(),
            Error::Limit
        );
    }
}
