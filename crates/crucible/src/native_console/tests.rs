//! Closed canonical encoding controls independent of physical transport.

use super::*;

pub(super) fn origin() -> NativeConsoleByteOrigin {
    NativeConsoleByteOrigin {
        device: ContentHash { bytes: [9; 32] },
        stream: 7,
        logical_generation: 3,
        node_sequence: 1,
        stream_sequence: 1,
        emitted_ps: 50,
        raw_prefix: 1,
        vcpu: 0,
        byte: 0xff,
    }
}

#[test]
fn native_console_origin_roundtrip_preserves_every_logical_field()
-> Result<(), NativeConsoleOriginError> {
    let original = origin();
    let bytes = original.to_canonical_bytes()?;
    assert_eq!(&bytes[..8], b"NCLOG001");
    assert_eq!(&bytes[8..40], &[9; 32]);
    assert_eq!(&bytes[40..44], &7_u32.to_le_bytes());
    assert_eq!(&bytes[68..76], &50_u64.to_le_bytes());
    assert_eq!(&bytes[76..84], &1_u64.to_le_bytes());
    assert_eq!(bytes[88], 0xff);
    assert_eq!(&bytes[89..], &[0; 7]);
    assert_eq!(
        NativeConsoleByteOrigin::from_canonical_bytes(&bytes)?,
        original
    );
    Ok(())
}

#[test]
fn native_console_origin_refuses_alternate_framing_and_missing_identity()
-> Result<(), NativeConsoleOriginError> {
    let bytes = origin().to_canonical_bytes()?;
    assert!(NativeConsoleByteOrigin::from_canonical_bytes(&bytes[..95]).is_err());
    for offset in [0, 89, 95] {
        let mut altered = bytes;
        altered[offset] ^= 1;
        assert!(NativeConsoleByteOrigin::from_canonical_bytes(&altered).is_err());
    }
    for field in 0..5 {
        let mut altered = origin();
        match field {
            0 => altered.device.bytes = [0; 32],
            1 => altered.stream = 0,
            2 => altered.node_sequence = 0,
            3 => altered.stream_sequence = 0,
            _ => altered.vcpu = 64,
        }
        assert!(altered.to_canonical_bytes().is_err());
    }
    Ok(())
}

#[test]
fn native_console_origin_changed_raw_or_logical_origin_changes_canonical_material()
-> Result<(), NativeConsoleOriginError> {
    let original = origin().to_canonical_bytes()?;
    for field in 0..9 {
        let mut altered = origin();
        match field {
            0 => altered.device.bytes[0] ^= 1,
            1 => altered.stream += 1,
            2 => altered.logical_generation += 1,
            3 => altered.node_sequence += 1,
            4 => altered.stream_sequence += 1,
            5 => altered.emitted_ps += 1,
            6 => altered.raw_prefix += 1,
            7 => altered.vcpu += 1,
            _ => altered.byte ^= 1,
        }
        assert_ne!(altered.to_canonical_bytes()?, original);
    }
    Ok(())
}
