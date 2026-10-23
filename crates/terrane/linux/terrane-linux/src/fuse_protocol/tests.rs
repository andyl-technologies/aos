//! Exercises complete-record boundaries without opening a kernel connection.

use super::{Error, Reply, Request, error_reply, reply};
use std::num::NonZeroU64;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn packet(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(&((40 + body.len()) as u32).to_ne_bytes());
    bytes[4..8].copy_from_slice(&0xfedc_ba98_u32.to_ne_bytes());
    bytes[8..16].copy_from_slice(&0x1122_3344_5566_7788_u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&0x8877_6655_4433_2211_u64.to_ne_bytes());
    bytes[24..28].copy_from_slice(&840_u32.to_ne_bytes());
    bytes[28..32].copy_from_slice(&845_u32.to_ne_bytes());
    bytes[32..36].copy_from_slice(&1234_u32.to_ne_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn preserves_unknown_operations_and_original_request_bytes() -> Result {
    let bytes = packet(b"raw body\xff");
    let request = Request::parse(&bytes, bytes.len())?;

    assert_eq!(request.opcode(), 0xfedc_ba98);
    assert_eq!(request.unique(), 0x1122_3344_5566_7788);
    assert_eq!(request.node(), 0x8877_6655_4433_2211);
    assert_eq!(
        (request.uid(), request.gid(), request.pid()),
        (840, 845, 1234)
    );
    assert_eq!(request.body(), b"raw body\xff");
    assert_eq!(request.body().as_ptr(), bytes[40..].as_ptr());
    Ok(())
}

#[test]
fn rejects_every_truncated_header_and_inconsistent_record_length() {
    let bytes = packet(b"body");
    for length in 0..bytes.len() {
        assert!(matches!(
            Request::parse(&bytes[..length], 1024),
            Err(Error::Encoding)
        ));
    }

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        Request::parse(&trailing, 1024),
        Err(Error::Encoding)
    ));

    let concatenated = [bytes.clone(), bytes].concat();
    assert!(matches!(
        Request::parse(&concatenated, 1024),
        Err(Error::Encoding)
    ));
}

#[test]
fn refuses_unnegotiated_extensions_and_reserved_padding() {
    let mut bytes = packet(b"name\0");
    bytes[36..38].copy_from_slice(&1_u16.to_ne_bytes());
    assert!(matches!(
        Request::parse(&bytes, 1024),
        Err(Error::Extensions)
    ));

    bytes[36..38].fill(0);
    bytes[38] = 1;
    assert!(matches!(Request::parse(&bytes, 1024), Err(Error::Encoding)));
}

#[test]
fn enforces_explicit_record_limits_and_keeps_zero_identifiers() -> Result {
    let mut bytes = packet(b"body");
    for limit in [0, 39, bytes.len() - 1] {
        assert!(matches!(Request::parse(&bytes, limit), Err(Error::Limit)));
    }
    if let Some(limit) = (u32::MAX as usize).checked_add(1) {
        assert!(matches!(Request::parse(&bytes, limit), Err(Error::Limit)));
    }

    bytes[8..24].fill(0);
    let request = Request::parse(&bytes, bytes.len())?;
    assert_eq!((request.unique(), request.node()), (0, 0));
    Ok(())
}

#[test]
fn body_fields_refuse_overflow_and_truncation() -> Result {
    let bytes = packet(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let request = Request::parse(&bytes, 1024)?;
    assert_eq!(request.body_u32(1)?, u32::from_ne_bytes([2, 3, 4, 5]));
    assert_eq!(
        request.body_u64(1)?,
        u64::from_ne_bytes([2, 3, 4, 5, 6, 7, 8, 9])
    );

    assert_eq!(request.body_u32(6), Err(Error::Encoding));
    assert_eq!(request.body_u64(2), Err(Error::Encoding));
    assert_eq!(request.body_u32(usize::MAX), Err(Error::Encoding));
    assert_eq!(request.body_u64(usize::MAX), Err(Error::Encoding));
    Ok(())
}

#[test]
fn filename_validation_preserves_bytes_and_namespace_dot_components() -> Result {
    for name in [b"ordinary".as_slice(), b"\xff", b".", b".."] {
        let bytes = packet(&[b"prefix".as_slice(), name, &[0]].concat());
        let request = Request::parse(&bytes, 1024)?;
        assert_eq!(request.name(6, name.len())?, name);
        assert_eq!(request.name(6, 0), Err(Error::Limit));
        assert_eq!(request.name(6, name.len() - 1), Err(Error::Limit));
    }
    Ok(())
}

#[test]
fn filename_validation_refuses_unterminated_trailing_or_multiple_names() -> Result {
    for body in [b"".as_slice(), b"\0", b"name", b"a/b\0", b"a\0b\0", b"a\0b"] {
        let bytes = packet(body);
        let request = Request::parse(&bytes, 1024)?;
        assert_eq!(request.name(0, 255), Err(Error::Encoding));
        assert_eq!(request.name(usize::MAX, 255), Err(Error::Encoding));
    }
    Ok(())
}

#[test]
fn successful_reply_does_not_expose_unused_output_capacity() -> Result {
    let mut output = [0xa5; 64];
    let unique = NonZeroU64::new(77).ok_or("invalid response identifier")?;
    let encoded = reply(&mut output, unique, b"actual result")?;

    assert_eq!(encoded.len(), 29);
    assert_eq!(&encoded[..4], &29_u32.to_ne_bytes());
    assert_eq!(&encoded[4..8], &[0; 4]);
    assert_eq!(&encoded[8..16], &77_u64.to_ne_bytes());
    assert_eq!(&encoded[16..], b"actual result");
    assert_eq!(&output[29..], &[0xa5; 35]);
    Ok(())
}

#[test]
fn errno_reply_uses_kernel_sign_and_never_contains_payload() -> Result {
    let mut output = [0xa5; 64];
    let unique = NonZeroU64::new(99).ok_or("invalid response identifier")?;
    let encoded = error_reply(&mut output, unique, libc::ENOTCONN)?;

    assert_eq!(encoded.len(), 16);
    assert_eq!(&encoded[..4], &16_u32.to_ne_bytes());
    assert_eq!(&encoded[4..8], &(-libc::ENOTCONN).to_ne_bytes());
    assert_eq!(&encoded[8..16], &99_u64.to_ne_bytes());
    assert_eq!(&output[16..], &[0xa5; 48]);
    Ok(())
}

#[test]
fn refused_reply_leaves_original_output_unchanged() -> Result {
    let unique = NonZeroU64::new(1).ok_or("invalid response identifier")?;
    let mut output = [0xa5; 16];
    assert_eq!(reply(&mut output, unique, b"too large"), Err(Error::Limit));
    assert_eq!(output, [0xa5; 16]);

    for errno in [i32::MIN, -1, 0, 4096, i32::MAX] {
        assert_eq!(
            error_reply(&mut output, unique, errno),
            Err(Error::Encoding)
        );
        assert_eq!(output, [0xa5; 16]);
    }
    assert_eq!(
        error_reply(&mut output[..15], unique, libc::EIO),
        Err(Error::Limit)
    );
    assert_eq!(output, [0xa5; 16]);
    Ok(())
}

#[test]
fn checked_reply_preserves_identifier_and_signed_error() -> Result {
    let unique = NonZeroU64::new(33).ok_or("invalid response identifier")?;
    let mut output = [0; 64];
    let bytes = reply(&mut output, unique, b"response")?;
    let checked = Reply::parse(bytes, bytes.len())?;
    assert_eq!(checked.unique(), unique);
    assert_eq!(checked.errno(), None);
    assert_eq!(checked.as_bytes().as_ptr(), bytes.as_ptr());

    let bytes = error_reply(&mut output, unique, libc::EIO)?;
    let checked = Reply::parse(bytes, 64)?;
    assert_eq!(checked.unique(), unique);
    assert_eq!(checked.errno(), Some(libc::EIO));
    Ok(())
}

#[test]
fn checked_reply_refuses_notification_identifiers_and_error_payloads() -> Result {
    let unique = NonZeroU64::new(33).ok_or("invalid response identifier")?;
    let mut output = [0; 64];
    let mut bytes = reply(&mut output, unique, b"payload")?.to_vec();
    bytes[4..8].copy_from_slice(&(-libc::EIO).to_ne_bytes());
    assert!(matches!(Reply::parse(&bytes, 64), Err(Error::Encoding)));

    let mut bytes = error_reply(&mut output, unique, libc::EIO)?.to_vec();
    for error in [i32::MIN, -4096, 1, i32::MAX] {
        bytes[4..8].copy_from_slice(&error.to_ne_bytes());
        assert!(matches!(Reply::parse(&bytes, 64), Err(Error::Encoding)));
    }
    bytes[4..8].fill(0);
    bytes[8..16].fill(0);
    assert!(matches!(Reply::parse(&bytes, 64), Err(Error::Encoding)));
    Ok(())
}

#[test]
fn checked_reply_requires_a_complete_bounded_record() -> Result {
    let unique = NonZeroU64::new(33).ok_or("invalid response identifier")?;
    let mut output = [0; 64];
    let bytes = reply(&mut output, unique, b"payload")?;
    for length in 0..bytes.len() {
        assert!(matches!(
            Reply::parse(&bytes[..length], 64),
            Err(Error::Encoding)
        ));
    }
    for maximum in [0, 15, bytes.len() - 1] {
        assert!(matches!(Reply::parse(bytes, maximum), Err(Error::Limit)));
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(Reply::parse(&trailing, 64), Err(Error::Encoding)));
    Ok(())
}
