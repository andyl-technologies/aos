//! Caller-owned framing capacity and canonical transport refusal controls.

use super::*;

#[test]
fn caller_storage_refuses_every_short_extent_without_touching_guards() {
    let request = frame(
        2,
        RamControlRequest::Apply {
            expected_revision: 1,
            policy_revision: 2,
            reservation_revision: 3,
            resources: RamControlResources::default(),
            policy: policy(),
        },
    );
    let canonical = encode_ram_control(&request).expect("canonical Apply");

    for capacity in 0..canonical.len() {
        let mut storage = [0xa5; RAM_CONTROL_MAX_BYTES + 2];
        let result = encode_ram_control_into(&request, &mut storage[1..capacity + 1]);

        assert!(matches!(result, Err(RamControlError::TooLarge)));
        assert_eq!(storage[0], 0xa5);
        assert!(storage[capacity + 1..].iter().all(|&byte| byte == 0xa5));
    }

    let mut storage = [0xa5; RAM_CONTROL_MAX_BYTES + 2];
    let length = encode_ram_control_into(&request, &mut storage[1..canonical.len() + 1])
        .expect("exact body storage");

    assert_eq!(length, canonical.len());
    assert_eq!(&storage[1..length + 1], canonical.as_slice());
    assert_eq!(storage[0], 0xa5);
    assert!(storage[length + 1..].iter().all(|&byte| byte == 0xa5));
    assert_eq!(
        decode_ram_control(&storage[1..length + 1]).unwrap(),
        request
    );
}

#[test]
fn fixed_stream_writer_does_not_publish_an_invalid_body_prefix() {
    let request = frame(
        2,
        RamControlRequest::Apply {
            expected_revision: 1,
            policy_revision: 3,
            reservation_revision: 3,
            resources: RamControlResources::default(),
            policy: policy(),
        },
    );
    let mut transport = Vec::new();

    assert!(write_ram_control(&mut transport, &request).is_err());
    assert!(transport.is_empty());
}

#[test]
fn fixed_stream_and_digest_preserve_the_existing_canonical_body() {
    let request = frame(1, RamControlRequest::Hello);
    let canonical = encode_ram_control(&request).expect("canonical Hello");
    let mut expected_digest = blake3::Hasher::new();
    expected_digest.update(b"crucible.ram.control.request.v1\0");
    expected_digest.update(&canonical);
    let mut transport = Vec::new();

    write_ram_control(&mut transport, &request).expect("canonical transport");

    assert_eq!(&transport[..4], &(canonical.len() as u32).to_be_bytes());
    assert_eq!(&transport[4..], canonical.as_slice());
    assert_eq!(
        ram_control_request_digest(&request).unwrap(),
        *expected_digest.finalize().as_bytes()
    );
}
