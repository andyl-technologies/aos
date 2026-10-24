//! Exercises strict disposition framing and physical/semantic failure separation.
//!
//! Wire observations in these controls do not issue native terminal authority.

use super::*;

fn binding(epoch: u64) -> RamControlCheckpointBinding {
    RamControlCheckpointBinding {
        arm_request_digest: [5; 32],
        request_generation: 7,
        connection_epoch: epoch,
    }
}

fn response(
    binding: RamControlCheckpointBinding,
    physical_state: RamControlCheckpointPhysicalState,
    first_status: i32,
    post_status: i32,
) -> RamControlFrame {
    RamControlFrame {
        message: RamControlMessage::CheckpointDispositionReply {
            binding,
            receipt: RamControlCheckpointDispositionReceipt {
                physical_state,
                first_status,
                post_status,
            },
        },
        ..frame(3, RamControlRequest::CheckpointDisposition { binding })
    }
}

#[test]
fn disposition_framing_refuses_previous_edition_and_generic_operator_dispatch() {
    let request = frame(
        3,
        RamControlRequest::CheckpointDisposition {
            binding: binding(11),
        },
    );
    let mut body = [0; RAM_CONTROL_CHECKPOINT_MAX_BYTES];
    let length = encode_ram_checkpoint_control(&request, &mut body).unwrap();
    assert_eq!(length, 206);
    assert_eq!(&body[..5], &[0, 0, 0, 11, 10]);
    assert_eq!(decode_ram_control(&body[..length]).unwrap(), request);
    assert_eq!(encode_ram_control(&request).unwrap(), body[..length]);
    let mut digest = blake3::Hasher::new();
    digest.update(b"crucible.ram.control.request.v1\0");
    digest.update(&body[..length]);
    assert_eq!(
        ram_control_request_digest(&request).unwrap(),
        *digest.finalize().as_bytes()
    );

    for version in [9_u32, 10] {
        body[..4].copy_from_slice(&version.to_be_bytes());
        assert!(matches!(
            decode_ram_control(&body[..length]),
            Err(RamControlError::UnsupportedVersion(observed)) if observed == version
        ));
    }
    let mut stream = Cursor::new(Vec::new());
    write_ram_control(&mut stream, &request).unwrap();
    stream.set_position(0);
    let mut sequence = 2;
    let mut dispatched = false;
    assert!(
        serve_ram_control_once(
            &mut stream,
            request.session,
            request.target,
            &mut sequence,
            &mut |_| {
                dispatched = true;
                state()
            }
        )
        .is_err()
    );
    assert!(!dispatched);
    assert_eq!(sequence, 2);
}

#[test]
fn completed_custody_preserves_semantic_failure_and_requires_certain_postcut() {
    use RamControlCheckpointPhysicalState::{NoRootAbandoned, Pending, Retired, Uncertain};
    for (epoch, state, first, post, valid) in [
        (11, Retired, -5, 0, true),
        (11, Retired, -5, -110, false),
        (0, Retired, 0, 0, false),
        (0, NoRootAbandoned, -5, 0, true),
        (11, NoRootAbandoned, -5, 0, true),
        (11, NoRootAbandoned, -5, -5, false),
        (11, Pending, -5, -110, true),
        (11, Uncertain, -5, -110, true),
        (11, Pending, 1, 0, false),
        (11, Uncertain, 0, 1, false),
    ] {
        let observed = response(binding(epoch), state, first, post);
        let encoded = encode_ram_control(&observed);
        assert_eq!(encoded.is_ok(), valid);
        if let Ok(bytes) = encoded {
            assert_eq!(bytes.len(), 215);
            assert_eq!(bytes[4], 130);
            assert_eq!(decode_ram_control(&bytes).unwrap(), observed);
        }
    }
}

#[test]
fn disposition_refuses_zero_generation_unknown_state_and_trailing_record() {
    let mut zero = binding(11);
    zero.request_generation = 0;
    assert!(
        encode_ram_control(&frame(
            3,
            RamControlRequest::CheckpointDisposition { binding: zero }
        ))
        .is_err()
    );
    let observed = response(
        binding(11),
        RamControlCheckpointPhysicalState::Retired,
        -5,
        0,
    );
    let mut bytes = encode_ram_control(&observed).unwrap();
    bytes[206] = 4;
    assert!(decode_ram_control(&bytes).is_err());
    bytes[206] = 1;
    bytes.push(0);
    assert!(decode_ram_control(&bytes).is_err());
    assert!(ram_control_request_digest(&observed).is_err());
}
