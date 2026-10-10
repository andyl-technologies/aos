//! Checks fixed workspace identities, immediate cutover and unchanged frame caps.

#![forbid(unsafe_code)]

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, DeviceDigestWorkspaceBinding, FrameDecodeError, HostMsg,
    MAX_FRAME_SIZE, MAX_PAYLOAD_SIZE, control_decode_host_msg, control_encode_host_msg,
};

fn enabled_setup() -> HostMsg {
    HostMsg::Setup {
        region_len: 450_560,
        process_generation: 3,
        device_digest_workspace: Some(DeviceDigestWorkspaceBinding {
            account_generation: 9,
            workspace_generation: 11,
            device: 0,
            inode: 13,
        }),
    }
}

#[test]
fn setup_workspace_is_fixed_big_endian_56_bytes_under_the_unchanged_cap() {
    let expected = enabled_setup();
    let frame = control_encode_host_msg(&expected);

    assert_eq!(CONTROL_PROTOCOL_VERSION, 5);
    assert_eq!(MAX_FRAME_SIZE, 64);
    assert_eq!(MAX_PAYLOAD_SIZE, 63);
    assert_eq!(frame.len(), 61);
    assert_eq!(&frame[..5], &[0, 0, 0, 57, 1]);
    assert_eq!(&frame[13..17], &1_u32.to_be_bytes());
    assert_eq!(&frame[17..21], &1_u32.to_be_bytes());
    assert_eq!(&frame[21..29], &3_u64.to_be_bytes());
    assert_eq!(&frame[29..37], &9_u64.to_be_bytes());
    assert_eq!(&frame[37..45], &11_u64.to_be_bytes());
    assert_eq!(&frame[45..53], &0_u64.to_be_bytes());
    assert_eq!(&frame[53..61], &13_u64.to_be_bytes());
    assert_eq!(control_decode_host_msg(&frame), Ok(expected));
}

#[test]
fn disabled_workspace_requires_all_absent_fields_zero() {
    let expected = HostMsg::Setup {
        region_len: 4_096,
        process_generation: 1,
        device_digest_workspace: None,
    };
    let frame = control_encode_host_msg(&expected);
    assert_eq!(control_decode_host_msg(&frame), Ok(expected));

    for offset in [13, 17, 29, 37, 45, 53] {
        let mut changed = frame.clone();
        changed[offset] = 1;
        assert!(matches!(
            control_decode_host_msg(&changed),
            Err(FrameDecodeError::InvalidSetupWorkspace { .. })
        ));
    }
}

#[test]
fn workspace_unknown_schema_flags_and_zero_generations_refuse() {
    let frame = control_encode_host_msg(&enabled_setup());
    for (offset, width, replacement) in [
        (13, 4, 2_u64),
        (17, 4, 2),
        (21, 8, 0),
        (29, 8, 0),
        (37, 8, 0),
    ] {
        let mut changed = frame.clone();
        let bytes = replacement.to_be_bytes();
        changed[offset..offset + width].copy_from_slice(&bytes[8 - width..]);
        assert!(matches!(
            control_decode_host_msg(&changed),
            Err(FrameDecodeError::InvalidSetupWorkspace { .. })
        ));
    }
}

#[test]
fn old_eight_byte_setup_payload_has_no_compatibility_decoder() {
    assert!(control_decode_host_msg(&[0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 16, 0]).is_err());
}
