//! Source-scoped SDK exchange and process-result tests; no TCG providers here.

use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;
use std::rc::Rc;

use crucible_protocol::{
    SelectableMessageKind, SelectionReply, SelectionReplyStatus, WhiteboxDoorbellFrame,
    WhiteboxMarkerPayload, decode_selectable_message_kind, decode_whitebox_marker_payload,
};

use super::*;

#[derive(Default)]
struct Records {
    frames: Vec<Vec<u8>>,
    addresses: Vec<usize>,
}

struct NativeProvider(Rc<RefCell<Records>>);

impl DoorbellTransport for NativeProvider {
    fn ring(&mut self, buffer: &mut [u8]) -> Result<(), GuestEmitterError> {
        let mut records = self.0.borrow_mut();
        records.addresses.push(buffer.as_ptr() as usize);
        records.frames.push(buffer.to_vec());
        if decode_selectable_message_kind(buffer) == Ok(SelectableMessageKind::Request) {
            let request = SelectionRequest::decode(buffer).expect("original SDK request");
            let reply = SelectionReply::rejected(
                request.sequence(),
                SelectionReplyStatus::Unavailable,
                [0; 32],
                [0; 32],
            )
            .expect("bounded reply")
            .encode()
            .expect("original reply codec");
            buffer.fill(0);
            buffer[..reply.len()].copy_from_slice(&reply);
        }
        Ok(())
    }
}

fn frame_names(records: &Records) -> Vec<String> {
    records
        .frames
        .iter()
        .map(|bytes| match decode_selectable_message_kind(bytes) {
            Ok(SelectableMessageKind::Register) => {
                let registration = SelectableRegister::decode(bytes).expect("registration");
                format!("register:{}", registration.sequence())
            }
            Ok(SelectableMessageKind::Request) => {
                let request = SelectionRequest::decode(bytes).expect("request");
                format!("request:{}:{}", request.sequence(), request.instance_key())
            }
            _ => {
                let frame = WhiteboxDoorbellFrame::decode(bytes).expect("marker frame");
                match decode_whitebox_marker_payload(&frame).expect("typed marker") {
                    WhiteboxMarkerPayload::Lifecycle(_) => "setup".into(),
                    WhiteboxMarkerPayload::SemanticMarker(marker) => {
                        assert_eq!(marker.marker, "out.frame");
                        assert!(marker.details.is_empty());
                        marker.instance
                    }
                    other => panic!("unexpected original payload: {other:?}"),
                }
            }
        })
        .collect()
}

#[test]
fn actual_sdk_frames_share_one_parent_buffer_across_both_profiles() {
    for profile in [Profile::NoChild, Profile::ExecChild] {
        let records = Rc::new(RefCell::new(Records::default()));
        let mut transport = ParentBuffer::new(NativeProvider(records.clone()));
        let mut executions = 0;

        exchange(profile, &mut transport, || {
            assert_eq!(
                frame_names(&records.borrow()),
                ["register:1", "setup", "first", "request:2:first"]
            );
            executions += 1;
            Ok(())
        })
        .expect("original typed SDK exchange with explicit reply provider");

        assert_eq!(executions, usize::from(profile == Profile::ExecChild));
        let recorded = records.borrow();
        assert_eq!(
            frame_names(&recorded),
            [
                "register:1",
                "setup",
                "first",
                "request:2:first",
                "second",
                "request:3:second"
            ]
        );
        assert_ne!(recorded.addresses[0], 0);
        assert!(
            recorded
                .addresses
                .iter()
                .all(|address| *address == recorded.addresses[0])
        );
    }
}

#[test]
fn child_failure_cannot_emit_the_post_exec_frame_or_request() {
    let records = Rc::new(RefCell::new(Records::default()));
    let mut transport = ParentBuffer::new(NativeProvider(records.clone()));

    let error = exchange(Profile::ExecChild, &mut transport, || {
        Err("original child failure".into())
    })
    .expect_err("child failure retained");

    assert_eq!(error.to_string(), "original child failure");
    assert_eq!(
        frame_names(&records.borrow()),
        ["register:1", "setup", "first", "request:2:first"]
    );
}

#[test]
fn late_profile_emits_the_original_registration_only_after_reply_two() {
    let records = Rc::new(RefCell::new(Records::default()));
    let mut transport = ParentBuffer::new(NativeProvider(records.clone()));

    let error = exchange(Profile::LateRegister, &mut transport, || {
        panic!("late-registration profile must not execute a child")
    })
    .expect_err("source provider cannot make late return a successful exchange");

    assert_eq!(error.to_string(), "late registration unexpectedly returned");
    let recorded = records.borrow();
    assert_eq!(
        frame_names(&recorded),
        [
            "register:1",
            "setup",
            "first",
            "request:2:first",
            "register:1"
        ]
    );
    assert_eq!(recorded.frames[0], recorded.frames[4]);
}

#[test]
fn oversize_frame_never_reaches_the_native_transport() {
    let records = Rc::new(RefCell::new(Records::default()));
    let mut transport = ParentBuffer::new(NativeProvider(records.clone()));
    let mut bytes = [7; CAPACITY + 1];

    assert!(transport.ring(&mut bytes).is_err());
    assert!(records.borrow().frames.is_empty());
    assert_eq!(bytes, [7; CAPACITY + 1]);
}

#[test]
fn static_child_status_and_exact_bounded_bytes_are_required() {
    assert!(require_child_result(ExitStatus::from_raw(0), CHILD_OUTPUT, b"").is_ok());
    for (status, stdout, stderr) in [
        (ExitStatus::from_raw(2 << 8), CHILD_OUTPUT, b"".as_slice()),
        (ExitStatus::from_raw(9), CHILD_OUTPUT, b"".as_slice()),
        (
            ExitStatus::from_raw(0),
            b"different".as_slice(),
            b"".as_slice(),
        ),
        (
            ExitStatus::from_raw(0),
            CHILD_OUTPUT,
            b"unexpected".as_slice(),
        ),
        (
            ExitStatus::from_raw(0),
            &[b'x'; MAX_CHILD_OUTPUT + 1],
            b"".as_slice(),
        ),
        (
            ExitStatus::from_raw(0),
            CHILD_OUTPUT,
            &[b'x'; MAX_CHILD_OUTPUT + 1],
        ),
    ] {
        assert!(require_child_result(status, stdout, stderr).is_err());
    }
}

#[test]
fn unknown_profile_cannot_fall_back_to_a_different_action() {
    for (name, profile) in [
        ("no-child", Profile::NoChild),
        ("exec-child", Profile::ExecChild),
        ("late-register", Profile::LateRegister),
    ] {
        assert_eq!(Profile::parse(name).expect("known profile"), profile);
    }
    for name in ["", "normal", "exec", "exec-child "] {
        assert!(Profile::parse(name).is_err());
    }
}
