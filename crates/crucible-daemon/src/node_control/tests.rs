//! Wire adversaries that must refuse before actor or native admission.

use std::{io::Write, os::unix::net::UnixStream};

use super::*;

#[test]
fn declared_oversized_frame_refuses_without_waiting_for_body() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.write_all(&u32::MAX.to_be_bytes()).unwrap();

    let result = transport::read::<NodeControlRequest>(
        &mut receiver,
        transport::operational_now() + transport::EXCHANGE_TIMEOUT,
    );

    assert!(matches!(result, Err(NodeControlError::Refused(_))));
}

#[test]
fn duplicate_keys_noncanonical_frames_and_unknown_editions_refuse() {
    for body in [
        br#"{"format":"crucible.node-control","format":"crucible.node-control"}"#.as_slice(),
        br#"{ "command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"probe","version":1}"#,
        br#"{"command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"probe","version":2}"#,
    ] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        sender.write_all(body).unwrap();

        let result = transport::read::<NodeControlRequest>(
            &mut receiver, transport::operational_now() + transport::EXCHANGE_TIMEOUT,
        ).and_then(|request| request.validate());

        assert!(result.is_err(), "wire adversary reached actor admission");
    }
}

#[test]
fn closed_selection_and_execution_nonce_rules_refuse_before_connect() {
    assert!(decode_node_selections(br#"[{"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock","qemu":true}}]"#).is_err());
    for execution in [
        "",
        "00000000000000000000000000000000",
        "2929292929292929292929292929292A",
    ] {
        assert!(
            NodeControlRequest::new(
                "probe",
                NodeControlCommand::Status {
                    execution: execution.into()
                }
            )
            .is_err()
        );
    }
    assert!(
        NodeControlRequest::new(
            "probe",
            NodeControlCommand::Status {
                execution: "29292929292929292929292929292929".into(),
            }
        )
        .is_ok()
    );
}
