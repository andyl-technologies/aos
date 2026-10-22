//! Exercises raw receipt over an actual inherited parent/child socket.
//!
//! Header fixtures are inert protocol bytes. No fixture constructs an opaque
//! Recipe/Initial, installs native state or supplies readiness. The child
//! typed controls exercise only real inert DTO decoding.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual inherited-channel test assertions deliberately panic on mismatch.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::reference_packet::service::complete_restore::import17::{
    NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC,
    NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION,
};
use std::{
    io::Write,
    net::Shutdown,
    process::{Command, Stdio},
};

#[path = "tests/typed.rs"]
mod typed;

#[path = "tests/source_authentication.rs"]
mod source_authentication;

#[path = "tests/initial_reconstruction.rs"]
mod initial_reconstruction;

const CHILD_CASE: &str = "CRUCIBLE_IMPORT18_RAW_BOOTSTRAP_CHILD";
const CHILD_TEST: &str = "reference_packet::service::ack_emitter::native_boot::bootstrap_import18::tests::inherited_raw_bootstrap_child";
const BODIES: [&[u8]; 3] = [
    b"recipe DATA",
    b"selected launch DATA",
    b"private boot DATA",
];

fn bounds() -> Import18RawBootstrapBounds {
    // Fund the positive control's complete current physical row. The negative
    // controls subtract one byte from each axis or from this independent peak.
    let requested_peak = raw_storage_floor(BODIES.map(<[u8]>::len))
        .unwrap()
        .into_iter()
        .sum();
    Import18RawBootstrapBounds {
        bodies: [256; 3],
        complete_private_bytes: NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES + 3 * 256,
        requested_peak,
    }
}

// This independent fixed-wire fixture deliberately cannot produce live recipe
// DATA. It tests only the actual raw receiver's origin, framing and storage cut.
fn prefix(row: [usize; 3]) -> [u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES] {
    prefix_for_bodies(row, BODIES)
}

fn prefix_for_bodies(
    row: [usize; 3],
    bodies: [&[u8]; 3],
) -> [u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES] {
    let mut bytes = [0; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES];
    bytes[..8].copy_from_slice(&NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC);
    bytes[8..16].copy_from_slice(&NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION.to_be_bytes());
    for (index, body) in bodies.into_iter().enumerate() {
        bytes[16 + index * 8..24 + index * 8].copy_from_slice(&(body.len() as u64).to_be_bytes());
        bytes[40 + index * 32..72 + index * 32].copy_from_slice(blake3::hash(body).as_bytes());
    }
    bytes[136..168].fill(17);
    for (index, value) in row.into_iter().enumerate() {
        bytes[168 + index * 8..176 + index * 8].copy_from_slice(&(value as u64).to_be_bytes());
    }
    bytes[192..224].fill(23);
    let derived = blake3::derive_key(NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN, &[23; 32]);
    let mac = blake3::keyed_hash(&derived, &bytes[..224]);
    bytes[224..].copy_from_slice(mac.as_bytes());
    bytes
}

fn child(case: &str, wire: &[u8]) {
    let (mut parent, inherited) = UnixStream::pair().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(CHILD_CASE, case)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(inherited)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut public_peer = if case.starts_with("initial_hello_channel_")
        || case.starts_with("initial_hello_exchange_")
        || case.starts_with("initial_hello_literal_")
        || case.starts_with("initial_hello_value_")
        || case.starts_with("initial_hello_request_")
        || case.starts_with("initial_hello_registrar_")
        || case.starts_with("initial_hello_sdk_request_")
        || case.starts_with("initial_hello_result_")
        || case.starts_with("initial_hello_envelope_")
        || case.starts_with("initial_hello_response_")
        || case.starts_with("initial_hello_verifier_")
        || case.starts_with("initial_hello_admission_")
        || case.starts_with("initial_hello_publication_")
        || case.starts_with("initial_policy_")
    {
        let (peer, inherited) = UnixStream::pair().unwrap();
        command.stderr(Stdio::from(std::os::fd::OwnedFd::from(inherited)));
        Some(peer)
    } else {
        None
    };
    let process = command.spawn().unwrap();
    drop(command);
    if let Some(peer) = &mut public_peer {
        if case.starts_with("initial_hello_request_")
            || case.starts_with("initial_hello_registrar_")
            || case.starts_with("initial_hello_sdk_request_")
            || case.starts_with("initial_hello_result_")
            || case.starts_with("initial_hello_envelope_")
            || case.starts_with("initial_hello_response_")
            || case.starts_with("initial_hello_verifier_")
            || case.starts_with("initial_hello_admission_")
            || case.starts_with("initial_hello_publication_")
            || case.starts_with("initial_policy_")
        {
            let body = initial_reconstruction::hello_request_body_data(case);
            peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            peer.write_all(&body).unwrap();
            if case.contains("_normalizations_host_value_") {
                super::bootstrap_value::tests::write_parent_frame(case, peer);
            } else if case.contains("_normalizations_host_frame_") {
                super::bootstrap_literal::tests::write_parent_frame(case, peer);
            } else {
                peer.write_all(b"literal suffix").unwrap();
            }
        } else if case.starts_with("initial_hello_value_") {
            let body = initial_reconstruction::hello_value_body_data(case);
            peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            peer.write_all(&body).unwrap();
            peer.write_all(b"literal suffix").unwrap();
        } else if case.starts_with("initial_hello_literal_") {
            let body = b"{unparsed public Hello DATA";
            let length = match case {
                "initial_hello_literal_zero" => 0,
                "initial_hello_literal_oversized" => 1048577,
                "initial_hello_literal_partial_body" | "initial_hello_literal_timeout" => 64,
                _ => body.len() as u32,
            };
            let header = length.to_be_bytes();
            if case == "initial_hello_literal_partial_header" {
                peer.write_all(&header[..2]).unwrap();
                peer.shutdown(Shutdown::Write).unwrap();
            } else {
                peer.write_all(&header).unwrap();
                peer.write_all(body).unwrap();
                if case == "initial_hello_literal_partial_body" {
                    peer.shutdown(Shutdown::Write).unwrap();
                } else if case != "initial_hello_literal_timeout" {
                    peer.write_all(b"literal suffix").unwrap();
                }
            }
        } else {
            peer.write_all(b"unconsumed public Hello DATA").unwrap();
        }
    }
    if case == "initial_hello_publication_broken_pipe" {
        public_peer
            .as_ref()
            .unwrap()
            .shutdown(Shutdown::Read)
            .unwrap();
    }
    parent.write_all(wire).unwrap();
    if case != "open_writer" {
        parent.shutdown(Shutdown::Write).unwrap();
    }
    let output = process.wait_with_output().unwrap();
    let mut diagnostics = output.stderr;
    if let Some(peer) = &mut public_peer {
        use std::io::Read;
        if let Err(error) = peer.read_to_end(&mut diagnostics) {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&diagnostics)
    );
    if case.starts_with("initial_hello_publication_") || case.starts_with("initial_policy_") {
        initial_reconstruction::assert_hello_publication_bytes(case, &diagnostics);
    } else if public_peer.is_some() {
        assert!(
            diagnostics.is_empty(),
            "public birth constructor wrote bytes"
        );
    }
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "private child of actual inherited-socket bootstrap controls"]
fn inherited_raw_bootstrap_child() {
    let case = std::env::var(CHILD_CASE).unwrap();
    let original = rustix::io::dup(rustix::stdio::stdin()).unwrap();
    let mut selected_bounds = if case.starts_with("typed_")
        || case.starts_with("source_")
        || case.starts_with("initial_")
    {
        typed::bounds()
    } else {
        bounds()
    };
    if case == "typed_independent_peak" {
        selected_bounds.requested_peak = typed::required_peak(&case) - 1;
    }
    if case == "source_independent_peak" {
        selected_bounds.requested_peak = source_authentication::required_peak(&case) - 1;
    }
    if case == "independent_peak" {
        selected_bounds.requested_peak -= 1;
    }
    initial_reconstruction::prepare_independent_kernel_image(&case);
    let mut owner =
        OriginalImport18RawBootstrap::retain(UnixStream::from(original), selected_bounds).unwrap();
    assert!(owner.inputs.is_empty_data());
    if case.starts_with("initial_hello_channel_")
        || case.starts_with("initial_hello_exchange_")
        || case.starts_with("initial_hello_literal_")
        || case.starts_with("initial_hello_value_")
        || case.starts_with("initial_hello_request_")
        || case.starts_with("initial_hello_registrar_")
        || case.starts_with("initial_hello_sdk_request_")
        || case.starts_with("initial_hello_result_")
        || case.starts_with("initial_hello_envelope_")
        || case.starts_with("initial_hello_response_")
        || case.starts_with("initial_hello_verifier_")
        || case.starts_with("initial_hello_admission_")
        || case.starts_with("initial_hello_publication_")
        || case.starts_with("initial_policy_")
    {
        initial_reconstruction::retain_public_before_read(&case, &mut owner);
    }
    let result = owner.receive();
    assert!(owner.inputs.is_empty_data());
    if case.starts_with("typed_") {
        typed::assert_child(&case, owner, result);
        return;
    }
    if case.starts_with("source_") {
        source_authentication::assert_child(&case, owner, result);
        return;
    }
    if case.starts_with("initial_") {
        initial_reconstruction::assert_child(&case, owner, result);
        return;
    }
    let received = owner.received;
    let retained = owner.retained_requested_bytes().unwrap();

    if case == "complete" {
        result.unwrap();
        assert_eq!(owner.bodies_data().unwrap(), BODIES);
        assert!(owner.closed);
        assert_eq!(owner.tail_received, 0);
        assert_eq!(
            retained,
            size_of::<OriginalImport18RawBootstrap>()
                + BODIES.iter().map(|body| body.len()).sum::<usize>()
        );
    } else {
        assert!(result.is_err());
        assert!(owner.bodies_data().is_err());
        if case.starts_with("short_") || case == "independent_peak" {
            assert_eq!(received, [0; 3]);
            assert_eq!(retained, size_of::<OriginalImport18RawBootstrap>());
        }
        if case == "partial_body" {
            assert_eq!(received, [BODIES[0].len(), 3, 0]);
            assert!(retained > size_of::<OriginalImport18RawBootstrap>());
            assert_eq!(owner.bodies[1].get(..3), Some(&BODIES[1][..3]));
        }
        if case == "suffix" {
            assert_eq!(owner.tail, [0x71]);
            assert_eq!(owner.tail_received, 1);
            assert!(!owner.closed);
            assert_eq!(received, BODIES.map(<[u8]>::len));
        }
        if case == "open_writer" {
            assert!(owner.cut.is_expired());
            assert!(!owner.closed);
            assert_eq!(received, BODIES.map(<[u8]>::len));
        }
        if case == "partial_prefix" {
            assert_eq!(owner.prefix_received, 41);
            assert!(owner.header.is_none());
        }
    }
    assert!(
        owner.receive().is_err(),
        "a failed or successful occurrence stays spent"
    );
    assert_eq!(owner.received, received);
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
}

#[test]
fn actual_inherited_parent_receives_exact_bodies_without_typed_authority() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    let mut wire = prefix(row).to_vec();
    for body in BODIES {
        wire.extend_from_slice(body);
    }
    child("complete", &wire);
}

#[test]
fn each_raw_axis_and_the_independent_policy_refuse_before_body_allocation() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    for (axis, case) in ["short_retained", "short_transient", "short_scratch"]
        .into_iter()
        .enumerate()
    {
        let mut short = row;
        short[axis] -= 1;
        child(case, &prefix(short));
    }
    child("independent_peak", &prefix(row));
}

#[test]
fn partial_prefix_and_partial_body_keep_the_same_bytes_and_nonrenewing_occurrence() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    child("partial_prefix", &prefix(row)[..41]);
    let mut wire = prefix(row).to_vec();
    wire.extend_from_slice(BODIES[0]);
    wire.extend_from_slice(&BODIES[1][..3]);
    child("partial_body", &wire);
}

#[test]
fn a_changed_complete_body_never_becomes_a_completed_raw_receipt() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    let mut wire = prefix(row).to_vec();
    for body in BODIES {
        wire.extend_from_slice(body);
    }
    wire[NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES + 1] ^= 1;
    child("changed_body", &wire);
}

// The actual retained journal uses Rc and makes cross-thread transfer illegal.
// These runtime controls additionally reject a foreign recorded creator.
fn with_foreign_thread_record(
    owner: &mut OriginalImport18RawBootstrap,
    check: impl FnOnce(&mut OriginalImport18RawBootstrap),
) {
    let original = owner.thread;
    owner.thread = std::thread::spawn(|| std::thread::current().id())
        .join()
        .unwrap();
    check(owner);
    owner.thread = original;
}

#[test]
fn native_hello_custody_statically_confines_the_entire_original_bootstrap() {
    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    struct SendMarker;
    impl<T: ?Sized + Send> AmbiguousIfSend<SendMarker> for T {}
    let _ = <OriginalImport18RawBootstrap as AmbiguousIfSend<_>>::marker;

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    struct SyncMarker;
    impl<T: ?Sized + Sync> AmbiguousIfSync<SyncMarker> for T {}
    let _ = <OriginalImport18RawBootstrap as AmbiguousIfSync<_>>::marker;
}

#[test]
fn same_process_socket_and_foreign_thread_refuse_without_receiving() {
    let (peer, stream) = UnixStream::pair().unwrap();
    let mut owner = OriginalImport18RawBootstrap::retain(stream, bounds()).unwrap();
    assert!(owner.receive().is_err());
    assert_eq!(owner.prefix_received, 0);
    assert!(owner.bodies_data().is_err());
    assert_eq!(
        owner.retained_requested_bytes().unwrap(),
        size_of::<OriginalImport18RawBootstrap>()
    );
    with_foreign_thread_record(&mut owner, |owner| {
        assert!(owner.retained_requested_bytes().is_err());
    });
    assert_eq!(
        owner.retained_requested_bytes().unwrap(),
        size_of::<OriginalImport18RawBootstrap>()
    );
    drop(peer);
}

#[test]
fn copied_expired_cut_and_overflow_cannot_reopen_a_raw_receiver() {
    assert!(raw_storage_floor([usize::MAX, 1, 1]).is_err());
    let (_peer, stream) = UnixStream::pair().unwrap();
    let mut owner = OriginalImport18RawBootstrap::retain(stream, bounds()).unwrap();
    owner.cut = OperationalDeadline::expired_fixture();
    assert!(owner.receive().is_err());
    assert!(owner.receive().is_err());
    assert_eq!(owner.prefix_received, 0);
    assert_eq!(
        owner.retained_requested_bytes().unwrap(),
        size_of::<OriginalImport18RawBootstrap>()
    );
}

#[test]
fn extra_private_suffix_is_retained_and_refused() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    let mut wire = prefix(row).to_vec();
    for body in BODIES {
        wire.extend_from_slice(body);
    }
    wire.push(0x71);
    child("suffix", &wire);
}

#[test]
fn an_open_private_writer_expires_the_same_original_cut() {
    let row = raw_storage_floor(BODIES.map(<[u8]>::len)).unwrap();
    let mut wire = prefix(row).to_vec();
    for body in BODIES {
        wire.extend_from_slice(body);
    }
    child("open_writer", &wire);
}
