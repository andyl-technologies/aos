//! Exercises real Unix transport cuts; scripted replies issue no native owner.

use super::*;
use crucible_host_resources::host_services::HostServiceAllocator;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_qemu_protocol::parent_park_return::ParentParkReturn;
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// These real guard/subscriber fixtures qualify the host protocol cuts.
// Scripted receipts do not supply a native parked owner or deployed phase.
struct Pair {
    actor: HostOperationGuard,
    family: HostOperationGuard,
    actor_event: OwnedFd,
    family_event: OwnedFd,
    _actor_owner: HostOperationSupervisor,
    _family_owner: HostOperationSupervisor,
    _account: HostServiceAllocator,
}

impl Pair {
    fn new() -> Self {
        let actor_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .expect("actor fixture supervisor");
        let family_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .expect("family fixture supervisor");
        let actor = actor_owner
            .begin(HostOperationClass::Quiescence)
            .expect("entered actor fixture");
        let family = family_owner
            .begin(HostOperationClass::Quiescence)
            .expect("entered family fixture");
        let account = HostServiceAllocator::new(1, 2, 8192).expect("subscriber fixture account");
        let subscribe = |guard: &HostOperationGuard| {
            let event = rustix::event::eventfd(
                0,
                rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
            )
            .expect("actual nonblocking event");
            let credit = account
                .reserve_resources(
                    0,
                    1,
                    HostOperationGuard::original_quiescence_cancellation_bytes(),
                )
                .expect("subscriber precharge");
            let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3).expect("same event alias");
            guard
                .retain_original_quiescence_cancellation(alias, credit)
                .expect("retain entered subscriber");
            event
        };
        let actor_event = subscribe(&actor);
        let family_event = subscribe(&family);
        Self {
            actor,
            family,
            actor_event,
            family_event,
            _actor_owner: actor_owner,
            _family_owner: family_owner,
            _account: account,
        }
    }
}

struct Transport {
    stream: UnixStream,
    writes: usize,
    read_calls: usize,
    read_timeout_updates: usize,
    remaining: Option<usize>,
    revoke: Option<OwnedFd>,
}

impl Read for Transport {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_calls += 1;
        self.stream.read(bytes)
    }
}

impl Write for Transport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == Some(0) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let count = self
            .remaining
            .map_or(bytes.len(), |left| left.min(bytes.len()));
        let written = self.stream.write(&bytes[..count])?;
        self.writes += written;
        if let Some(left) = &mut self.remaining {
            *left -= written;
        }
        if let Some(event) = self.revoke.take() {
            rustix::io::write(&event, &1_u64.to_ne_bytes())?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl QmpTimeoutStream for Transport {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.read_timeout_updates += 1;
        self.stream.set_read_timeout(Some(timeout))
    }
    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.stream.set_write_timeout(Some(timeout))
    }
    fn poison_qmp_stream(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

struct Peer {
    thread: thread::JoinHandle<()>,
    commands: Arc<Mutex<Vec<Value>>>,
}

fn connect_peer(replies: Vec<Value>) -> (QmpClient<Transport>, Peer) {
    let (local, remote) = UnixStream::pair().unwrap();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&commands);
    let thread = thread::spawn(move || {
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut remote = BufReader::new(remote);
        writeln!(
            remote.get_mut(),
            "{{\"QMP\":{{\"version\":{{}},\"capabilities\":[]}}}}"
        )
        .unwrap();
        let mut line = String::new();
        remote.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["execute"],
            "qmp_capabilities"
        );
        writeln!(remote.get_mut(), "{{\"return\":{{}}}}").unwrap();
        for reply in replies {
            line.clear();
            match remote.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let Ok(command) = serde_json::from_str::<Value>(&line) else {
                return;
            };
            seen.lock().unwrap().push(command);
            if writeln!(remote.get_mut(), "{}", json!({"return":reply})).is_err() {
                return;
            }
        }
    });
    let client = QmpClient::connect(Transport {
        stream: local,
        writes: 0,
        read_calls: 0,
        read_timeout_updates: 0,
        remaining: None,
        revoke: None,
    })
    .unwrap();
    (client, Peer { thread, commands })
}

fn binding() -> ActionBinding {
    ActionBinding {
        cap: [1; 32],
        reservation: [2; 32],
        account_generation: 1,
        process_generation: 1,
        loan_sequence: 2,
        frontier: 7,
        token: 0,
        capture: None,
        park_request: Some(9),
    }
}

struct Imports {
    basis: QmpDescriptorName,
    cancellation: QmpDescriptorName,
}

impl Imports {
    fn new() -> Self {
        Self {
            basis: QmpDescriptorName::new("park-basis").unwrap(),
            cancellation: QmpDescriptorName::new("park-cancel").unwrap(),
        }
    }
    fn request(&self, binding: ActionBinding) -> ParentParkRequest<'_> {
        ParentParkRequest::Begin {
            binding,
            stopped: 11,
            basis: &self.basis,
            cancellation: &self.cancellation,
        }
    }
}

fn pending() -> Value {
    json!({"status":0,"post-status":0,"return-status":-libc::EINPROGRESS,
        "received":true,"entered":false,"pending":true,"native-returned":false,
        "terminal-published":false,"mapped-metadata-bytes":4096,"completed-requests":0,
        "lifetime-first-status":0,"lifetime-post-status":0})
}

fn closed(binding: ActionBinding, first: i32, post: i32) -> Value {
    let mut result = pending();
    result["status"] = json!(first);
    result["post-status"] = json!(post);
    result["return-status"] = json!(0);
    result["pending"] = json!(false);
    result["native-returned"] = json!(true);
    result["terminal-published"] = json!(true);
    result["mapped-metadata-bytes"] = json!(4096);
    result["completed-requests"] = json!(1);
    result["lifetime-first-status"] = json!(first);
    result["lifetime-post-status"] = json!(post);
    result["closed-request"] = json!({"binding":WireBinding::new(binding),"completed-requests":1,
        "stopped-generation":11,"native-generation":13,"plugin-owner-generation":17,"connection-epoch":19,
        "status":first,"post-status":post,"operation-status":first,"physical-status":0,
        "final-original0-status":post,"final-original1-status":0,"writer-status":0,
        "writer-first-status":0,"writer-post-status":0,"publisher-cohort-return-proven":false});
    result
}

fn terminal(binding: ActionBinding, first: i32, post: i32) -> ParentParkReturn {
    ParentParkReturn {
        binding,
        first,
        post,
        physical_resolution_mask: 255,
        publication_count: 2,
        pair_view_return_mask: 3,
        original_statuses: [post, 0],
        operation_status: first,
        return_status: 0,
        stopped_generation: 11,
        native_generation: 13,
    }
}

#[test]
fn pair_wrapper_keeps_each_entered_identity_literal() {
    let pair = Pair::new();
    let actor = pair.actor.serialize_original_quiescence_basis().unwrap();
    let family = pair.family.serialize_original_quiescence_basis().unwrap();

    let encoded = encode_parent_park_drain_basis(&pair.actor, &pair.family).unwrap();

    assert_eq!(&encoded[..8], b"CRUCPDR1");
    assert_eq!(&encoded[8..16], &[0, 0, 0, 1, 0, 0, 0, 176]);
    assert_eq!(&encoded[16..96], &actor);
    assert_eq!(&encoded[96..176], &family);
    assert_ne!(&encoded[32..64], &encoded[112..144]);
}

#[test]
fn real_unix_begin_is_nonterminal_and_uses_frozen_binding_fields() {
    let pair = Pair::new();
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![pending()]);
    let result = client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    assert!(result.pending);
    assert!(result.closed_request.is_none());
    assert_eq!(pair.actor.status().unwrap().completed_work_units, 0);
    assert_eq!(pair.family.status().unwrap().completed_work_units, 0);
    peer.thread.join().unwrap();
    let commands = peer.commands.lock().unwrap();
    assert_eq!(commands[0]["execute"], "crucible-parent-park-begin");
    assert_eq!(
        commands[0]["arguments"]["binding"]["source-capability"],
        "01".repeat(32)
    );
    assert_eq!(
        commands[0]["arguments"]["binding"]["request-correlation"],
        9
    );
    assert!(commands[0]["arguments"].get("action").is_none());
    assert!(commands[0]["arguments"].get("generation").is_none());
}

#[test]
fn either_original_cancellation_prevents_begin_without_consuming_event() {
    for actor in [false, true] {
        let pair = Pair::new();
        let imports = Imports::new();
        let (mut client, peer) = connect_peer(vec![]);
        let event = if actor {
            &pair.actor_event
        } else {
            &pair.family_event
        };
        rustix::io::write(event, &1_u64.to_ne_bytes()).unwrap();
        let written = client.stream.get_ref().writes;
        assert!(
            client
                .parent_park_begin_under_originals(
                    &imports.request(binding()),
                    &pair.actor,
                    &pair.family
                )
                .is_err()
        );
        assert_eq!(client.stream.get_ref().writes, written);
        let mut bytes = [0; 8];
        assert_eq!(rustix::io::read(event, &mut bytes).unwrap(), 8);
        assert_eq!(u64::from_ne_bytes(bytes), 1);
        assert!(
            rustix::fs::fcntl_getfl(event)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
        peer.thread.join().unwrap();
    }
}

#[test]
fn partial_begin_write_retains_first_selector_and_cannot_replay() {
    let pair = Pair::new();
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![pending()]);
    client.stream.get_mut().remaining = Some(9);
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    let written = client.stream.get_ref().writes;
    assert_eq!(
        client.parent_park_session.as_ref().unwrap().state.binding,
        binding()
    );
    assert!(client.poisoned);
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    assert_eq!(client.stream.get_ref().writes, written);
    drop(client);
    peer.thread.join().unwrap();
}

#[test]
fn cancellation_during_begin_write_keeps_uncertainty_sticky() {
    let pair = Pair::new();
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![pending()]);
    client.stream.get_mut().revoke =
        Some(rustix::io::fcntl_dupfd_cloexec(&pair.family_event, 3).unwrap());
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    assert!(client.poisoned);
    let written = client.stream.get_ref().writes;
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    assert_eq!(client.stream.get_ref().writes, written);
    drop(client);
    peer.thread.join().unwrap();
}

#[test]
fn return_requires_the_saved_connection_binding_before_any_write() {
    let pair = Pair::new();
    let imports = Imports::new();
    let cleanup = pair
        ._family_owner
        .begin(HostOperationClass::Cleanup)
        .unwrap();
    let (mut client, peer) = connect_peer(vec![pending()]);
    client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    let mut wrong = binding();
    wrong.loan_sequence += 2;
    let written = client.stream.get_ref().writes;
    assert!(
        client
            .parent_park_return_under_cleanup(wrong, &cleanup)
            .is_err()
    );
    assert_eq!(client.stream.get_ref().writes, written);
    peer.thread.join().unwrap();
    let (mut foreign, peer) = connect_peer(vec![]);
    let written = foreign.stream.get_ref().writes;
    assert!(
        foreign
            .parent_park_return_under_cleanup(binding(), &cleanup)
            .is_err()
    );
    assert_eq!(foreign.stream.get_ref().writes, written);
    peer.thread.join().unwrap();
}

#[test]
fn negative_operation_closes_physically_and_correlates_exact_mapping() {
    let pair = Pair::new();
    let imports = Imports::new();
    let cleanup = pair
        ._family_owner
        .begin(HostOperationClass::Cleanup)
        .unwrap();
    let (mut client, peer) = connect_peer(vec![pending(), closed(binding(), -5, -125)]);
    client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    rustix::io::write(&pair.actor_event, &1_u64.to_ne_bytes()).unwrap();
    let result = client
        .parent_park_return_under_cleanup(binding(), &cleanup)
        .unwrap();
    assert!(result.has_operation_failure());
    let proof = result.closed_request.unwrap();
    assert_eq!(proof.completed_requests(), 1);
    proof
        .corroborate_return(binding(), &terminal(binding(), -5, -125))
        .unwrap();
    let mut wrong = terminal(binding(), -5, -125);
    wrong.original_statuses[1] = -5;
    assert!(proof.corroborate_return(binding(), &wrong).is_err());
    let mut wrong_binding = binding();
    wrong_binding.frontier += 1;
    assert!(
        proof
            .corroborate_return(wrong_binding, &terminal(binding(), -5, -125))
            .is_err()
    );
    peer.thread.join().unwrap();
    assert_eq!(
        peer.commands.lock().unwrap()[1]["execute"],
        "crucible-parent-park-return"
    );
}

#[test]
fn pending_and_repeated_return_preserve_one_exact_closed_ordinal() {
    let pair = Pair::new();
    let imports = Imports::new();
    let cleanup = pair
        ._family_owner
        .begin(HostOperationClass::Cleanup)
        .unwrap();
    let (mut client, peer) = connect_peer(vec![
        pending(),
        pending(),
        closed(binding(), 0, 0),
        closed(binding(), 0, 0),
    ]);
    client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    assert!(
        client
            .parent_park_return_under_cleanup(binding(), &cleanup)
            .unwrap()
            .closed_request
            .is_none()
    );
    let first = client
        .parent_park_return_under_cleanup(binding(), &cleanup)
        .unwrap()
        .closed_request
        .unwrap();
    let again = client
        .parent_park_return_under_cleanup(binding(), &cleanup)
        .unwrap()
        .closed_request
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.completed_requests(), 1);
    let written = client.stream.get_ref().writes;
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    assert_eq!(client.stream.get_ref().writes, written);
    peer.thread.join().unwrap();
}

#[test]
fn malformed_or_foreign_closure_never_constructs_proof_and_poisons_transport() {
    for mutate in 0..9 {
        let pair = Pair::new();
        let imports = Imports::new();
        let cleanup = pair
            ._family_owner
            .begin(HostOperationClass::Cleanup)
            .unwrap();
        let mut reply = closed(binding(), 0, 0);
        match mutate {
            0 => reply["closed-request"]["binding"]["loan-sequence"] = json!(4),
            1 => reply["closed-request"]["stopped-generation"] = json!(12),
            2 => reply["closed-request"]["connection-epoch"] = json!(0),
            3 => reply["closed-request"]["completed-requests"] = json!(2),
            4 => reply["closed-request"]["publisher-cohort-return-proven"] = json!(true),
            5 => reply["terminal-published"] = json!(false),
            6 => reply["closed-request"]["writer-status"] = json!(1),
            7 => reply["native-returned"] = json!(false),
            _ => {
                reply = json!({"schema-version":2,"action":"relinquish","state":"relinquished","retained":false})
            }
        }
        let (mut client, peer) = connect_peer(vec![pending(), reply]);
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family,
            )
            .unwrap();
        assert!(
            client
                .parent_park_return_under_cleanup(binding(), &cleanup)
                .is_err()
        );
        assert!(client.poisoned);
        assert!(
            client
                .parent_park_session
                .as_ref()
                .unwrap()
                .state
                .closed
                .is_none()
        );
        peer.thread.join().unwrap();
    }
}

#[test]
fn same_process_event_alias_revokes_both_real_subscribers_without_consumption() {
    let actor_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let family_owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let actor = actor_owner.begin(HostOperationClass::Quiescence).unwrap();
    let family = family_owner.begin(HostOperationClass::Quiescence).unwrap();
    let event = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .unwrap();
    let account = HostServiceAllocator::new(1, 2, 8192).unwrap();
    for guard in [&actor, &family] {
        let credit = account
            .reserve_resources(
                0,
                1,
                HostOperationGuard::original_quiescence_cancellation_bytes(),
            )
            .unwrap();
        let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3).unwrap();
        guard
            .retain_original_quiescence_cancellation(alias, credit)
            .unwrap();
    }
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![]);
    let before = client.stream.get_ref().writes;

    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
    let outcome =
        client.parent_park_begin_under_originals(&imports.request(binding()), &actor, &family);

    assert!(outcome.is_err());
    assert!(actor.check_original_quiescence_cancellation().is_err());
    assert!(family.check_original_quiescence_cancellation().is_err());
    assert_eq!(client.stream.get_ref().writes, before);
    let mut bytes = [0; 8];
    assert_eq!(rustix::io::read(&event, &mut bytes).unwrap(), 8);
    assert_eq!(u64::from_ne_bytes(bytes), 1);
    assert!(
        rustix::fs::fcntl_getfl(&event)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK)
    );
    peer.thread.join().unwrap();
}

#[test]
fn next_begin_requires_both_strictly_advancing_coordinates_after_closed_return() {
    let pair = Pair::new();
    let imports = Imports::new();
    let cleanup = pair
        ._family_owner
        .begin(HostOperationClass::Cleanup)
        .unwrap();
    let mut next = binding();
    next.loan_sequence = 4;
    next.park_request = Some(10);
    let mut next_pending = pending();
    next_pending["completed-requests"] = json!(1);
    let (mut client, peer) = connect_peer(vec![pending(), closed(binding(), 0, 0), next_pending]);
    client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    client
        .parent_park_return_under_cleanup(binding(), &cleanup)
        .unwrap();
    let original_buffer = client.parent_park_session.as_ref().unwrap().frame.as_ptr();
    let written = client.stream.get_ref().writes;
    for bad in [
        ActionBinding {
            loan_sequence: 2,
            ..next
        },
        ActionBinding {
            park_request: Some(9),
            ..next
        },
    ] {
        assert!(
            client
                .parent_park_begin_under_originals(&imports.request(bad), &pair.actor, &pair.family)
                .is_err()
        );
    }
    assert_eq!(client.stream.get_ref().writes, written);
    assert!(
        client
            .parent_park_begin_under_originals(&imports.request(next), &pair.actor, &pair.family)
            .unwrap()
            .pending
    );
    assert_eq!(
        client.parent_park_session.as_ref().unwrap().state.binding,
        next
    );
    assert_eq!(
        client.parent_park_session.as_ref().unwrap().frame.as_ptr(),
        original_buffer
    );
    assert_eq!(
        client
            .parent_park_session
            .as_ref()
            .unwrap()
            .frame
            .capacity(),
        super::super::QMP_MAX_LINE_BYTES
    );
    peer.thread.join().unwrap();
}

#[test]
fn begin_reply_cannot_manufacture_closed_request_evidence() {
    let pair = Pair::new();
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![closed(binding(), 0, 0)]);
    assert!(
        client
            .parent_park_begin_under_originals(
                &imports.request(binding()),
                &pair.actor,
                &pair.family
            )
            .is_err()
    );
    assert!(
        client
            .parent_park_session
            .as_ref()
            .unwrap()
            .state
            .closed
            .is_none()
    );
    assert!(client.poisoned);
    peer.thread.join().unwrap();
}

#[test]
fn configured_channel_request_counts_its_actual_body_and_decoder_peak_once() {
    let expected = std::mem::size_of::<crate::QemuQmpExactSnapshotControlChannel<UnixStream>>()
        + crate::qmp::QMP_READ_BUFFER_BYTES
        + decoder_extent().unwrap();
    assert_eq!(
        crate::QemuQmpExactSnapshotControlChannel::<UnixStream>::host_allocation_extent(),
        Some(expected as u64)
    );
    assert!(decoder_extent().unwrap() > super::super::QMP_MAX_LINE_BYTES);
}

#[test]
fn wrong_operation_class_cannot_replace_the_retained_cleanup_phase() {
    let pair = Pair::new();
    let imports = Imports::new();
    let (mut client, peer) = connect_peer(vec![pending()]);
    client
        .parent_park_begin_under_originals(&imports.request(binding()), &pair.actor, &pair.family)
        .unwrap();
    let written = client.stream.get_ref().writes;
    assert!(
        client
            .parent_park_return_under_cleanup(binding(), &pair.family)
            .is_err()
    );
    assert_eq!(client.stream.get_ref().writes, written);
    peer.thread.join().unwrap();
}

#[test]
fn buffered_frame_reader_keeps_adjacent_frames_and_updates_timeout_per_refill() {
    let pair = Pair::new();
    let (local, mut peer) = UnixStream::pair().unwrap();
    let mut first = b"{\"event\":\"BUFFERED\",\"data\":{\"padding\":\"".to_vec();
    first.extend(std::iter::repeat_n(
        b'x',
        2 * super::super::QMP_READ_BUFFER_BYTES + 137,
    ));
    first.extend_from_slice(b"\"}}\n");
    let second = b"{\"return\":{}}\n";
    let tail = b"tail";
    let mut published = first.clone();
    published.extend_from_slice(second);
    published.extend_from_slice(tail);
    peer.set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.write_all(&published).unwrap();
    let transport = Transport {
        stream: local,
        writes: 0,
        read_calls: 0,
        read_timeout_updates: 0,
        remaining: None,
        revoke: None,
    };
    let mut stream = BufReader::with_capacity(super::super::QMP_READ_BUFFER_BYTES, transport);
    let deadline = super::super::QmpOperationDeadline {
        supervision: None,
        timeout: Duration::from_secs(2),
        shared: None,
        checkpoint_original: None,
        checkpoint_loan: None,
        borrowed: Some(&pair.actor),
        paired: Some(&pair.family),
        _lifetime: std::marker::PhantomData,
    };
    let mut frame = vec![0; super::super::QMP_MAX_LINE_BYTES];

    let length = super::transport::read_frame(
        &mut stream,
        &mut frame,
        &deadline,
        QmpCommandKind::ParentParkReturn,
        super::super::QMP_MAX_LINE_BYTES,
    )
    .unwrap();
    assert_eq!(&frame[..length], first);
    let refills = stream.get_ref().read_calls;
    assert!(refills >= 3);
    assert_eq!(stream.get_ref().read_timeout_updates, refills);
    assert!(refills < first.len() / 2);
    assert!(stream.buffer().starts_with(second));

    let length = super::transport::read_frame(
        &mut stream,
        &mut frame,
        &deadline,
        QmpCommandKind::ParentParkReturn,
        super::super::QMP_MAX_LINE_BYTES,
    )
    .unwrap();
    assert_eq!(&frame[..length], second);
    assert_eq!(stream.get_ref().read_calls, refills);
    assert_eq!(stream.get_ref().read_timeout_updates, refills);
    assert_eq!(stream.buffer(), tail);
    assert_eq!(pair.actor.status().unwrap().completed_work_units, 0);
    assert_eq!(pair.family.status().unwrap().completed_work_units, 0);
}
