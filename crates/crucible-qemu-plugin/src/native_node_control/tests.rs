//! Adversarial native callback correlation without claiming adapter qualification.

use super::*;
use crucible_node_contract::{HashRef, Id};

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}
fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}
fn position(time: u64) -> Position {
    Position {
        time_ps: U64::new(time),
        microstep: U64::new(0),
        phase: Phase::BoundaryControl,
    }
}
pub(super) fn command() -> ExecutionCommand {
    ExecutionCommand {
        sequence: U64::new(1),
        scope: OwnerScope {
            session: id("session/a"),
            incarnation: id("incarnation/a"),
            activation: id("activation/1"),
            node: id("machine/a"),
            owner: id("owner/a"),
            world_generation: U64::new(1),
            owner_generation: U64::new(3),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        operation: id("operation/1"),
        grant: id("grant/1"),
        input_epoch: id("input/epoch"),
        input_batch: id("batch/1"),
        input_batch_hash: hash("cnp.input-batch.v1"),
        closed_input_prefix: position(110),
        authorization_digest: [7; 32],
        kind: ExecutionKind::ExactRun {
            start: position(0),
            limit: position(110),
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
    }
}
fn owner() -> NativeNodeControl {
    NativeNodeControl::new(command().scope, position(0), 4).unwrap()
}
pub(super) fn receipt(snapshot: NativeNodeCommand) -> NativeNodeReceipt {
    NativeNodeReceipt {
        version: 1,
        size: 112,
        reason: 1,
        pending_classes: u32::MAX,
        command_sequence: snapshot.sequence,
        current_ps: snapshot.limit_ps,
        raw_icount: 2,
        reached_microstep: snapshot.limit_microstep,
        reached_phase: snapshot.limit_phase,
        next_native_deadline_ps: u64::MAX,
        next_service_deadline_ps: 150,
        pending_service_credit_ps: 10,
        grant_hash: snapshot.grant_hash,
    }
}

#[test]
fn no_original_command_withholds_all_native_execution() {
    let owner = owner();
    assert!(owner.command().is_none());
    assert!(owner.receipt(U64::new(1)).is_none());
}

#[test]
fn native_snapshot_commits_to_the_complete_original_authority_scope() {
    let owner = owner();
    let original = command();
    assert_eq!(
        owner.retain(original.clone()).unwrap(),
        CommandJournalDisposition::New
    );
    let native = owner.command().unwrap();
    assert_eq!(native.version, 1);
    assert_eq!(native.size, 168);
    assert_eq!(native.limit_ps, 110);
    assert_eq!(native.grant_hash, original.identity_digest().unwrap());
    assert_eq!(
        owner.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Outstanding
    );
    assert_eq!(owner.command(), Some(native));
    let mut changed = original;
    changed.input_epoch = id("changed-epoch");
    assert!(owner.retain(changed).is_err());
    assert_eq!(owner.command(), Some(native));
}

#[test]
fn native_stop_preserves_independent_retirement_and_pending_service_facts() {
    let owner = owner();
    let original = command();
    owner.retain(original.clone()).unwrap();
    let native = owner.command().unwrap();
    let facts = receipt(native);
    owner.record_stop(facts).unwrap();
    assert!(owner.command().is_none());
    assert_eq!(owner.receipt(U64::new(1)), Some(facts));
    assert_eq!(facts.current_ps, 110);
    assert_eq!(facts.raw_icount, 2);
    assert_eq!(facts.next_service_deadline_ps, 150);
    assert_eq!(facts.pending_classes, u32::MAX);
    assert_eq!(
        owner.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Stopped
    );
    owner
        .acknowledge(U64::new(1), &original.authorization_digest)
        .unwrap();
    assert_eq!(
        owner.retain(original).unwrap(),
        CommandJournalDisposition::Acknowledged
    );
    assert!(owner.command().is_none());
}

#[test]
fn invalid_native_grant_binding_quarantines_instead_of_clamping_or_replaying() {
    let owner = owner();
    let original = command();
    owner.retain(original.clone()).unwrap();
    let mut facts = receipt(owner.command().unwrap());
    facts.grant_hash[0] ^= 1;
    assert!(owner.record_stop(facts).is_err());
    assert!(owner.command().is_none());
    assert!(owner.receipt(U64::new(1)).is_none());
    assert!(owner.retain(original).is_err());
}

#[test]
fn conflicting_repeat_receipt_blocks_all_future_native_requests() {
    let owner = owner();
    owner.retain(command()).unwrap();
    let facts = receipt(owner.command().unwrap());
    owner.record_stop(facts).unwrap();
    owner.record_stop(facts).unwrap();
    let mut changed = facts;
    changed.raw_icount += 1;
    assert!(owner.record_stop(changed).is_err());
    assert!(owner.command().is_none());
    assert_eq!(owner.receipt(U64::new(1)), Some(facts));
}

#[cfg(unix)]
#[test]
fn real_private_socket_retries_original_native_facts_without_reexecution() {
    use crucible_protocol::node_control::{NativeChannel, NativeFrame, ReceiptAcknowledgement};
    let (host, provider) = NativeChannel::supervised_pair().unwrap();
    let owner = owner().with_prepared_channel(provider);
    let original = command();
    host.send(&NativeFrame::Command(Box::new(original.clone())))
        .unwrap();
    owner.poll_channel().unwrap();
    let native = owner.command().unwrap();
    let facts = receipt(native);
    owner.record_stop(facts).unwrap();
    owner.send_original_facts(U64::new(1)).unwrap();
    let first = host.receive().unwrap().unwrap();
    assert!(
        matches!(&first, NativeFrame::Stopped(stop) if stop.retired_count.get()==2 && stop.reached.time_ps.get()==110)
    );
    host.send(&NativeFrame::Command(Box::new(original.clone())))
        .unwrap();
    owner.poll_channel().unwrap();
    assert_eq!(host.receive().unwrap(), Some(first));
    assert!(owner.command().is_none());
    host.send(&NativeFrame::Acknowledge(ReceiptAcknowledgement {
        sequence: U64::new(1),
        command_digest: original.identity_digest().unwrap(),
        authorization_digest: original.authorization_digest,
    }))
    .unwrap();
    owner.poll_channel().unwrap();
    assert_eq!(
        host.receive().unwrap(),
        Some(NativeFrame::Acknowledged(ReceiptAcknowledgement {
            sequence: U64::new(1),
            command_digest: original.identity_digest().unwrap(),
            authorization_digest: original.authorization_digest,
        }))
    );
    assert_eq!(
        owner.retain(original).unwrap(),
        CommandJournalDisposition::Acknowledged
    );
    assert!(owner.command().is_none());
}

#[cfg(unix)]
#[test]
fn reader_worker_admits_original_before_notify_and_contains_unexpected_frames() {
    use crucible_protocol::node_control::{NativeChannel, NativeFrame, NativePreparation};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn notify() -> i32 {
        NOTIFICATIONS.fetch_add(1, Ordering::SeqCst);
        0
    }

    let (host, provider) = NativeChannel::supervised_pair().unwrap();
    let owner = Box::leak(Box::new(owner().with_prepared_channel(provider)));
    owner.start_protocol_worker(notify).unwrap();
    let original = command();
    host.send(&NativeFrame::Command(Box::new(original.clone())))
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while owner.command().is_none() && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        owner.command().unwrap().grant_hash,
        original.identity_digest().unwrap()
    );
    assert!(owner.has_protocol_worker());
    assert_eq!(
        owner.prepared_resources().unwrap().1,
        original.scope.identity_digest().unwrap()
    );

    // Re-preparation is an unsolicited frame after original native admission.
    // Containment withholds the current original without replaying its command.
    host.send(&NativeFrame::Prepare(Box::new(NativePreparation {
        scope: original.scope,
        boundary: position(0),
        maximum_commands: U64::new(4),
    })))
    .unwrap();
    let mut worker = owner.protocol_worker.lock().unwrap();
    worker.take().unwrap().join().unwrap();
    drop(worker);

    assert!(owner.command().is_none());
    assert!(!owner.has_protocol_worker());
    assert!(NOTIFICATIONS.load(Ordering::SeqCst) >= 2);
}
