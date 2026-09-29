//! Protected-row/cryptographic joins and local preparation regressions.
//!
//! The signed assignment fixture uses existing authentic publication gates.
//! Runtime audit rows below are synthetic comparison DATA, not installed Host,
//! worker, kernel-request, Root, Policy or disclosure-producer qualification.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture setup and regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::model::{
    AttachmentConsistency, AttachmentIntent, AttachmentLease, AttachmentPresentation, CacheDomain,
    CacheDomainKind, MountAttributes, View, ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    AttachmentSlotId, CacheDomainId, DesiredGeneration, FeatureRef, IncarnationId, LeaseId,
    MediaType, NamespaceGeneration, ObjectDigest, OperationId, PrincipalId, RawClockProvenance,
    Revision, SandboxId, ViewId, descriptor_for_bytes, encode_view,
};
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::*;
use crate::runtime_authority::RuntimeAuthorityIntentV1;
use crate::runtime_scope::{ConsumerResourceFixture, consumer_resource_policy};
use crate::{JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

const ATTACHMENT: AttachmentId = AttachmentId::from_bytes([20; 16]);
const SLOT: AttachmentSlotId = AttachmentSlotId::from_bytes([21; 16]);
const VIEW: ViewId = ViewId::from_bytes([22; 16]);

fn open(path: &Path, limits: JournalLimits) -> Journal {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        path,
        CONTROLLER_JOURNAL,
        limits,
        std::fs::metadata(path).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn view() -> View {
    View::new(
        ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor").unwrap(),
                ObjectDigest::from_bytes([30; 32]),
                1,
            ),
        },
        Vec::new(),
        ViewConsistency::Immutable,
        ViewMutation::ReadOnly,
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap(),
        CacheDomain::new(
            CacheDomainKind::Private,
            CacheDomainId::from_bytes([31; 16]),
        ),
        Vec::new(),
    )
    .unwrap()
}

fn publish_view(journal: &mut Journal, revision: u8) -> DurableFilesystemViewRevisionV1 {
    let previous = filesystem_view_state::get_current(journal, VIEW)
        .unwrap()
        .map(|row| row.record_digest());
    filesystem_view_state::commit(
        journal,
        crate::FilesystemViewRevisionMutationV1::new(
            crate::FilesystemViewRevisionPresenceV1::Available,
            VIEW,
            Revision::new(u64::from(revision)),
            view(),
            OperationId::from_bytes([revision + 100; 16]),
            ObjectDigest::from_bytes([revision + 110; 32]),
            previous,
        )
        .unwrap(),
    )
    .unwrap()
    .0
}

fn intent(generation: u64) -> AttachmentIntent {
    AttachmentIntent::new_with_presentation(
        ATTACHMENT,
        DesiredGeneration::new(generation),
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([4; 16]),
        NamespaceGeneration::new(8),
        VIEW,
        Revision::new(1),
        None,
        descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.view.v1+cbor").unwrap(),
            &encode_view(&view()),
        ),
        SLOT,
        AttachmentConsistency::ImmutableRevision,
        ViewMutation::ReadOnly,
        MountAttributes::new(true, true, true, true, true, false),
        AttachmentLease::new(LeaseId::from_bytes([23; 16]), 140, 170).unwrap(),
        AttachmentPresentation::Fuse,
    )
    .unwrap()
}

fn desired(journal: &mut Journal, generation: u8, presence: crate::AttachmentDesiredPresenceV1) {
    let previous = attachment_state::get(journal, ATTACHMENT)
        .unwrap()
        .map(|row| row.record_digest());
    attachment_state::commit_consumer_fixture(
        journal,
        crate::AttachmentDesiredMutationV1::new_v2(
            presence,
            intent(u64::from(generation)),
            OperationId::from_bytes([generation + 60; 16]),
            ObjectDigest::from_bytes([generation + 70; 32]),
            previous,
        )
        .unwrap(),
    );
}

fn fixture() -> (TempDir, ConsumerResourceFixture) {
    let directory = tempfile::tempdir().unwrap();
    let spec = {
        let mut journal = open(directory.path(), JournalLimits::default());
        crate::sandbox_spec_state::publish_slot_spec_for_test(&mut journal, SLOT)
    };
    let mut fixture = ConsumerResourceFixture::new(directory.path(), spec);
    let journal = fixture.journal_mut();
    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
        .unwrap()
        .current(SandboxId::from_bytes([1; 16]))
        .unwrap()
        .unwrap();
    runtime_scope::seed_consumer_origin_for_test(journal, &binding);
    publish_view(journal, 1);
    attachment_slot_state::commit_for_test(
        journal,
        &crate::AttachmentSlotMutationV1::new(
            crate::AttachmentSlotPresenceV1::Available,
            SLOT,
            Revision::new(1),
            OperationId::from_bytes([24; 16]),
            ObjectDigest::from_bytes([25; 32]),
            None,
        )
        .unwrap(),
        binding.sandbox(),
        binding.manifest().manifest().incarnation(),
        8,
    )
    .unwrap();
    desired(journal, 1, crate::AttachmentDesiredPresenceV1::Present);
    (directory, fixture)
}

fn boottime() -> u64 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u64::try_from(time.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(time.tv_nsec).unwrap()
}

fn clock_at(wall: i64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([91; 16]).unwrap(),
        KernelBootId::current().unwrap().into_bytes(),
        wall,
        boottime(),
    )
    .unwrap()
}

fn clock() -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
    Ok(clock_at(150))
}

fn hold<'a>(journal: &'a mut Journal, path: &Path) -> CurrentControllerConsumerResourceV1<'a> {
    capture(
        journal,
        ATTACHMENT,
        consumer_resource_policy(),
        &mut clock,
        Location::Fixture(path.to_owned()),
    )
    .unwrap()
}

fn request(id: u8) -> ConsumerReadRequestDataV1 {
    ConsumerReadRequestDataV1 {
        request_id: [id; 16],
        connection_instance: [2; 16],
        kernel_unique: 3,
        node: 4,
        file_handle: 5,
        offset: 6,
        length: 7,
        deadline: boottime() + 10_000_000_000,
    }
}

fn limits(journal: &Journal) -> ConsumerResourceAttemptLimitsV1 {
    let actual = journal.configured_limits();
    ConsumerResourceAttemptLimitsV1 {
        maximum_attempts: actual.maximum_materialized_records,
        maximum_materialized_bytes: actual.maximum_materialized_bytes,
        maximum_read_bytes: 4096,
    }
}

#[test]
fn original_view_revision_and_accepted_lease_survive_newer_view_publication() {
    let (directory, mut fixture) = fixture();
    let original =
        filesystem_view_state::get_revision(fixture.journal_mut(), VIEW, Revision::new(1))
            .unwrap()
            .unwrap();
    publish_view(fixture.journal_mut(), 2);

    let held = hold(fixture.journal_mut(), directory.path());
    assert_eq!(held.original_view(), &original);
    assert_eq!(held.desired().intent().lease(), intent(1).lease());
    assert_eq!(
        held.accepted_policy(),
        held.binding.manifest().manifest().policy()
    );
}

#[test]
fn released_attachment_expired_lease_and_revoke_rebind_aba_refuse_resource_guard() {
    for failure in 0..3 {
        let (directory, mut fixture) = fixture();
        match failure {
            0 => desired(
                fixture.journal_mut(),
                2,
                crate::AttachmentDesiredPresenceV1::Released,
            ),
            1 => {}
            _ => {
                fixture.activate(2, RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap());
                fixture.activate(
                    3,
                    RuntimeAuthorityIntentV1::bind_holder(
                        PrincipalId::from_bytes([0x91; 16]),
                        Some(2),
                    )
                    .unwrap(),
                );
            }
        }
        let mut time = || Ok(clock_at(if failure == 1 { 170 } else { 150 }));
        assert!(
            capture(
                fixture.journal_mut(),
                ATTACHMENT,
                consumer_resource_policy(),
                &mut time,
                Location::Fixture(directory.path().to_owned())
            )
            .is_err(),
            "case {failure}"
        );
    }
}

#[test]
fn frozen_selected_binding_and_request_do_not_renew_or_extend() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let request = request(40);
    let ceilings = limits(held.journal);
    let retained = held
        .retain_resource_prepared(request, ceilings, &mut clock)
        .unwrap();
    let sequence = held.journal.snapshot_sequence();
    assert_eq!(
        held.retain_resource_prepared(request, ceilings, &mut clock)
            .unwrap(),
        retained
    );
    assert_eq!(held.journal.snapshot_sequence(), sequence);
    let mut extended = request;
    extended.deadline += 1;
    assert!(
        held.retain_resource_prepared(extended, ceilings, &mut clock)
            .is_err()
    );
    drop(held);
    fixture.activate(
        2,
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), Some(1))
            .unwrap(),
    );
    let mut renewed = hold(fixture.journal_mut(), directory.path());
    let before = renewed.journal.snapshot_sequence();
    assert!(
        renewed
            .retain_resource_prepared(request, ceilings, &mut clock)
            .is_err()
    );
    assert_eq!(renewed.journal.snapshot_sequence(), before);
}

#[test]
fn policy_selector_requires_actual_successful_prepared_row_and_live_capacity() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    assert!(held.prepared_policy_selector(&mut clock).is_err());
    let request = request(58);
    let mut ceilings = limits(held.journal);
    ceilings.maximum_attempts = 0;
    let sequence = held.journal.snapshot_sequence();
    assert!(
        held.retain_resource_prepared(request, ceilings, &mut clock)
            .is_err()
    );
    assert_eq!(held.request, Some(request));
    assert_eq!(held.journal.snapshot_sequence(), sequence);
    assert!(held.prepared_policy_selector(&mut clock).is_err());

    let ceilings = limits(held.journal);
    let row = held
        .retain_resource_prepared(request, ceilings, &mut clock)
        .unwrap();
    let selected = held.prepared_policy_selector(&mut clock).unwrap();
    let manifest = held.binding.manifest().manifest();
    assert_eq!(
        selected,
        (manifest.project(), manifest.sandbox(), request.deadline)
    );
    assert_eq!(
        held.begin_pre_root_policy_flight(&mut clock).unwrap(),
        selected
    );
    assert!(held.begin_pre_root_policy_flight(&mut clock).is_err());
    assert_eq!(held.prepared_policy_selector(&mut clock).unwrap(), selected);
    // A separately decoded DATA row has no effect on selector production.
    assert_eq!(
        DurableConsumerResourceAttemptV1::decode_canonical(&row.canonical_bytes()).unwrap(),
        row
    );
    attempt::quarantine(held.journal, request.request_id).unwrap();
    assert!(held.prepared_policy_selector(&mut clock).is_err());
    assert!(attempt::require_retained_prepared(held.journal, request, &held.source).is_err());
}

#[test]
fn available_slot_successor_is_rejected_without_changing_the_original_cut() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let previous = held.slot.record_digest();
    let sequence = held.journal.snapshot_sequence();
    let journal_path = directory.path().join(CONTROLLER_JOURNAL);
    let journal_bytes = std::fs::read(&journal_path).unwrap();

    let result = attachment_slot_state::commit_for_test(
        held.journal,
        &crate::AttachmentSlotMutationV1::new(
            crate::AttachmentSlotPresenceV1::Available,
            SLOT,
            Revision::new(2),
            OperationId::from_bytes([47; 16]),
            ObjectDigest::from_bytes([48; 32]),
            Some(previous),
        )
        .unwrap(),
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([4; 16]),
        8,
    );
    assert!(matches!(
        result,
        Err(crate::AttachmentSlotStateError::Conflict)
    ));
    assert_eq!(held.journal.snapshot_sequence(), sequence);
    assert_eq!(std::fs::read(&journal_path).unwrap(), journal_bytes);
    held.recheck(&mut clock).unwrap();
    assert_eq!(held.slot.record_digest(), previous);
}

#[test]
fn removed_slot_row_refuses_the_original_held_cut() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let deletions: Vec<_> = held
        .journal
        .records(RecordNamespace::AttachmentSlot)
        .map(|(key, _)| JournalRecord::delete(RecordNamespace::AttachmentSlot, key.to_vec()))
        .collect();
    assert_eq!(deletions.len(), 1);

    // Deliberately remove comparison DATA; do not invent a legal slot successor.
    held.journal
        .commit(&JournalTransaction::new([48; 16], deletions).unwrap())
        .unwrap();
    assert!(held.recheck(&mut clock).is_err());
}

#[test]
fn missing_protected_allocation_refuses_a_fresh_original_cut() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    held.recheck(&mut clock).unwrap();
    drop(held);

    let journal = fixture.journal_mut();
    let deletions: Vec<_> = journal
        .records(RecordNamespace::NamespaceTarget)
        .map(|(key, _)| JournalRecord::delete(RecordNamespace::NamespaceTarget, key.to_vec()))
        .collect();
    assert!(!deletions.is_empty());
    journal
        .commit(&JournalTransaction::new([49; 16], deletions).unwrap())
        .unwrap();
    assert!(
        capture(
            journal,
            ATTACHMENT,
            consumer_resource_policy(),
            &mut clock,
            Location::Fixture(directory.path().to_owned())
        )
        .is_err()
    );
}

#[test]
fn physical_journal_lock_and_parent_replacement_refuse_retained_writer() {
    for replacement in 0..3 {
        let (directory, mut fixture) = fixture();
        let mut held = hold(fixture.journal_mut(), directory.path());
        let path = directory.path();
        if replacement == 2 {
            let moved = path.with_extension("retired");
            std::fs::rename(path, &moved).unwrap();
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(held.recheck(&mut clock).is_err());
            drop(held);
            std::fs::remove_dir(path).unwrap();
            std::fs::rename(moved, path).unwrap();
        } else {
            let name = if replacement == 0 {
                CONTROLLER_JOURNAL
            } else {
                "controller.journal.lock"
            };
            let original = path.join(name);
            let saved = path.join(format!("{name}.retired"));
            std::fs::rename(&original, &saved).unwrap();
            std::fs::copy(&saved, &original).unwrap();
            assert!(held.recheck(&mut clock).is_err());
        }
    }
}

#[test]
fn exact_local_terminal_capacity_and_cold_quarantine_preserve_original_data() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let request = request(41);
    let retained = held
        .retain_resource_prepared(request, limits(held.journal), &mut clock)
        .unwrap();
    let bytes = retained.canonical_bytes();
    assert_eq!(bytes.len(), 872);
    let reservation = <[u8; 32]>::try_from(&bytes[808..840]).unwrap();
    let capacity = held
        .journal
        .recover_global_capacity_reservation_v1(reservation)
        .unwrap();
    assert_eq!(
        capacity.request().purpose,
        crate::GlobalCapacityReservationPurposeV1::ControllerConsumerResource
    );
    assert_eq!(capacity.request().future_transactions, 1);
    assert_eq!(capacity.request().terminal_records, 2);
    let terminal_bytes = capacity.request().terminal_bytes;
    let capacity_delete = capacity.settlement_record();
    drop(held);
    drop(fixture);

    // A lost return after the committed preparation leaves DATA only. Cold
    // cleanup needs no renewed clock, live owner, Ready proof or current lease.
    let mut cold = open(directory.path(), JournalLimits::default());
    let journal_path = directory.path().join(CONTROLLER_JOURNAL);
    let before_quarantine = std::fs::metadata(&journal_path).unwrap().len();
    let quarantined = attempt::quarantine(&mut cold, request.request_id).unwrap();
    let terminal = JournalTransaction::new(
        [50; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::ControllerConsumerReadAttempt,
                request.request_id.to_vec(),
                quarantined.canonical_bytes(),
            ),
            capacity_delete,
        ],
    )
    .unwrap();
    assert_eq!(
        crate::journal::encoded_transaction_append_bytes(&terminal).unwrap(),
        terminal_bytes
    );
    assert_eq!(
        std::fs::metadata(&journal_path).unwrap().len() - before_quarantine,
        terminal_bytes
    );
    assert_eq!(quarantined.request(), request);
    assert_eq!(
        quarantined.phase(),
        ConsumerResourceAttemptPhaseV1::ResourceQuarantined
    );
    assert_eq!(&quarantined.canonical_bytes()[16..776], &bytes[16..776]);
    assert_eq!(
        &quarantined.canonical_bytes()[776..808],
        retained.record_digest().as_bytes()
    );
    assert!(
        cold.lookup_global_capacity_reservation_v1(reservation)
            .unwrap()
            .is_none()
    );
    let sequence = cold.snapshot_sequence();
    assert_eq!(
        attempt::quarantine(&mut cold, request.request_id).unwrap(),
        quarantined
    );
    assert_eq!(cold.snapshot_sequence(), sequence);
    assert!(hold_for_result(&mut cold, directory.path(), 170).is_err());
}

#[test]
fn postcommit_clock_failure_keeps_preparation_and_permanently_refuses_the_borrow() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let request = request(52);
    let path = directory.path().join(CONTROLLER_JOURNAL);
    let before = std::fs::metadata(&path).unwrap().len();
    // This is an injected adapter failure after a real successful append,
    // not a filesystem-fsync ambiguity or installed read-authority fixture.
    let mut fail_after_append = || {
        if std::fs::metadata(&path).unwrap().len() > before {
            Err(ProtectedOwnershipClockError)
        } else {
            clock()
        }
    };
    assert!(
        held.retain_resource_prepared(request, limits(held.journal), &mut fail_after_append)
            .is_err()
    );
    assert!(
        held.journal
            .get(
                RecordNamespace::ControllerConsumerReadAttempt,
                &request.request_id
            )
            .is_some()
    );
    assert!(held.recheck(&mut clock).is_err());
    assert!(
        held.retain_resource_prepared(request, limits(held.journal), &mut clock)
            .is_err()
    );
    drop(held);
    drop(fixture);

    let mut cold = open(directory.path(), JournalLimits::default());
    assert_eq!(
        attempt::quarantine(&mut cold, request.request_id)
            .unwrap()
            .phase(),
        ConsumerResourceAttemptPhaseV1::ResourceQuarantined
    );
}

fn hold_for_result<'a>(
    journal: &'a mut Journal,
    path: &Path,
    wall: i64,
) -> Result<CurrentControllerConsumerResourceV1<'a>, ConsumerResourceErrorV1> {
    capture(
        journal,
        ATTACHMENT,
        consumer_resource_policy(),
        &mut || Ok(clock_at(wall)),
        Location::Fixture(path.to_owned()),
    )
}

#[test]
fn configured_family_limits_fail_before_admission_without_budget_growth() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    for bad in 0..4 {
        let mut ceilings = limits(held.journal);
        match bad {
            0 => ceilings.maximum_attempts = 0,
            1 => ceilings.maximum_materialized_bytes = 887,
            2 => ceilings.maximum_read_bytes = 6,
            _ => {
                ceilings.maximum_attempts = held
                    .journal
                    .configured_limits()
                    .maximum_materialized_records
                    + 1
            }
        }
        let sequence = held.journal.snapshot_sequence();
        // Fresh guards do not renew requests after a denied preparation.
        let request = held.request.unwrap_or_else(|| request(42));
        assert!(
            held.retain_resource_prepared(request, ceilings, &mut clock)
                .is_err()
        );
        assert_eq!(held.journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn actual_opened_global_transaction_ceiling_reserves_the_entire_local_suffix() {
    for remaining in [1, 2] {
        let (directory, fixture) = fixture();
        drop(fixture);
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let (journal, report) = Journal::open_protected_at_uid(
            directory.path(),
            CONTROLLER_JOURNAL,
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        drop(journal);
        let opened = JournalLimits {
            maximum_transactions: report.committed_transactions + remaining,
            ..JournalLimits::default()
        };
        let mut journal = open(directory.path(), opened);
        let mut held = hold(&mut journal, directory.path());
        let request = request(51);
        let before = held.journal.snapshot_sequence();
        let result = held.retain_resource_prepared(request, limits(held.journal), &mut clock);
        if remaining == 1 {
            assert!(result.is_err());
            assert_eq!(held.journal.snapshot_sequence(), before);
            assert!(
                held.journal
                    .get(
                        RecordNamespace::ControllerConsumerReadAttempt,
                        &request.request_id
                    )
                    .is_none()
            );
        } else {
            assert_eq!(
                result.unwrap().phase(),
                ConsumerResourceAttemptPhaseV1::ResourcePrepared
            );
            drop(held);
            assert_eq!(
                attempt::quarantine(&mut journal, request.request_id)
                    .unwrap()
                    .phase(),
                ConsumerResourceAttemptPhaseV1::ResourceQuarantined
            );
        }
    }
}

#[test]
fn actual_opened_journal_byte_ceiling_funds_the_full_quarantine_append() {
    for boundary in ["payload-only", "one-byte-short", "exact-full-append"] {
        let (directory, mut fixture) = fixture();
        let journal_path = directory.path().join(CONTROLLER_JOURNAL);
        let before_bytes = std::fs::metadata(&journal_path).unwrap().len();
        let request = request(53);
        let mut held = hold(fixture.journal_mut(), directory.path());
        let ceilings = limits(held.journal);
        let prepared = attempt::prepare(held.journal, request, &held.source, ceilings).unwrap();
        let attempt::Prepared::Append {
            record,
            capacity,
            transaction,
            ..
        } = prepared
        else {
            panic!("fresh fixture must prepare a new comparison record");
        };
        let (capacity_request, _, _) =
            crate::journal::decode_capacity_reservation_request_v1(capacity.record()).unwrap();
        let admission_bytes =
            crate::journal::encoded_transaction_append_bytes(&transaction).unwrap();
        // Prepared and Quarantined values have the same fixed width. This is
        // only a size projection; the actual private reducer performs cleanup.
        let terminal_shape = JournalTransaction::new(
            [54; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::ControllerConsumerReadAttempt,
                    request.request_id.to_vec(),
                    record.canonical_bytes(),
                ),
                JournalRecord::delete(
                    RecordNamespace::GlobalCapacityReservation,
                    capacity.record().key().to_vec(),
                ),
            ],
        )
        .unwrap();
        let full_terminal_bytes =
            crate::journal::encoded_transaction_append_bytes(&terminal_shape).unwrap();
        let payload_bytes =
            crate::journal::encoded_transaction_record_bytes(&terminal_shape).unwrap();
        assert!(payload_bytes < full_terminal_bytes);
        assert_eq!(capacity_request.terminal_bytes, full_terminal_bytes);
        assert_eq!(
            std::fs::metadata(&journal_path).unwrap().len(),
            before_bytes
        );
        drop(held);
        drop(fixture);

        let suffix_bytes = match boundary {
            "payload-only" => payload_bytes,
            "one-byte-short" => full_terminal_bytes - 1,
            _ => full_terminal_bytes,
        };
        let maximum_journal_bytes = before_bytes + admission_bytes + suffix_bytes;
        assert!(maximum_journal_bytes < JournalLimits::default().maximum_journal_bytes);
        let mut journal = open(
            directory.path(),
            JournalLimits {
                maximum_journal_bytes,
                ..JournalLimits::default()
            },
        );
        let sequence = journal.snapshot_sequence();
        let capacities = journal
            .records(RecordNamespace::GlobalCapacityReservation)
            .count();
        let mut held = hold(&mut journal, directory.path());
        let result = held.retain_resource_prepared(request, limits(held.journal), &mut clock);
        if boundary != "exact-full-append" {
            assert!(result.is_err(), "{boundary}");
            assert_eq!(held.journal.snapshot_sequence(), sequence, "{boundary}");
            assert_eq!(
                std::fs::metadata(&journal_path).unwrap().len(),
                before_bytes
            );
            assert!(
                held.journal
                    .get(
                        RecordNamespace::ControllerConsumerReadAttempt,
                        &request.request_id
                    )
                    .is_none()
            );
            assert_eq!(
                held.journal
                    .records(RecordNamespace::GlobalCapacityReservation)
                    .count(),
                capacities
            );
        } else {
            assert_eq!(
                result.unwrap().phase(),
                ConsumerResourceAttemptPhaseV1::ResourcePrepared
            );
            assert_eq!(
                std::fs::metadata(&journal_path).unwrap().len(),
                before_bytes + admission_bytes
            );
            drop(held);
            assert_eq!(
                attempt::quarantine(&mut journal, request.request_id)
                    .unwrap()
                    .phase(),
                ConsumerResourceAttemptPhaseV1::ResourceQuarantined
            );
            assert_eq!(
                std::fs::metadata(&journal_path).unwrap().len(),
                maximum_journal_bytes
            );
        }
    }
}

#[test]
fn generic_commit_and_capacity_only_settlement_cannot_manufacture_the_family() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let request = request(43);
    let retained = held
        .retain_resource_prepared(request, limits(held.journal), &mut clock)
        .unwrap();
    let bytes = retained.canonical_bytes();
    let reservation = <[u8; 32]>::try_from(&bytes[808..840]).unwrap();
    let sequence = held.journal.snapshot_sequence();
    let rewrite = JournalTransaction::new(
        [44; 16],
        vec![JournalRecord::put(
            RecordNamespace::ControllerConsumerReadAttempt,
            request.request_id.to_vec(),
            bytes,
        )],
    )
    .unwrap();
    assert!(held.journal.commit(&rewrite).is_err());
    let capacity = held
        .journal
        .recover_global_capacity_reservation_v1(reservation)
        .unwrap();
    let deletion = JournalTransaction::new([45; 16], vec![capacity.settlement_record()]).unwrap();
    let mut authority = held
        .journal
        .claim_global_capacity_reservation_authority(
            crate::GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
        )
        .unwrap();
    assert!(
        authority
            .preflight_reserved_terminal_v1(&capacity, &deletion)
            .is_err()
    );
    assert_eq!(held.journal.snapshot_sequence(), sequence);
}

#[test]
fn scalar_source_substitutions_cannot_pass_the_actual_owner_graph_preflight() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    held.recheck(&mut clock).unwrap();
    let ceilings = limits(held.journal);
    let before = held.journal.snapshot_sequence();
    // Private comparison data is deliberately corrupted, never upgraded to a
    // CurrentAssignmentTarget/namespace/worker authority fixture.
    for (index, offset) in [
        48, 80, 104, 136, 176, 264, 320, 376, 416, 456, 496, 560, 592,
    ]
    .into_iter()
    .enumerate()
    {
        let mut substituted = held.source.clone();
        substituted.bytes[offset] ^= 1;
        assert!(
            attempt::prepare(
                held.journal,
                request(u8::try_from(index).unwrap() + 80),
                &substituted,
                ceilings
            )
            .is_err(),
            "source offset {offset}"
        );
        assert_eq!(held.journal.snapshot_sequence(), before);
    }
}

#[test]
fn exact_canonical_format_rejects_unknown_reserved_trailing_and_altered_fields() {
    let (directory, mut fixture) = fixture();
    let mut held = hold(fixture.journal_mut(), directory.path());
    let retained = held
        .retain_resource_prepared(request(46), limits(held.journal), &mut clock)
        .unwrap();
    let bytes = retained.canonical_bytes();
    assert_eq!(
        DurableConsumerResourceAttemptV1::decode_canonical(&bytes).unwrap(),
        retained
    );
    let expected: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.controller-consumer-resource-attempt.v1\0")
        .chain_update(&bytes[..840])
        .finalize()
        .into();
    assert_eq!(&bytes[840..], &expected);
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        assert!(
            DurableConsumerResourceAttemptV1::decode_canonical(&altered).is_err(),
            "byte {index}"
        );
        assert!(
            DurableConsumerResourceAttemptV1::decode_canonical(&bytes[..index]).is_err(),
            "length {index}"
        );
    }
    for index in [8, 9, 84, 776] {
        let mut altered = bytes.clone();
        altered[index] = 3;
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-consumer-resource-attempt.v1\0")
            .chain_update(&altered[..840])
            .finalize()
            .into();
        altered[840..].copy_from_slice(&checksum);
        assert!(
            DurableConsumerResourceAttemptV1::decode_canonical(&altered).is_err(),
            "resigned byte {index}"
        );
    }
    for deadline in [0, u64::MAX] {
        let mut altered = bytes.clone();
        altered[88..96].copy_from_slice(&deadline.to_be_bytes());
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-consumer-resource-attempt.v1\0")
            .chain_update(&altered[..840])
            .finalize()
            .into();
        altered[840..].copy_from_slice(&checksum);
        assert!(DurableConsumerResourceAttemptV1::decode_canonical(&altered).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(DurableConsumerResourceAttemptV1::decode_canonical(&trailing).is_err());
}
