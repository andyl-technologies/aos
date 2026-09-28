//! Real protected append/reopen regressions with only test-local fake NV.
//!
//! These fixtures retain actual named journal writers, native replay and bounds.
//! They deliberately do not mint fixed endpoint manifests, an authenticated
//! ESYS session, installed owner configuration, readiness, or method-46 effects.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

use super::super::backend::fixture::{ExtendBehavior, FakeTpm, fake};
use super::super::head::journal_floor_cuts_v1;
use super::super::{FloorCheckpointV1, FloorIntentV1};
use super::store::{CHECKPOINT_KEY, FloorStoreV1, NAME};
use super::traffic::FixtureTrafficWriterV1;
use super::*;

type Owner = DurableTpmFloorV1<FixtureTrafficWriterV1, FakeTpm>;

struct Fixture {
    directory: tempfile::TempDir,
    uid: u32,
    limits: JournalLimits,
    profile: FloorProfileV1,
    initial: FloorCheckpointV1,
}

impl Fixture {
    fn new(limits: JournalLimits) -> (Self, Owner) {
        let directory = tempfile::Builder::new()
            .prefix("aos-tpm-floor-")
            .tempdir()
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory.path(), "session.journal", limits, uid)
                .unwrap();
        journal
            .commit(&transaction(1, vec![put(b"a", b"z")]))
            .unwrap();
        let current = journal_floor_cuts_v1(&mut journal, None).unwrap().0;
        let profile = super::super::tests::floor_fixture().0;
        let initial =
            FloorCheckpointV1::new(1, profile.scope(), current, [0; 32], [0; 32]).unwrap();

        // Provisioning exists only inside this test fixture. The runtime opener
        // cannot create, seed, repair, adopt, or reinitialize this sidecar.
        let (mut floor, _) = Journal::open_protected_at_uid(
            directory.path(),
            NAME,
            FloorStoreV1::fixture_limits(limits).unwrap(),
            uid,
        )
        .unwrap();
        floor
            .commit(&transaction(
                2,
                vec![put(CHECKPOINT_KEY, &initial.encode())],
            ))
            .unwrap();
        drop(floor);
        let fixture = Self {
            directory,
            uid,
            limits,
            profile,
            initial,
        };
        let traffic = FixtureTrafficWriterV1 {
            journal,
            directory: fixture.directory.path().to_path_buf(),
            limits,
            uid,
        };
        let owner = DurableTpmFloorV1::open(
            traffic,
            profile,
            fake(profile, initial.nv_value(), ExtendBehavior::Success),
        )
        .unwrap();
        (fixture, owner)
    }

    fn open(&self, io: FakeTpm) -> Result<Owner, FloorErrorV1> {
        self.open_with_factory(|_| Ok(io))
    }

    fn open_with_factory(
        &self,
        make_io: impl FnOnce(
            [aos_sandbox::ProtectedJournalLockCustodyV1; 2],
        ) -> Result<FakeTpm, FloorErrorV1>,
    ) -> Result<Owner, FloorErrorV1> {
        let (journal, _) = Journal::open_existing_protected_at_uid(
            self.directory.path(),
            "session.journal",
            self.limits,
            self.uid,
        )
        .map_err(|_| FloorErrorV1::Unavailable)?;
        let traffic = FixtureTrafficWriterV1 {
            journal,
            directory: self.directory.path().to_path_buf(),
            limits: self.limits,
            uid: self.uid,
        };
        DurableTpmFloorV1::open_with_factory(traffic, self.profile, make_io)
    }

    fn open_floor(&self) -> Journal {
        Journal::open_existing_protected_at_uid(
            self.directory.path(),
            NAME,
            FloorStoreV1::fixture_limits(self.limits).unwrap(),
            self.uid,
        )
        .unwrap()
        .0
    }

    fn read_main(&self) -> Vec<u8> {
        fs::read(self.directory.path().join("session.journal")).unwrap()
    }
    fn read_floor(&self) -> Vec<u8> {
        fs::read(self.directory.path().join(NAME)).unwrap()
    }
}

fn limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024,
        maximum_record_bytes: 512,
        maximum_key_bytes: 24,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 16,
        maximum_materialized_bytes: 4096,
        maximum_materialized_records: 8,
    }
}

fn put(key: &[u8], value: &[u8]) -> JournalRecord {
    JournalRecord::put(
        RecordNamespace::BrokerSessionTraffic,
        key.to_vec(),
        value.to_vec(),
    )
}

fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
    JournalTransaction::new([id; 16], records).unwrap()
}

fn update() -> JournalTransaction {
    transaction(
        5,
        vec![
            put(b"a", b"y"),
            JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, b"b".to_vec()),
        ],
    )
}

fn stop(owner: Owner) -> FakeTpm {
    let DurableTpmFloorV1 {
        traffic,
        store,
        backend,
        ..
    } = owner;
    drop(store);
    drop(traffic);
    backend.into_test_io()
}

fn prepared(
    owner: &mut Owner,
) -> (
    super::store::StoredFloorV1,
    FloorIntentV1,
    JournalTransaction,
) {
    let stored = owner.store.read(owner.profile).unwrap();
    let (intent, transaction) = stored.prepared.clone().unwrap();
    (stored, intent, transaction)
}

fn assert_current(owner: &mut Owner, expected: FloorCheckpointV1) {
    let (stored, phase) = owner.classify().unwrap();
    assert_eq!(phase, FloorRecoveryV1::Current);
    assert_eq!(stored.checkpoint, expected);
    assert!(stored.prepared.is_none());
    assert_eq!(
        owner.traffic.cuts(owner.profile, None).unwrap().0,
        expected.cut()
    );
    assert_eq!(owner.backend.read().unwrap(), expected.nv_value());
}

#[test]
fn tpm_floor_durable_opens_physical_factory_after_both_named_writers() {
    let (fixture, owner) = Fixture::new(limits());
    let io = stop(owner);
    let called = std::cell::Cell::new(false);
    let mut reopened = fixture
        .open_with_factory(|locks| {
            // These are actual protected Journal flocks, not a scalar promise
            // that the traffic/sidecar owners have been retained.
            assert!(
                Journal::open_existing_protected_at_uid(
                    fixture.directory.path(),
                    "session.journal",
                    fixture.limits,
                    fixture.uid,
                )
                .is_err()
            );
            assert!(
                Journal::open_existing_protected_at_uid(
                    fixture.directory.path(),
                    NAME,
                    FloorStoreV1::fixture_limits(fixture.limits).unwrap(),
                    fixture.uid,
                )
                .is_err()
            );
            assert_ne!(locks[0].identity().unwrap(), locks[1].identity().unwrap());
            called.set(true);
            Ok(io)
        })
        .unwrap();

    assert!(called.get());
    reopened.require_current().unwrap();
    assert_eq!(reopened.backend.test_io().extensions(), 0);
}

#[test]
fn tpm_floor_durable_missing_sidecar_never_starts_physical_factory() {
    let (fixture, owner) = Fixture::new(limits());
    let io = stop(owner);
    let before = fixture.read_main();
    let retained = fixture.directory.path().join("retained-floor.journal");
    fs::rename(fixture.directory.path().join(NAME), &retained).unwrap();
    let called = std::cell::Cell::new(false);

    let result = fixture.open_with_factory(|_| {
        called.set(true);
        Ok(io)
    });

    assert!(result.is_err());
    assert!(!called.get());
    assert_eq!(fixture.read_main(), before);
    assert!(retained.exists());
    assert!(!fixture.directory.path().join(NAME).exists());
}

#[test]
fn tpm_floor_durable_final_suffix_token_is_exact_and_expires_after_finalize() {
    let (_fixture, mut owner) = Fixture::new(limits());
    owner.prepare(&update()).unwrap();
    let (stored, _, _) = prepared(&mut owner);
    let suffix = owner.store.preflight_final(&stored, owner.profile).unwrap();
    owner
        .store
        .validate_final_preflight(&suffix, &stored, owner.profile)
        .unwrap();

    owner.recover().unwrap();

    assert!(
        owner
            .store
            .validate_final_preflight(&suffix, &stored, owner.profile)
            .is_err()
    );
    assert_eq!(owner.backend.test_io().extensions(), 1);
    owner.require_current().unwrap();
}

#[test]
fn tpm_floor_durable_held_cut_failure_cannot_extend_even_after_fresh_nv_read() {
    let (_fixture, mut owner) = Fixture::new(limits());
    owner.prepare(&update()).unwrap();
    let (_, intent, _) = prepared(&mut owner);

    let result = owner
        .backend
        .advance_with_held_cut(intent, || Err(FloorErrorV1::Unavailable));

    assert_eq!(result, Err(FloorErrorV1::Unavailable));
    assert_eq!(owner.backend.test_io().extensions(), 0);
    assert_eq!(
        owner.backend.read().unwrap(),
        intent.predecessor().nv_value()
    );
    assert_eq!(owner.classify().unwrap().1, FloorRecoveryV1::ExtendPrepared);
}

#[test]
fn tpm_floor_durable_reopens_every_exact_crash_cut_without_repeating_extend() {
    for crash_cut in 0..3 {
        let (fixture, mut owner) = Fixture::new(limits());
        let original = update();
        let before = fixture.read_main();
        owner.prepare(&original).unwrap();
        let (_, intent, retained) = prepared(&mut owner);
        assert_eq!(retained, original);
        assert_eq!(fixture.read_main(), before);

        if crash_cut >= 1 {
            assert_eq!(
                owner.backend.advance(intent).unwrap(),
                FloorAdvanceV1::Advanced
            );
        }
        if crash_cut >= 2 {
            owner
                .traffic
                .commit_exact(owner.profile, intent, &retained)
                .unwrap();
        }
        let mut reopened = fixture.open(stop(owner)).unwrap();
        assert_eq!(reopened.recover(), Ok(FloorProgressV1::Current));
        assert_current(&mut reopened, intent.target());
        assert_eq!(reopened.backend.test_io().extensions(), 1);

        // A finalized restart performs no extension or replayed journal append.
        let disk = fixture.read_main();
        let floor = fixture.read_floor();
        let mut again = fixture.open(stop(reopened)).unwrap();
        assert_eq!(again.recover(), Ok(FloorProgressV1::Current));
        assert_eq!(again.backend.test_io().extensions(), 1);
        assert_eq!(fixture.read_main(), disk);
        assert_eq!(fixture.read_floor(), floor);
    }
}

#[test]
fn tpm_floor_durable_advances_exact_ordinals_with_complete_last_preimage() {
    let (fixture, mut owner) = Fixture::new(limits());
    for (index, transaction) in [
        update(),
        transaction(6, vec![put(b"b", b"new")]),
        transaction(
            7,
            vec![JournalRecord::delete(
                RecordNamespace::BrokerSessionTraffic,
                b"a".to_vec(),
            )],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        owner.prepare(&transaction).unwrap();
        let (_, intent, retained) = prepared(&mut owner);
        assert_eq!(retained, transaction);
        assert_eq!(intent.target().ordinal(), u64::try_from(index).unwrap() + 2);
        assert_eq!(
            &intent.target().encode()[124..],
            &super::super::head::transaction_digest_v1(&transaction).unwrap()
        );
        owner.recover().unwrap();
        assert_current(&mut owner, intent.target());
        let mut restarted = fixture.open(stop(owner)).unwrap();
        assert_current(&mut restarted, intent.target());
        assert_eq!(restarted.backend.test_io().extensions(), index + 1);
        owner = restarted;
    }
}

#[test]
fn tpm_floor_durable_lost_reply_and_unwritten_retry_keep_exact_preparation() {
    for behavior in [ExtendBehavior::LostReply, ExtendBehavior::NotWritten] {
        let (fixture, mut owner) = Fixture::new(limits());
        owner.backend.test_io().set_behavior(behavior);
        owner.prepare(&update()).unwrap();
        let (_, intent, original) = prepared(&mut owner);
        let pending = fixture.read_floor();
        let main = fixture.read_main();
        let result = owner.recover().unwrap();
        if matches!(behavior, ExtendBehavior::NotWritten) {
            assert_eq!(result, FloorProgressV1::NvNotAdvanced);
            assert_eq!(fixture.read_floor(), pending);
            assert_eq!(fixture.read_main(), main);
            assert!(
                owner
                    .prepare(&transaction(9, vec![put(b"a", b"replacement")]))
                    .is_err()
            );
            assert_eq!(prepared(&mut owner).2, original);
            let mut io = stop(owner);
            io.set_behavior(ExtendBehavior::Success);
            owner = fixture.open(io).unwrap();
            assert_eq!(owner.recover(), Ok(FloorProgressV1::Current));
            assert_eq!(owner.backend.test_io().extensions(), 2);
        } else {
            assert_eq!(result, FloorProgressV1::Current);
            assert_eq!(owner.backend.test_io().extensions(), 1);
        }
        assert_current(&mut owner, intent.target());
    }
}

#[test]
fn tpm_floor_durable_rejects_nv_disk_rollback_forks_and_lost_preparation() {
    for rollback in ["main", "floor", "both"] {
        let (fixture, mut owner) = Fixture::new(limits());
        let old_main = fixture.read_main();
        let old_floor = fixture.read_floor();
        owner.prepare(&update()).unwrap();
        owner.recover().unwrap();
        let io = stop(owner);
        if rollback != "floor" {
            fs::write(fixture.directory.path().join("session.journal"), &old_main).unwrap();
        }
        if rollback != "main" {
            fs::write(fixture.directory.path().join(NAME), &old_floor).unwrap();
        }
        assert!(fixture.open(io).is_err(), "rollback {rollback}");
    }

    let (fixture, mut owner) = Fixture::new(limits());
    owner.prepare(&update()).unwrap();
    let (_, intent, original) = prepared(&mut owner);
    // An actual native commit before NV violates the mandatory ordering.
    owner
        .traffic
        .commit_exact(owner.profile, intent, &original)
        .unwrap();
    let io = stop(owner);
    assert!(matches!(fixture.open(io), Err(FloorErrorV1::Diverged)));

    let (fixture, owner) = Fixture::new(limits());
    let io = stop(owner);
    let mut main = Journal::open_existing_protected_at_uid(
        fixture.directory.path(),
        "session.journal",
        fixture.limits,
        fixture.uid,
    )
    .unwrap()
    .0;
    main.commit(&transaction(8, vec![put(b"a", b"fork")]))
        .unwrap();
    drop(main);
    assert!(fixture.open(io).is_err());
}

#[test]
fn tpm_floor_durable_refuses_false_prospective_cut_and_changed_exact_transaction() {
    for mutation in ["cut", "ID", "order", "value", "tag", "namespace"] {
        let (fixture, mut owner) = Fixture::new(limits());
        let original = update();
        let (current, target) = owner.traffic.cuts(owner.profile, Some(&original)).unwrap();
        assert_eq!(current, fixture.initial.cut());
        let false_cut =
            super::super::FloorCutV1::new(target.unwrap().sequence(), [91; 32]).unwrap();
        let cut = if mutation == "cut" {
            false_cut
        } else {
            target.unwrap()
        };
        let intent = FloorIntentV1::new(owner.profile, fixture.initial, cut, &original).unwrap();
        let io = stop(owner);
        let mut floor = fixture.open_floor();
        let altered = match mutation {
            "ID" => transaction(6, original.records().to_vec()),
            "order" => transaction(5, original.records().iter().rev().cloned().collect()),
            "value" => transaction(
                5,
                vec![put(b"a", b"changed"), original.records()[1].clone()],
            ),
            "tag" => transaction(
                5,
                vec![
                    JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, b"a".to_vec()),
                    original.records()[1].clone(),
                ],
            ),
            "namespace" => transaction(
                5,
                vec![
                    JournalRecord::put(
                        RecordNamespace::SourceProviderAuthority,
                        b"a".to_vec(),
                        b"y".to_vec(),
                    ),
                    original.records()[1].clone(),
                ],
            ),
            _ => original.clone(),
        };
        floor
            .commit(&FloorStoreV1::fixture_preparation(
                intent,
                &altered,
                fixture.limits,
            ))
            .unwrap();
        drop(floor);
        if mutation != "cut" {
            assert!(fixture.open(io).is_err());
        } else {
            let mut reopened = fixture.open(io).unwrap();
            assert!(reopened.recover().is_err());
            assert_eq!(reopened.backend.test_io().extensions(), 0);
        }
    }
}

#[test]
fn tpm_floor_durable_missing_empty_torn_and_unknown_sidecar_never_seed_or_repair() {
    for damage in ["missing", "empty", "torn-floor", "torn-main", "unknown"] {
        let (fixture, owner) = Fixture::new(limits());
        let io = stop(owner);
        let floor_path = fixture.directory.path().join(NAME);
        match damage {
            "missing" => {
                fs::remove_file(&floor_path).unwrap();
            }
            "empty" => {
                fs::remove_file(&floor_path).unwrap();
                let (empty, _) = Journal::open_protected_at_uid(
                    fixture.directory.path(),
                    NAME,
                    FloorStoreV1::fixture_limits(fixture.limits).unwrap(),
                    fixture.uid,
                )
                .unwrap();
                drop(empty);
            }
            "torn-floor" | "torn-main" => {
                let path = if damage == "torn-main" {
                    fixture.directory.path().join("session.journal")
                } else {
                    floor_path.clone()
                };
                let mut file = OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(b"torn-frame").unwrap();
                file.sync_all().unwrap();
            }
            "unknown" => {
                let mut floor = fixture.open_floor();
                floor
                    .commit(&transaction(7, vec![put(b"unexpected", b"row")]))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let prior = fs::read(&floor_path).ok();
        let main = fixture.read_main();
        assert!(fixture.open(io).is_err(), "damage {damage}");
        assert_eq!(fs::read(&floor_path).ok(), prior);
        assert_eq!(fixture.read_main(), main);
    }
}

#[test]
fn tpm_floor_durable_compaction_and_unrelated_sidecar_append_close_replay() {
    for pending in [false, true] {
        let (fixture, mut owner) = Fixture::new(limits());
        owner.prepare(&update()).unwrap();
        if !pending {
            owner.recover().unwrap();
        }
        let io = stop(owner);
        let mut floor = fixture.open_floor();
        floor.compact().unwrap();
        drop(floor);
        assert!(fixture.open(io).is_err());
    }

    let (fixture, mut owner) = Fixture::new(limits());
    owner.prepare(&update()).unwrap();
    let (stored, _, _) = prepared(&mut owner);
    let io = stop(owner);
    let mut floor = fixture.open_floor();
    // Even an otherwise identical checkpoint rewrite changes frame geometry.
    floor
        .commit(&transaction(
            9,
            vec![put(CHECKPOINT_KEY, &stored.checkpoint.encode())],
        ))
        .unwrap();
    drop(floor);
    assert!(fixture.open(io).is_err());
}

#[test]
fn tpm_floor_durable_preflights_main_and_full_sidecar_suffix_before_prepare() {
    let (fixture, mut owner) = Fixture::new(JournalLimits {
        maximum_transactions: 1,
        ..limits()
    });
    let floor = fixture.read_floor();
    let main = fixture.read_main();
    assert!(owner.prepare(&update()).is_err());
    assert_eq!(fixture.read_floor(), floor);
    assert_eq!(fixture.read_main(), main);
    assert_eq!(owner.backend.test_io().extensions(), 0);

    // Determine the native encoded sizes through actual appends, not copied
    // journal frame arithmetic. Admit exactly the preparation, but no final.
    let (sizing, mut sample) = Fixture::new(limits());
    sample.prepare(&update()).unwrap();
    let pending_bytes = u64::try_from(sizing.read_floor().len()).unwrap();
    let (_, intent, _) = prepared(&mut sample);
    sample.recover().unwrap();
    assert!(u64::try_from(sizing.read_floor().len()).unwrap() > pending_bytes);
    assert_eq!(intent.target().ordinal(), 2);
    drop(sample);

    let tight = JournalLimits {
        maximum_journal_bytes: pending_bytes,
        ..limits()
    };
    let (fixture, mut owner) = Fixture::new(tight);
    let initial = fixture.read_floor();
    let original = update();
    let (_, target) = owner.traffic.cuts(owner.profile, Some(&original)).unwrap();
    let intent =
        FloorIntentV1::new(owner.profile, fixture.initial, target.unwrap(), &original).unwrap();
    let preparation = FloorStoreV1::fixture_preparation(intent, &original, tight);
    let finalization = FloorStoreV1::fixture_finalization(intent);
    assert!(
        owner
            .store
            .fixture_preflight(core::slice::from_ref(&preparation))
            .is_ok()
    );
    assert!(
        owner
            .store
            .fixture_preflight(&[preparation, finalization])
            .is_err()
    );
    assert!(owner.prepare(&original).is_err());
    assert_eq!(fixture.read_floor(), initial);
    assert_eq!(owner.backend.test_io().extensions(), 0);
}

#[test]
fn tpm_floor_durable_retains_both_locks_and_rechecks_fixed_names_before_nv() {
    for changed_name in ["session.journal", NAME, "session-floor.journal.lock"] {
        let (fixture, mut owner) = Fixture::new(limits());
        assert!(
            Journal::open_existing_protected_at_uid(
                fixture.directory.path(),
                "session.journal",
                fixture.limits,
                fixture.uid
            )
            .is_err()
        );
        assert!(
            Journal::open_existing_protected_at_uid(
                fixture.directory.path(),
                NAME,
                FloorStoreV1::fixture_limits(fixture.limits).unwrap(),
                fixture.uid
            )
            .is_err()
        );
        owner.prepare(&update()).unwrap();
        let path = fixture.directory.path().join(changed_name);
        let backup = fixture
            .directory
            .path()
            .join(format!("{changed_name}.saved"));
        fs::rename(&path, backup).unwrap();
        // Replace only this fixture's known owned path; no broad directory or
        // system-state mutation occurs in the test.
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(owner.recover().is_err());
        assert_eq!(owner.backend.test_io().extensions(), 0);
    }
}

#[test]
fn tpm_floor_durable_nv_missing_third_value_and_power_loss_never_commit() {
    for behavior in [
        ExtendBehavior::DeletedByPowerLoss,
        ExtendBehavior::CompetingExtension,
    ] {
        let (fixture, mut owner) = Fixture::new(limits());
        owner.backend.test_io().set_behavior(behavior);
        let main = fixture.read_main();
        owner.prepare(&update()).unwrap();
        let pending = fixture.read_floor();
        assert!(owner.recover().is_err());
        assert_eq!(owner.backend.test_io().extensions(), 1);
        assert_eq!(fixture.read_main(), main);
        assert_eq!(fixture.read_floor(), pending);
        assert!(fixture.open(stop(owner)).is_err());
    }

    let (fixture, owner) = Fixture::new(limits());
    let mut io = stop(owner);
    io.set_value(None);
    assert!(fixture.open(io).is_err());
}
