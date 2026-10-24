//! Exercises native read-only closing without granting effect compatibility.

use super::super::history_inputs::ControlPinRecords;
use super::*;
use crate::bucket::held::SingleHeld;
use crate::store::{StoreErrorKind, TokioLocalFs};
use std::os::unix::fs::PermissionsExt;
use terrane_format::auth::Verb;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn native_token_refusal_preserves_registered_error_kind() {
    let failure = crate::guard::denied("refs/heads/_/main", Verb::Read);
    let expected = failure.kind().clone();
    let actual = current_read_failure(std::io::Error::other(failure));
    assert_eq!(actual.kind(), &expected);
    let unavailable = current_read_failure(std::io::Error::other("native physical fault"));
    assert!(matches!(
        unavailable.kind(),
        StoreErrorKind::Unavailable { .. }
    ));
}

/// Closes a genuine factory-initialized selection and actual Original controls.
async fn close_fixture(replace: bool, unsafe_control: bool) -> TestResult {
    let fixture = crate::ref_advance::tests::fixture().await;
    let guard = fixture.guard();
    let bucket = guard.store();
    let key = BucketKey::parse("objects/index/2/MANIFEST")?;
    let path = bucket.root().join(key.as_str());
    std::fs::create_dir_all(path.parent().ok_or("artifact parent")?)?;
    std::fs::write(&path, b"actual ordinary current-history bytes")?;
    std::fs::hard_link(&path, path.with_file_name("public-alias"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;

    let holder = SingleHeld::acquire_read_namespace(bucket).await?;
    let held = holder.source();
    assert!(!held.identity_proof().writable());
    let observed = held.observe_publication_ordinary_retained().await?;
    let read = bucket.read_optional_ordinary_retained(&key).await?;
    assert!(read.is_ordinary_retained());
    assert!(read.require_effect_compatible().is_err());
    let authority = guard.configured_original_authority()?;
    let mut exclusion = guard
        .hold_original_registration(&authority, observed.identity())
        .await?;
    let controls = exclusion.retain_used(&[]).await?;
    let token = crate::ref_advance::tests::token();
    let current =
        PendingCurrentReadCheck::for_guard(guard, "refs/heads/_/main", &token, Verb::Read)?;

    if replace {
        let bytes = std::fs::read(&path)?;
        std::fs::rename(&path, path.with_file_name("original"))?;
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    }
    let previous = std::fs::symlink_metadata(controls.directory())?.permissions();
    if unsafe_control {
        std::fs::set_permissions(controls.directory(), std::fs::Permissions::from_mode(0o777))?;
    }
    let closed = close_current_history_inputs(
        &TokioLocalFs,
        &observed,
        std::slice::from_ref(&controls),
        &[],
        vec![read],
        &current,
    )
    .await;
    if unsafe_control {
        std::fs::set_permissions(controls.directory(), previous)?;
    }

    if replace || unsafe_control {
        assert!(closed.is_err());
    } else {
        let closed = closed?;
        assert!(std::ptr::eq(closed.observed(), &observed));
        assert_eq!(closed.controls().len(), 1);
        assert!(closed.original_reads().is_empty());
        assert_eq!(closed.payload_reads().len(), 1);
        assert!(
            closed.payload_reads()[0]
                .require_effect_compatible()
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn current_close_preserves_public_hardlinked_data_under_read_only_holder() -> TestResult {
    close_fixture(false, false).await
}

#[tokio::test]
async fn current_close_refuses_equal_bytes_replaced_original_data() -> TestResult {
    close_fixture(true, false).await
}

#[tokio::test]
async fn current_close_keeps_original_control_protection_strict() -> TestResult {
    close_fixture(false, true).await
}

/// Changes one captured protected input after genuine factory publication.
async fn close_changed_protected_input(selected_guard: bool, change: Option<bool>) -> TestResult {
    use std::os::unix::fs::MetadataExt;
    use terrane_format::gc::publication::evidence::ControlKind;

    let fixture = crate::ref_advance::tests::fixture().await;
    let token = crate::ref_advance::tests::token();
    let reference = "refs/heads/_/main";
    let mut writer = fixture.begin(reference, &token, "sdk").await?;
    let head = fixture
        .advance(&mut writer, crate::ref_advance::tests::request(Vec::new()))
        .await?;
    let guard = fixture.guard();
    let bucket = guard.store();
    let holder = SingleHeld::acquire_read_namespace(bucket).await?;
    let held = holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;
    let snapshot = held
        .selected_guard_snapshot_record_retained(&observed)
        .await?
        .ok_or("selected Guard snapshot absent")?;
    let authority = guard.configured_original_authority()?;
    let mut exclusion = guard
        .hold_original_registration(&authority, observed.identity())
        .await?;
    let context = guard.original_commit(&head.commit)?;
    let pin = crate::guard::publication_original_pins(&context)?
        .into_iter()
        .find(|pin| pin.kind == ControlKind::Association)
        .ok_or("actual Original association absent")?;
    let bytes = exclusion.read_record(&pin.key).await?;
    pin.check_record(&bytes)?;
    let controls = exclusion.retain_named(&[(pin.key.clone(), bytes)]).await?;
    let mut pin_records = ControlPinRecords::new(std::slice::from_ref(&controls));
    pin_records.check(&pin)?;
    assert_eq!(controls.records().len(), 1);
    assert!(!held.identity_proof().writable());
    let current = PendingCurrentReadCheck::for_guard(guard, reference, &token, Verb::Read)?;

    let path = if selected_guard {
        snapshot.path()
    } else {
        controls.records()[0].path()
    };
    let original_bytes = std::fs::read(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if change == Some(true) {
        // Equal bytes and protection must not substitute a new physical leaf.
        std::fs::rename(path, path.with_extension("captured-original"))?;
        std::fs::write(path, &original_bytes)?;
        std::fs::set_permissions(path, metadata.permissions())?;
        assert_ne!(std::fs::symlink_metadata(path)?.ino(), metadata.ino());
        assert_eq!(std::fs::read(path)?, original_bytes);
    } else if change == Some(false) {
        // Keep the named incarnation while invalidating the consumed body.
        let mut changed = original_bytes.clone();
        let first = changed.first_mut().ok_or("empty protected record")?;
        *first ^= 1;
        std::fs::write(path, &changed)?;
        assert_eq!(std::fs::symlink_metadata(path)?.ino(), metadata.ino());
        assert_ne!(std::fs::read(path)?, original_bytes);
    }

    // Indexed captured bytes still match after a body or incarnation change.
    // They supply no freshness: the native close must reject the actual change.
    pin_records.check(&pin)?;
    let closed = close_current_history_inputs(
        &TokioLocalFs,
        &observed,
        std::slice::from_ref(&controls),
        &[snapshot],
        Vec::new(),
        &current,
    )
    .await;
    if change.is_some() {
        let expected = if !selected_guard && change == Some(true) {
            // The retained control incarnation is checked before native submission.
            StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into()))
        } else {
            StoreErrorKind::Unavailable { retry_after: None }
        };
        let failure = match closed {
            Err(failure) => failure,
            Ok(_) => panic!("changed captured protected input must refuse closing"),
        };
        assert_eq!(failure.kind(), &expected);
    } else {
        let closed = closed?;
        assert_eq!(closed.original_reads().len(), 1);
        assert_eq!(closed.controls()[0].records().len(), 1);
        assert!(!held.identity_proof().writable());
    }
    Ok(())
}

#[tokio::test]
async fn current_close_refuses_equal_bytes_replaced_selected_guard_snapshot() -> TestResult {
    close_changed_protected_input(true, Some(true)).await
}

#[tokio::test]
async fn current_close_refuses_equal_bytes_replaced_retained_original_control() -> TestResult {
    close_changed_protected_input(false, Some(true)).await
}

#[tokio::test]
async fn current_close_refuses_changed_body_of_retained_original_control() -> TestResult {
    close_changed_protected_input(false, Some(false)).await
}

#[tokio::test]
async fn current_close_preserves_captured_selected_guard_and_original_control() -> TestResult {
    close_changed_protected_input(false, None).await
}

/// Counts exact scalar path construction independently of native physical I/O.
fn scalar_pin_lookup(
    controls: &[RetainedControls],
    pins: &[terrane_format::gc::publication::evidence::RequiredControlPin],
) -> Result<usize, StoreFailure> {
    let mut joined_paths = 0;
    for pin in pins {
        let terrane_format::gc::publication::evidence::PhysicalRegistration::Local(owner) =
            &pin.owner
        else {
            return Err(unsupported());
        };
        let retained = controls
            .iter()
            .find(|retained| {
                retained.directory().as_os_str().as_encoded_bytes() == owner.control.as_slice()
            })
            .ok_or_else(unsupported)?;
        let record = retained
            .records()
            .iter()
            .find(|record| {
                joined_paths += 1;
                record.path() == retained.directory().join(&pin.key)
            })
            .ok_or_else(unsupported)?;
        pin.check_record(record.bytes()).map_err(|_| corrupt())?;
    }
    Ok(joined_paths)
}

#[tokio::test]
async fn candidate_pin_lookup_reuses_exact_control_paths_with_scalar_refusals() -> TestResult {
    use terrane_format::gc::publication::evidence::ControlKind;

    let fixture = crate::ref_advance::tests::fixture().await;
    let token = crate::ref_advance::tests::token();
    let reference = "refs/heads/_/main";
    let mut writer = fixture.begin(reference, &token, "sdk").await?;
    let head = fixture
        .advance(&mut writer, crate::ref_advance::tests::request(Vec::new()))
        .await?;
    let guard = fixture.guard();
    let bucket = guard.store();
    let holder = SingleHeld::acquire_read_namespace(bucket).await?;
    let held = holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;
    let authority = guard.configured_original_authority()?;
    let context = guard.original_commit(&head.commit)?;
    let pins = crate::guard::publication_original_pins(&context)?;
    assert!(pins.len() >= 3);
    assert!(pins.iter().any(|pin| pin.kind == ControlKind::Association));
    let unique_keys = pins
        .iter()
        .map(|pin| pin.key.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique_keys.len(), pins.len());
    let mut exclusion = guard
        .hold_original_registration(&authority, observed.identity())
        .await?;
    let empty = exclusion.retain_used(&[]).await?;
    let retained = exclusion.retain_used(&pins).await?;
    let controls = std::slice::from_ref(&retained);

    let scalar_joins = scalar_pin_lookup(controls, &pins)?;
    let mut indexed = ControlPinRecords::new(controls);
    for pin in &pins {
        indexed.check(pin)?;
    }
    assert_eq!(indexed.work(), (pins.len(), pins.len()));
    assert_eq!(scalar_joins, pins.len() * (pins.len() + 1) / 2);
    assert!(scalar_joins > indexed.work().1);
    for pin in &pins {
        indexed.check(pin)?;
    }
    assert_eq!(indexed.work(), (pins.len(), 2 * pins.len()));

    // A later complete receipt cannot fill the selected first receipt's gap.
    let duplicates = [empty, retained.clone()];
    let expected: StoreFailure = match scalar_pin_lookup(&duplicates, &pins) {
        Err(failure) => failure,
        Ok(_) => panic!("scalar lookup must refuse the first receipt's missing record"),
    };
    let actual: StoreFailure = match ControlPinRecords::new(&duplicates).check(&pins[0]) {
        Err(failure) => failure,
        Ok(()) => panic!("indexed lookup must refuse the first receipt's missing record"),
    };
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.kind(), &StoreErrorKind::Unsupported);

    let mut changed = pins[0].clone();
    changed.digest[0] ^= 1;
    let mut missing = pins[0].clone();
    missing.key = "missing-consumed-control.cbor".to_owned();
    for ordered in [[changed.clone(), missing.clone()], [missing, changed]] {
        let expected: StoreFailure = match scalar_pin_lookup(controls, &ordered) {
            Err(failure) => failure,
            Ok(_) => panic!("scalar lookup must refuse the first invalid pin"),
        };
        let mut indexed = ControlPinRecords::new(controls);
        let actual: StoreFailure = match ordered.iter().try_for_each(|pin| indexed.check(pin)) {
            Err(failure) => failure,
            Ok(()) => panic!("indexed lookup must refuse the first invalid pin"),
        };
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(indexed.work().1, 1);
    }

    Ok(())
}
