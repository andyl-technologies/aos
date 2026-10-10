//! Exercises real pinned input custody with the local catalog mechanism bank.
//!
//! These files and fixture accounts do not authenticate a Parent invocation,
//! native source role, immutable workflow or execution permission.

// crucible-lint: allow panic-shortcut -- failed real-file ownership assertions stop these controls.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;
use crate::private_measurement_runtime::catalog::tests::{fixture, fixture_original};

pub(super) fn empty_owner(budget: &DecodeBudget) -> OriginalWorkflowArtifactsOwner {
    OriginalWorkflowArtifactsOwner {
        executor_config: None,
        lifecycle: None,
        projection: None,
        files: Vec::new(),
        models: Vec::new(),
        budget: budget.clone(),
        custody: budget.custody(),
        closed: false,
    }
}

pub(super) fn input(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("compact.bin");
    std::fs::write(&path, b"actual compact bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    path
}

pub(super) fn install_configuration_fixture(
    owner: &mut OriginalWorkflowArtifactsOwner,
    path: &std::path::Path,
    run_state_root: &std::path::Path,
) {
    let configuration =
        crucible_api::ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(
            crucible_api::vm_lifecycle::ProductionVmGuestAssetPaths {
                executable: path,
                plugin: path,
                architecture: crucible::model::VmArchitecture::X86_64,
                kernel: path,
                root_image: path,
                initrd: None,
                root_image_format: crucible_qemu::QemuRootImageFormat::Raw,
                run_state_root,
            },
            &owner.budget,
        )
        .unwrap();
    owner.lifecycle = Some(std::sync::Arc::new(configuration));
}

#[test]
fn configuration_alias_refuses_close_and_keeps_the_same_body() {
    let (_, decoder, catalog) = fixture();
    let budget = decoder.budget().unwrap();
    let original = fixture_original(&catalog);
    let check = || original.wait_slice().map(|_| ());
    let directory = tempfile::TempDir::new().unwrap();
    let path = input(directory.path());
    let mut owner = empty_owner(budget);
    install_configuration_fixture(&mut owner, &path, directory.path());
    let alias = std::sync::Arc::clone(owner.lifecycle.as_ref().unwrap());
    let mut failure = ArtifactFailurePurpose::prepare(budget, &check).unwrap();

    let refusal = lifecycle::close_configuration(&mut owner, &failure.work(&check)).unwrap_err();
    let error = failure.finish::<()>(Err(refusal)).unwrap_err();

    assert!(matches!(
        error.cause(),
        Some(ArtifactCause::LifecycleAliases)
    ));
    assert!(std::sync::Arc::ptr_eq(
        &alias,
        owner.lifecycle.as_ref().unwrap()
    ));
    drop(error);
    drop(alias);
    let mut failure = ArtifactFailurePurpose::prepare(budget, &check).unwrap();
    lifecycle::close_configuration(&mut owner, &failure.work(&check)).unwrap();
    failure.finish(Ok(())).unwrap();
    owner.closed = true;
    drop(owner);
    catalog.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn configuration_closes_while_actual_input_pin_and_credit_remain_owned() {
    let (_, decoder, catalog) = fixture();
    let budget = decoder.budget().unwrap();
    let original = fixture_original(&catalog);
    let check = || original.wait_slice().map(|_| ());
    let directory = tempfile::TempDir::new().unwrap();
    let path = input(directory.path());
    let mut owner = empty_owner(budget);
    let mut failure = ArtifactFailurePurpose::prepare(budget, &check).unwrap();
    owner.files.push(PinnedInput::reserved(budget).unwrap());
    let metadata = owner.files[0]
        .open_fixture(&path, &failure.work(&check))
        .unwrap();
    let digest = blake3::hash(b"actual compact bytes").to_hex().to_string();
    owner.files[0]
        .authenticate_stream(metadata.len(), &digest, &failure.work(&check))
        .unwrap();
    let descriptor = owner.files[0].file.as_ref().unwrap().as_raw_fd();
    install_configuration_fixture(&mut owner, &path, directory.path());

    lifecycle::close_configuration(&mut owner, &failure.work(&check)).unwrap();

    assert!(owner.lifecycle.is_none());
    let retained = std::fs::metadata(format!("/proc/self/fd/{descriptor}")).unwrap();
    assert_eq!(
        (retained.dev(), retained.ino()),
        (metadata.dev(), metadata.ino())
    );
    budget.verify_live().unwrap();
    owner.files[0].close();
    owner.files.clear();
    failure.finish(Ok(())).unwrap();
    owner.closed = true;
    drop(owner);
    catalog.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn actual_pin_hash_eof_and_buffer_close_before_descriptor_refund() {
    let (_, decoder, catalog) = fixture();
    let budget = decoder.budget().unwrap();
    let original = fixture_original(&catalog);
    let check = || original.wait_slice().map(|_| ());
    let mut failure = ArtifactFailurePurpose::prepare(budget, &check).unwrap();
    let check = failure.work(&check);
    let directory = tempfile::TempDir::new().unwrap();
    let path = input(directory.path());
    let mut pin = PinnedInput::reserved(budget).unwrap();

    let metadata = pin.open_fixture(&path, &check).unwrap();
    let digest = blake3::hash(b"actual compact bytes").to_hex().to_string();
    assert_eq!(
        pin.authenticate_stream(metadata.len(), &digest, &check)
            .unwrap(),
        *b"actu"
    );
    // A second independently pinned file starts from its actual offset zero.
    pin.close();
    pin = PinnedInput::reserved(budget).unwrap();
    pin.open_fixture(&path, &check).unwrap();
    pin.read_compact(metadata.len(), &digest, budget, &check)
        .unwrap();
    assert_eq!(
        pin.bytes.as_deref(),
        Some(b"actual compact bytes".as_slice())
    );
    pin.close();
    assert!(pin.file.is_none());
    assert!(pin.bytes.is_none());
    failure.finish(Ok(())).unwrap();
}

#[test]
fn successful_open_then_real_cancel_retains_actual_file_across_owner_drop() {
    let (root, decoder, catalog) = fixture();
    let budget = decoder.budget().unwrap();
    let original = fixture_original(&catalog);
    let directory = tempfile::TempDir::new().unwrap();
    let path = input(directory.path());
    let mut owner = empty_owner(budget);
    owner.files.push(PinnedInput::reserved(budget).unwrap());
    let calls = Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            root.cancel().unwrap();
        }
        original.wait_slice().map(|_| ())
    };

    let mut failure =
        ArtifactFailurePurpose::prepare(budget, &|| original.wait_slice().map(|_| ())).unwrap();
    let check = failure.work(&check);
    let refusal = owner.files[0].open_fixture(&path, &check).err().unwrap();
    let error = failure
        .finish::<std::fs::Metadata>(Err(refusal))
        .unwrap_err();
    assert!(matches!(
        error.cause(),
        Some(ArtifactCause::OriginalBoundary(_))
    ));
    let file = owner.files[0].file.as_ref().unwrap();
    let identity = file.metadata().unwrap();
    let descriptor = file.as_raw_fd();
    drop(owner);

    let retained = std::fs::metadata(format!("/proc/self/fd/{descriptor}")).unwrap();
    assert_eq!(
        (retained.dev(), retained.ino()),
        (identity.dev(), identity.ino())
    );
}

#[test]
fn real_open_error_remains_first_before_actual_later_original_cancel() {
    let (root, decoder, catalog) = fixture();
    let original = fixture_original(&catalog);
    let directory = tempfile::TempDir::new().unwrap();
    let mut owner = empty_owner(decoder.budget().unwrap());
    owner
        .files
        .push(PinnedInput::reserved(decoder.budget().unwrap()).unwrap());
    let calls = Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            root.cancel().unwrap();
        }
        original.wait_slice().map(|_| ())
    };

    let mut failure = ArtifactFailurePurpose::prepare(decoder.budget().unwrap(), &|| {
        original.wait_slice().map(|_| ())
    })
    .unwrap();
    let check = failure.work(&check);
    let refusal = owner.files[0]
        .open_fixture(&directory.path().join("absent"), &check)
        .err()
        .unwrap();
    let error = failure
        .finish::<std::fs::Metadata>(Err(refusal))
        .unwrap_err();
    assert!(matches!(error.cause(), Some(ArtifactCause::Kernel(source))
        if source.kind() == std::io::ErrorKind::NotFound));
    assert!(error.original_after().is_some());
    assert!(owner.files[0].file.is_none());
}

#[test]
fn unwind_retains_the_actual_open_pin_and_same_original_custody() {
    let (_, decoder, catalog) = fixture();
    let original = fixture_original(&catalog);
    let check = || original.wait_slice().map(|_| ());
    let directory = tempfile::TempDir::new().unwrap();
    let path = input(directory.path());
    let descriptor = Cell::new(None);
    let identity = std::fs::metadata(&path).unwrap();

    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut failure =
            ArtifactFailurePurpose::prepare(decoder.budget().unwrap(), &check).unwrap();
        let check = failure.work(&check);
        let mut owner = empty_owner(decoder.budget().unwrap());
        owner
            .files
            .push(PinnedInput::reserved(decoder.budget().unwrap()).unwrap());
        owner.files[0].open_fixture(&path, &check).unwrap();
        descriptor.set(Some(owner.files[0].file.as_ref().unwrap().as_raw_fd()));
        panic!("pinned input unwind");
    }));

    assert!(failed.is_err());
    let retained =
        std::fs::metadata(format!("/proc/self/fd/{}", descriptor.get().unwrap())).unwrap();
    assert_eq!(
        (retained.dev(), retained.ino()),
        (identity.dev(), identity.ino())
    );
}

#[test]
fn failure_body_admission_refuses_exhausted_original_before_file_work() {
    let (_, decoder, catalog) = fixture();
    let budget = decoder.budget().unwrap();
    let original = fixture_original(&catalog);
    assert!(budget.reserve_scratch_bytes(4 << 20).is_err());

    let refusal = ArtifactFailurePurpose::prepare(budget, &|| original.wait_slice().map(|_| ()))
        .err()
        .unwrap();

    assert!(refusal.is_storage_admission());
}

#[test]
fn actual_failure_body_keeps_decoder_custody_through_error_drop() {
    let (_, decoder, catalog) = fixture();
    let original = fixture_original(&catalog);
    let mut purpose = ArtifactFailurePurpose::prepare(decoder.budget().unwrap(), &|| {
        original.wait_slice().map(|_| ())
    })
    .unwrap();
    let refusal = purpose
        .work(&|| original.wait_slice().map(|_| ()))
        .error(ArtifactCause::Identity);
    let error = purpose.finish::<()>(Err(refusal)).unwrap_err();
    catalog.try_close().unwrap();

    let retained = decoder.try_close().err().unwrap();
    assert!(matches!(error.cause(), Some(ArtifactCause::Identity)));
    drop(error);
    // This consuming failed close is terminal; a separate control below proves
    // error-drop-before-first-close rather than claiming retry on this decoder.
    drop(retained);
}

#[test]
fn failure_body_drop_precedes_first_healthy_decoder_close() {
    let (_, decoder, catalog) = fixture();
    let original = fixture_original(&catalog);
    let mut purpose = ArtifactFailurePurpose::prepare(decoder.budget().unwrap(), &|| {
        original.wait_slice().map(|_| ())
    })
    .unwrap();
    let refusal = purpose
        .work(&|| original.wait_slice().map(|_| ()))
        .error(ArtifactCause::Identity);
    let error = purpose.finish::<()>(Err(refusal)).unwrap_err();
    catalog.try_close().unwrap();

    drop(error);
    assert!(decoder.try_close().is_ok());
}

#[test]
fn paid_json_failure_keeps_artifact_body_and_decoder_custody() {
    // crucible-lint: allow direct-diagnostic -- reports the actual reserved body and its holders, not allocator rounding or stack qualification.
    eprintln!(
        "Artifact target geometry: Data={} Purpose={} Error={}",
        ArtifactFailurePurpose::body_bytes_for_test(),
        std::mem::size_of::<ArtifactFailurePurpose>(),
        std::mem::size_of::<OriginalWorkflowArtifactsError>()
    );

    let (_, decoder, catalog) = fixture();
    let original = fixture_original(&catalog);
    let budget = decoder.budget().unwrap();
    let check = || original.wait_slice().map(|_| ());
    let mut purpose = ArtifactFailurePurpose::prepare(budget, &check).unwrap();

    let json = match from_json_slice_closed::<Projection>(b"{}", budget) {
        Ok(_) => panic!("missing required asset fields were accepted"),
        Err(error) => error,
    };
    let refusal = purpose
        .work(&check)
        .checked::<()>(Err(ArtifactCause::Json(json)))
        .unwrap_err();
    let error = purpose.finish::<()>(Err(refusal)).unwrap_err();
    assert!(
        matches!(error.cause(), Some(ArtifactCause::Json(ClosedJsonError::Json(source)))
        if source.is_data() && source.line() == 1)
    );
    assert!(error.original_after().is_none());
    catalog.try_close().unwrap();

    drop(error);
    assert!(decoder.try_close().is_ok());
}
