//! Exercises actual Source construction with declared, unselected target grammar.

use super::*;
use crate::node_qualification::packet_collection::complete::{
    records::validate_original_native_definition_data, tests::native_roundtrip,
};
use crucible_node_transport::reference_packet::service::native_startup::restoration_suffix_schema;

#[test]
fn original_five_constructs_full_suffix_grammar_without_selecting_startup_sixteen() {
    // The existing fixture measures and copies this ELF only as constructor
    // DATA. No process is launched and it is never treated as a native receipt.
    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    let selected: Manifest = serde_json::from_value(declaration).unwrap();
    let content = super::super::manifest::content(selected.content).unwrap();

    let (sources, _) = prepare_sources(
        selected.participants,
        &selected.coordinator,
        selected.maximum_native_rows,
        selected.maximum_initial_bytes,
        selected.mechanism,
        true,
        true,
        true,
        false,
        &content,
    )
    .unwrap();

    let suffix = restoration_suffix_schema().unwrap();
    for (member, source) in sources.iter().enumerate() {
        assert!(
            source
                .is_original_restoration_observation_declaration_data()
                .unwrap()
        );
        assert!(
            !source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        );
        validate_original_native_definition_data(source, &content, member).unwrap();

        let mut missing = content.clone();
        assert!(missing.remove(&suffix.definition).is_some());
        assert!(validate_original_native_definition_data(source, &missing, member,).is_err());

        let mut changed = content.clone();
        changed.insert(suffix.definition.clone(), b"changed suffix bytes".to_vec());
        assert!(validate_original_native_definition_data(source, &changed, member,).is_err());
        assert!(
            !source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        );
    }
}

#[test]
fn full_invocation_fresh_report_quote_preserves_sixty_four_kib_query_limits() {
    use crucible_node_transport::reference_packet::service::report_startup::{
        PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA, PacketNativeReportStartupAllocation,
        PacketNativeReportStartupAllocationRow, PacketNativeReportStartupPurpose,
        original_invocation_report_startup_allocation_peak_data,
        original_invocation_report_startup_storage_data,
    };

    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    let selected: Manifest = serde_json::from_value(declaration).unwrap();
    let measurements = selected.measurements.map(|one| PacketFixtureMeasurements {
        peer: artifact(one.peer),
        host: one.host,
        sources: one.sources.into_iter().map(artifact).collect(),
    });
    let content = super::super::manifest::content(selected.content).unwrap();
    let (_sources, declarations) = prepare_sources(
        selected.participants,
        &selected.coordinator,
        selected.maximum_native_rows,
        selected.maximum_initial_bytes,
        selected.mechanism,
        true,
        true,
        true,
        false,
        &content,
    )
    .unwrap();
    let initial_bytes = encoded(&selected.coordinator).unwrap();
    let initial = InstalledContent {
        reference: canonical::content_ref(&initial_bytes, "application/json").unwrap(),
        bytes: Bytes::new(initial_bytes),
    };
    let directory = tempfile::tempdir().unwrap();
    let paths =
        std::array::from_fn(|member| directory.path().join(format!("effect-{member}.sock")));
    let launches = launch_declarations(
        declarations,
        &selected.coordinator,
        &initial,
        &measurements,
        &paths,
    )
    .unwrap();

    // These are the actual same Source-selected full32-format launch records
    // from the installed regression. No native process or receipt is created.
    for mut launch in launches {
        assert_eq!(launch.limits.frame_bytes.get(), 65_536);
        let data = original_invocation_report_startup_storage_data(
            &launch,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
        )
        .unwrap();
        assert_eq!(data.raw_report_capacity(), 16_384);
        assert!(data.retained_growth_bytes() > 0);
        assert!(data.maximum_simultaneous_transient_bytes() > 0);

        let row = |purpose| {
            let quote = original_invocation_report_startup_storage_data(&launch, purpose).unwrap();
            PacketNativeReportStartupAllocationRow {
                raw_report_capacity: U64::new(quote.raw_report_capacity() as u64),
                retained_growth_bytes: U64::new(quote.retained_growth_bytes() as u64),
                maximum_simultaneous_transient_bytes: U64::new(
                    quote.maximum_simultaneous_transient_bytes() as u64,
                ),
                declared_counter_scratch_bytes: U64::new(
                    quote.declared_counter_scratch_bytes() as u64
                ),
            }
        };
        let original = row(PacketNativeReportStartupPurpose::OriginalObserve12);
        let fresh = row(PacketNativeReportStartupPurpose::FreshCompletedAdmit13);
        let allocation = PacketNativeReportStartupAllocation {
            schema: PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA.into(),
            original_observe12: Some(original),
            fresh_completed_admit13: Some(fresh),
        };
        let expected = allocation.requested_peak_data().unwrap();
        assert!(expected > 512 * 1024 * 1024);
        for one in [original, fresh] {
            assert!(one.requested_peak_data().unwrap() <= 512 * 1024 * 1024);
        }
        let original_purpose = crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::original_execution_data(&launch).unwrap();
        let runtime =
            canonical::content_ref(b"inert historical runtime", "application/runtime").unwrap();
        let native =
            canonical::content_ref(b"inert historical native", "application/native").unwrap();
        let fresh_purpose = crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::restoration_target_data(
            &launch, &runtime, &native, &launch.selection.realization.owner_bindings[0].owner.id,
        ).unwrap();
        for purpose in [original_purpose, fresh_purpose] {
            assert_eq!(
                original_invocation_report_startup_allocation_peak_data(
                    &launch,
                    &purpose,
                    Some(original),
                    Some(fresh),
                )
                .unwrap(),
                expected
            );
        }
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &original_purpose,
                None,
                Some(fresh),
            )
            .is_err()
        );
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &fresh_purpose,
                Some(original),
                None,
            )
            .is_err()
        );
        let saved_capture = launch.capture_allocation_selection;
        launch.capture_allocation_selection = None;
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &original_purpose,
                None,
                Some(fresh),
            )
            .is_err()
        );
        launch.capture_allocation_selection = saved_capture;
        let saved_fresh = launch.fresh_restore_allocation_selection;
        launch.fresh_restore_allocation_selection = None;
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &fresh_purpose,
                Some(original),
                None,
            )
            .is_err()
        );
        launch.fresh_restore_allocation_selection = saved_fresh;

        for field in ["original_observe12", "fresh_completed_admit13"] {
            let mut null_row = serde_json::to_value(&allocation).unwrap();
            null_row[field] = serde_json::Value::Null;
            let parsed: PacketNativeReportStartupAllocation =
                serde_json::from_value(null_row).unwrap();
            assert!(
                original_invocation_report_startup_allocation_peak_data(
                    &launch,
                    &original_purpose,
                    parsed.original_observe12,
                    parsed.fresh_completed_admit13,
                )
                .is_err()
            );
        }

        let mut oversized = original;
        oversized.retained_growth_bytes = U64::new(512 * 1024 * 1024);
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &fresh_purpose,
                Some(oversized),
                Some(fresh),
            )
            .is_err()
        );
        let mut overflow = fresh;
        overflow.retained_growth_bytes = U64::new(u64::MAX);
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &original_purpose,
                Some(original),
                Some(overflow),
            )
            .is_err()
        );
        let saved_admission = launch.selection.admission.clone();
        launch.selection.admission =
            crucible_node_format::Id::new("foreign-report-admission").unwrap();
        assert!(
            original_invocation_report_startup_allocation_peak_data(
                &launch,
                &original_purpose,
                Some(original),
                Some(fresh),
            )
            .is_err()
        );

        launch.selection.admission = saved_admission;

        launch.limits.frame_bytes = U64::new(0);
        assert!(
            original_invocation_report_startup_storage_data(
                &launch,
                PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            )
            .is_err()
        );
    }
}

#[test]
fn full_roster_native_and_report_phases_admit_before_any_child() {
    use crucible_engine::node_contract::RuntimeError;
    use std::os::unix::fs::PermissionsExt;

    // The real installer/finalizers read and copy the measured test ELF as
    // constructor DATA, reserve actual supervision/transport slots and retain
    // Source banks. No launcher, SDK, Child or protocol lifecycle is called.
    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    for participant in declaration["participants"].as_array().unwrap() {
        assert_eq!(
            participant["installation"]["provider"]["implementation"]["formats"]
                .as_array()
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            participant["storage"]["limits"]["frame_bytes"],
            serde_json::to_value(U64::new(65_536)).unwrap()
        );
    }
    let parent = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let bytes = canonical::canonical_json(&declaration).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let path = parent.path().join("installation.json");
    std::fs::write(&path, bytes).unwrap();
    let pin = InstalledCompleteSceneManifest::new(path, reference).unwrap();
    let mut scene = InstalledCompleteScene::install(pin, parent.path().join("scene")).unwrap();
    let maximum: U64 =
        serde_json::from_value(declaration["resources"]["memory_bytes"].clone()).unwrap();
    assert_eq!(maximum.get(), 4 * 1024 * 1024 * 1024);

    PacketCompleteReportStartupHolder::stage_original_scene_into(
        &scene.original,
        &mut scene.incoming,
    )
    .unwrap();
    PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&scene.original)
        .unwrap();
    let report =
        PacketCompleteReportStartupHolder::finalize_original_report_startup(&scene.original)
            .unwrap();
    let native =
        PacketCompleteReportStartupHolder::finalize_original_native_startup(&scene.original)
            .unwrap();

    assert!(scene.incoming.is_none());
    assert!(report > 0 && report <= usize::try_from(maximum.get()).unwrap());
    assert!(native > 0 && native <= usize::try_from(maximum.get()).unwrap());
    assert!(matches!(
        PacketCompleteReportStartupHolder::finalize_original_native_startup(&scene.original),
        Err(RuntimeError::DuplicateOperation)
    ));
    scene.retire().unwrap();
    let _ = scene.poll_reclamation().unwrap();
}

#[test]
fn full_roster_native_report_and_sdk_commitments_admit_before_any_child() {
    use crucible_engine::node_contract::RuntimeError;
    use std::os::unix::fs::PermissionsExt;

    // The real installer/finalizers read and copy the measured test ELF as
    // constructor DATA, reserve actual supervision/transport slots and retain
    // Source banks. The real SDK constructor runs after native finalization;
    // no launcher, Child, Hello or native protocol lifecycle is called.
    let executable = std::env::current_exe().unwrap();
    let (_code_source, declaration) = native_roundtrip::declaration(&executable);
    for participant in declaration["participants"].as_array().unwrap() {
        assert_eq!(
            participant["installation"]["provider"]["implementation"]["formats"]
                .as_array()
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            participant["storage"]["limits"]["frame_bytes"],
            serde_json::to_value(U64::new(65_536)).unwrap()
        );
    }
    let parent = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let bytes = canonical::canonical_json(&declaration).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let path = parent.path().join("installation.json");
    std::fs::write(&path, bytes).unwrap();
    let pin = InstalledCompleteSceneManifest::new(path, reference).unwrap();
    let mut scene = InstalledCompleteScene::install(pin, parent.path().join("scene")).unwrap();
    let maximum: U64 =
        serde_json::from_value(declaration["resources"]["memory_bytes"].clone()).unwrap();
    assert_eq!(maximum.get(), 4 * 1024 * 1024 * 1024);

    PacketCompleteReportStartupHolder::stage_original_scene_into(
        &scene.original,
        &mut scene.incoming,
    )
    .unwrap();
    PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&scene.original)
        .unwrap();
    let report =
        PacketCompleteReportStartupHolder::finalize_original_report_startup(&scene.original)
            .unwrap();
    let native =
        PacketCompleteReportStartupHolder::finalize_original_native_startup(&scene.original)
            .unwrap();

    PacketCompleteReportStartupHolder::assert_native_report_commitment_for_test(
        &scene.original,
        true,
    );

    let sdk = PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&scene.original)
        .unwrap();

    assert!(scene.incoming.is_none());
    assert!(report > 0 && report <= usize::try_from(maximum.get()).unwrap());
    assert!(native > 0 && native <= usize::try_from(maximum.get()).unwrap());
    assert!(sdk > 0 && sdk <= usize::try_from(maximum.get()).unwrap());
    assert!(matches!(
        PacketCompleteReportStartupHolder::prepare_original_native_host_sdk(&scene.original),
        Err(RuntimeError::DuplicateOperation)
    ));
    assert!(matches!(
        PacketCompleteReportStartupHolder::finalize_original_native_startup(&scene.original),
        Err(RuntimeError::DuplicateOperation)
    ));
    scene.retire().unwrap();
    let _ = scene.poll_reclamation().unwrap();
}
