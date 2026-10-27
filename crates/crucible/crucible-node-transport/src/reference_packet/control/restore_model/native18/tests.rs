//! Checks actual current model transfer beneath a separate fresh physical Hold.
//!
//! These controls exercise the installer field moves and legacy dispatch fence.
//! They do not fabricate a complete archive or claim original phase admission.

// crucible-lint: allow panic-shortcut -- paired writers and real socket identity define the verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
use crate::reference_packet::{
    continuation_models::settled_reader::{PacketSettledModel17Data, read_settled_model17_data},
    service::PacketConnectedSourceProgram,
};
use crate::retained_metadata::{
    MetadataObserver,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};
use std::os::fd::AsRawFd;

fn decode_model(actual: &PacketControl) -> Result<PacketSettledModel17Data, ProviderError> {
    let mut records = MetadataRecordBank::reserve(16384)?;
    let mut observer = MetadataObserver::recording(&mut records);
    let input = match &actual.program {
        NativeProgram::OutputOnly(program) => {
            observer.observe(program)?;
            serde_json::to_vec(&("producer", program.borrowed_settled_model_data()))
        }
        NativeProgram::Connected(program) => {
            observer.observe(program)?;
            serde_json::to_vec(&("reactive", program.borrowed_settled_model_data()))
        }
        NativeProgram::RestorationInProgress => return Err(refused18()),
    }
    .map_err(ContractError::from)?;
    let facts = observer.finish();
    let encoded = serde_json::to_vec(&records).map_err(ContractError::from)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)?;
    let limits = HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 16384,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 4096,
    };
    let mut preflight = Ledger::new(rows.rows(), limits);
    assert!(read_settled_model17_data(&input, &mut preflight, false)?.is_none());
    assert!(preflight.rows.next().is_none());

    let mut ledger = Ledger::new(rows.rows(), limits);
    let model = read_settled_model17_data(&input, &mut ledger, true)?.ok_or_else(refused18)?;
    assert!(ledger.rows.next().is_none());
    Ok(model)
}

#[test]
fn native18_installation_owner_quote_covers_actual_shared_hold_without_releasing_it()
-> Result<(), ProviderError> {
    let row = native_import18_installation_owner_construction_data(usize::MAX)?;
    let peak = row
        .into_iter()
        .try_fold(0usize, |total, term| total.checked_add(term))
        .ok_or_else(refused18)?;
    assert_eq!(
        native_import18_installation_owner_construction_data(peak)?,
        row
    );
    assert!(native_import18_installation_owner_construction_data(peak - 1).is_err());
    assert!(native_import18_installation_owner_construction_data(0).is_err());

    for reactive in [false, true] {
        let actual = super::super::super::native5::current_control17_fixture_data(reactive)?;
        let boundary = decode_model(&actual)?.installation_boundary18_data()?;
        let hold = Native18ModelInstallation::preparing_hold(&actual, boundary);
        let expected_cursor = hold.cursor;
        let expected_hash = hold.inventory_hash.clone();

        // Count the actual shared allocation through the independent metadata
        // visitor. Its hash backing and Control identity have separate owners
        // in the boundary and target components of the complete admission.
        let mut observer = MetadataObserver::new();
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredPhysicalHold,
            hold.as_ref(),
        )?;
        let hold_backing =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
        assert!(hold_backing >= std::mem::size_of::<PacketCompleteRestorePhysicalHold>());
        assert!(row[0] >= std::mem::size_of::<Native18ModelInstallation>() + hold_backing);

        assert_eq!(
            native_import18_installation_owner_construction_data(peak)?,
            row
        );
        assert!(hold.phase.get() == HoldPhase::Preparing);
        assert!(hold.authenticate_held().is_err());
        assert!(hold.physical_gate_data().is_err());
        assert_eq!(hold.cursor, expected_cursor);
        assert_eq!(hold.inventory_hash, expected_hash);
        assert!(Rc::ptr_eq(&hold.control_identity, &actual.capture_identity));
    }
    Ok(())
}

#[test]
fn native18_installation_preserves_current_model_and_blocks_legacy_hold_release()
-> Result<(), ProviderError> {
    use crate::reference_packet::continuation_models::settled_reader::adoption18::CurrentModel18Adoption;

    for (reactive, failed) in [(false, false), (false, true), (true, false)] {
        let mut actual = super::super::super::native5::current_control17_fixture_data(reactive)?;
        actual.program.open_gate()?;
        if let NativeProgram::OutputOnly(program) = &mut actual.program {
            let start = program.inventory().reached;
            program.execute(
                Id::new("actual-private-progress")?,
                start,
                Position::new(U64::new(4), U64::new(0), Phase::Reaction),
            )?;
        }
        let expected_cursor = actual.program.inventory()?.reached;
        let expected_hash = actual.program.inventory_hash()?;
        let definition = match &mut actual.program {
            NativeProgram::OutputOnly(program) => {
                program.failed = failed;
                PacketConnectedSourceProgram::Producer {
                    program: program.definition(),
                }
            }
            NativeProgram::Connected(program) => PacketConnectedSourceProgram::Reactive {
                program: program.definition().clone(),
            },
            NativeProgram::RestorationInProgress => return Err(refused18()),
        };
        let mut model = Some(decode_model(&actual)?);
        let boundary = model
            .as_ref()
            .ok_or_else(refused18)?
            .installation_boundary18_data()?;
        assert!(!boundary.gate_closed);
        assert_eq!(boundary.local_cursor, expected_cursor);
        assert_eq!(boundary.inventory_hash, expected_hash);
        let expected = serde_json::to_vec(
            &model
                .as_ref()
                .ok_or_else(refused18)?
                .borrowed_program17_data(),
        )
        .unwrap();
        let coordinator = actual
            .complete_coordinator
            .as_ref()
            .ok_or_else(refused18)?
            .clone();
        let mut target = Native18InstallationTarget {
            selection: Some(actual.selection.clone()),
            coordinator: Some(coordinator),
        }
        .into_model_absent_control()
        .map_err(|_| refused18())?;
        assert!(matches!(
            target.program,
            NativeProgram::RestorationInProgress
        ));
        let hold = Native18ModelInstallation::preparing_hold(&target, boundary);
        target.complete_restored_hold = Some(Rc::clone(&hold));
        Native18ModelInstallation::authenticate_model_absent_target(
            &target,
            &hold,
            HoldPhase::Preparing,
        )?;

        let mut adoption = None;
        CurrentModel18Adoption::prepare_into(&mut model, &definition, &mut adoption)?;
        let adoption = adoption.as_mut().ok_or_else(refused18)?;
        let (socket, peer) = UnixDatagram::pair()?;
        peer.set_nonblocking(true)?;
        let descriptor = socket.as_raw_fd();
        let mut socket = Some(socket);
        hold.phase.set(HoldPhase::Installing);
        adoption.bind_effect_socket(&mut socket)?;
        let mut completed = None;
        adoption.take_completed_into(&mut completed)?;
        Native18ModelInstallation::retain_completed_model(&mut target, &hold, &mut completed)?;

        assert!(socket.is_none() && completed.is_none());
        let transferred = match &target.program {
            NativeProgram::OutputOnly(program) => {
                assert!(!program.gate_closed);
                assert_eq!(program.failed, failed);
                assert_eq!(program.effect_socket.as_raw_fd(), descriptor);
                serde_json::to_vec(&("producer", program.borrowed_settled_model_data())).unwrap()
            }
            NativeProgram::Connected(program) => {
                let fields = serde_json::to_value(program.borrowed_settled_model_data()).unwrap();
                assert_eq!(fields["gate_closed"], false);
                assert_eq!(fields["failed"], failed);
                serde_json::to_vec(&("reactive", program.borrowed_settled_model_data())).unwrap()
            }
            NativeProgram::RestorationInProgress => return Err(refused18()),
        };
        assert_eq!(transferred, expected);
        assert!(hold.physical_gate_data()?);
        assert_eq!(hold.captured_boundary()?.0, expected_cursor);
        assert_eq!(hold.captured_boundary()?.1, &expected_hash);
        assert!(target.fenced && !target.immediate && target.restoration_activation_required);
        assert!(target.release_original_physical_gate().is_err());
        assert!(
            Native18ModelInstallation::authenticate_model_absent_target(
                &target,
                &hold,
                HoldPhase::Preparing
            )
            .is_err()
        );
        assert!(adoption.take_completed_into(&mut None).is_err());
        assert_eq!(
            peer.recv(&mut [0u8; 32]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}

#[test]
fn native18_installation_refuses_an_equal_foreign_control_identity() -> Result<(), ProviderError> {
    let actual = super::super::super::native5::current_control17_fixture_data(false)?;
    let boundary = decode_model(&actual)?.installation_boundary18_data()?;
    let coordinator = actual
        .complete_coordinator
        .as_ref()
        .ok_or_else(refused18)?
        .clone();
    let first = Native18ModelInstallation::model_absent_target(
        actual.selection.clone(),
        coordinator.clone(),
    );
    let mut foreign =
        Native18ModelInstallation::model_absent_target(actual.selection.clone(), coordinator);
    let hold = Native18ModelInstallation::preparing_hold(&first, boundary);
    foreign.complete_restored_hold = Some(Rc::clone(&hold));

    assert!(
        Native18ModelInstallation::authenticate_model_absent_target(
            &foreign,
            &hold,
            HoldPhase::Preparing
        )
        .is_err()
    );
    assert!(matches!(
        foreign.program,
        NativeProgram::RestorationInProgress
    ));
    assert!(hold.phase.get() == HoldPhase::Preparing);
    Ok(())
}

#[test]
fn native18_installation_derives_the_whole_original_coordinator() -> Result<(), ProviderError> {
    let actual = super::super::super::native5::current_control17_fixture_data(false)?;
    let coordinator = actual.complete_coordinator.as_ref().ok_or_else(refused18)?;
    let original = canonical::canonical_json(&serde_json::to_value(coordinator).unwrap())?;

    let mut foreign = coordinator.clone();
    foreign.participants[2].prepared_token = Id::new("different-original-preparation")?;
    foreign.validate(&actual.selection)?;

    let derived = PacketNative5CoordinatorInstallation::decode(&original, &actual.selection)?;
    assert_eq!(derived, *coordinator);
    assert_ne!(derived, foreign);
    assert_eq!(foreign.participants[0], actual.selection);
    assert_ne!(foreign, *coordinator);
    Ok(())
}

#[test]
fn native18_installation_boundary_quote_preserves_actual_current_inventory()
-> Result<(), ProviderError> {
    for reactive in [false, true] {
        let mut actual = super::super::super::native5::current_control17_fixture_data(reactive)?;
        actual.program.open_gate()?;
        let model = decode_model(&actual)?;
        let before = serde_json::to_vec(&model.borrowed_program17_data()).unwrap();
        let formatter = model.installation_boundary18_quote_formatter_data(usize::MAX)?;
        assert_eq!(
            model.installation_boundary18_quote_formatter_data(formatter)?,
            formatter
        );
        if formatter > 0 {
            assert!(
                model
                    .installation_boundary18_quote_formatter_data(formatter - 1)
                    .is_err()
            );
        }

        let row = model.installation_boundary18_construction_data(usize::MAX)?;
        let peak = row
            .into_iter()
            .try_fold(0usize, |total, term| total.checked_add(term))
            .ok_or_else(refused18)?;
        assert_eq!(model.installation_boundary18_construction_data(peak)?, row);
        assert!(
            model
                .installation_boundary18_construction_data(peak - 1)
                .is_err()
        );

        let boundary = model.installation_boundary18_data()?;
        let retained_hash = boundary.inventory_hash.algorithm.capacity()
            + boundary.inventory_hash.domain.capacity()
            + boundary.inventory_hash.digest.capacity();
        assert!(row[0] >= retained_hash);
        assert!(row[1] > 0 && row[2] > 0);
        assert_eq!(boundary.inventory_hash, actual.program.inventory_hash()?);
        assert_eq!(
            serde_json::to_vec(&model.borrowed_program17_data()).unwrap(),
            before
        );
    }
    Ok(())
}
