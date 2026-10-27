//! Checks actual refusal custody and moved model backing in the installer census.
//!
//! The policy fixture is inert DATA, not a Source/SDK admission. Failed capsules
//! remain failed while their real target, socket, model and Hold allocations are
//! measured. No complete archive, Commit receipt or phase success is fabricated.

// crucible-lint: allow panic-shortcut -- actual ownership, requested capacities and refusal define the verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hello_frames::OriginalHelloFrameDigests;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SelectedLaunchWireData, inert_bootstrap_fixtures,
    native_import18_restored_record_schema_data, native_import18_schema_data,
    native_import18_stage_schema_data,
};
use crate::reference_packet::{PacketEvent, control::native5::current_control17_fixture_data};
use std::os::fd::AsRawFd;

fn inert_policy() -> Result<Rc<NativeImport18PolicyData>, ProviderError> {
    let mut value = inert_bootstrap_fixtures::selected_launch(false);
    let formats = value["launch"]["selection"]["provider"]["implementation"]["formats"]
        .as_array_mut()
        .ok_or_else(refused18)?;
    for schema in [
        native_import18_schema_data()?,
        native_import18_stage_schema_data()?,
        native_import18_restored_record_schema_data()?,
    ] {
        let encoded = serde_json::to_value(schema).map_err(ContractError::from)?;
        formats.retain(|previous| previous["id"] != encoded["id"]);
        formats.push(encoded);
    }
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(value).map_err(ContractError::from)?;
    Ok(Rc::new(NativeImport18PolicyData::from_original_data(
        Rc::new(launch),
        [9; 32],
        OriginalHelloFrameDigests {
            request_frame_digest: [11; 32],
            response_frame_digest: [13; 32],
        },
    )?))
}

#[test]
fn native18_installation_retained_census_keeps_refused_target_and_socket()
-> Result<(), ProviderError> {
    let policy = inert_policy()?;
    let mut actual = current_control17_fixture_data(false)?;
    let (socket, _peer) = UnixDatagram::pair()?;
    let descriptor = socket.as_raw_fd();
    let mut inputs = Some(Native18ModelInstallationInputs {
        target: Some((
            actual.selection.clone(),
            actual.complete_coordinator.take().ok_or_else(refused18)?,
        )),
        archive: None,
        effect_socket: Some(socket),
    });
    let mut output = None;

    assert!(Native18ModelInstallation::prepare_into(&mut inputs, &policy, &mut output).is_err());

    assert!(inputs.is_none());
    let owner = output.as_ref().ok_or_else(refused18)?;
    assert!(owner.failed && !owner.installed);
    assert!(owner.control.is_none() && owner.hold.is_none());
    let retained = owner.inputs.as_ref().ok_or_else(refused18)?;
    let selection = &retained.target.as_ref().ok_or_else(refused18)?.0;
    assert_eq!(selection, &actual.selection);
    assert_eq!(
        retained
            .effect_socket
            .as_ref()
            .ok_or_else(refused18)?
            .as_raw_fd(),
        descriptor
    );
    let requested = owner.additional_retained_requested_storage_data(&policy, usize::MAX)?;
    assert!(requested > size_of::<Native18ModelInstallation>());
    assert_eq!(
        owner.additional_retained_requested_storage_data(&policy, requested)?,
        requested
    );
    assert!(
        owner
            .additional_retained_requested_storage_data(&policy, requested - 1)
            .is_err()
    );

    let foreign = inert_policy()?;
    assert_eq!(
        policy.recipe_identity_data(),
        foreign.recipe_identity_data()
    );
    assert_eq!(
        serde_json::to_value(policy.launch_data()).unwrap(),
        serde_json::to_value(foreign.launch_data()).unwrap()
    );
    assert!(
        owner
            .additional_retained_requested_storage_data(&foreign, usize::MAX)
            .is_err()
    );
    assert_eq!(
        owner.additional_retained_requested_storage_data(&policy, requested)?,
        requested
    );
    assert_eq!(
        retained
            .effect_socket
            .as_ref()
            .ok_or_else(refused18)?
            .as_raw_fd(),
        descriptor
    );
    Ok(())
}

#[test]
fn native18_installation_retained_census_follows_spare_model_backing_into_held_control()
-> Result<(), ProviderError> {
    let policy = inert_policy()?;
    let mut output = None;
    assert!(Native18ModelInstallation::prepare_into(&mut None, &policy, &mut output).is_err());
    let owner = output.as_mut().ok_or_else(refused18)?;
    let mut actual = current_control17_fixture_data(false)?;
    let inventory = actual.program.inventory()?;
    owner.boundary = Some(PacketModelCaptureBoundaryData {
        local_cursor: inventory.reached,
        gate_closed: inventory.gate_closed,
        retained_outputs: inventory.retained_outputs.len(),
        earliest_pending_completion: inventory.pending.iter().map(|event| event.completion).min(),
        inventory_hash: actual.program.inventory_hash()?,
    });
    let NativeProgram::OutputOnly(program) =
        std::mem::replace(&mut actual.program, NativeProgram::RestorationInProgress)
    else {
        return Err(refused18());
    };
    owner.completed = Some(CurrentModel18Program::Producer(program));
    let before = owner.additional_retained_requested_storage_data(&policy, usize::MAX)?;
    let Some(CurrentModel18Program::Producer(program)) = owner.completed.as_mut() else {
        return Err(refused18());
    };
    let old_capacity = program.events.capacity();
    let old_length = program.events.len();
    program.events.reserve(1024);
    let additional = (program.events.capacity() - old_capacity) * size_of::<PacketEvent>();
    assert_eq!(program.events.len(), old_length);
    let enlarged = owner.additional_retained_requested_storage_data(&policy, usize::MAX)?;
    assert_eq!(enlarged - before, additional);

    let mut control = Native18ModelInstallation::model_absent_target(
        actual.selection.clone(),
        actual.complete_coordinator.take().ok_or_else(refused18)?,
    );
    let hold = Native18ModelInstallation::preparing_hold(
        &control,
        owner.boundary.take().ok_or_else(refused18)?,
    );
    control.complete_restored_hold = Some(Rc::clone(&hold));
    hold.phase.set(HoldPhase::Installing);
    Native18ModelInstallation::retain_completed_model(&mut control, &hold, &mut owner.completed)?;
    owner.control = Some(control);
    owner.hold = Some(hold);
    assert!(owner.completed.is_none() && owner.boundary.is_none());
    assert!(owner.failed && !owner.installed);

    let held = owner.additional_retained_requested_storage_data(&policy, usize::MAX)?;
    assert!(held >= enlarged);
    assert_eq!(
        owner.additional_retained_requested_storage_data(&policy, held)?,
        held
    );
    assert!(
        owner
            .additional_retained_requested_storage_data(&policy, held - 1)
            .is_err()
    );
    assert!(owner.install_held().is_err());
    assert!(
        owner
            .hold
            .as_ref()
            .ok_or_else(refused18)?
            .physical_gate_data()?
    );
    assert_eq!(
        owner.additional_retained_requested_storage_data(&policy, held)?,
        held
    );
    assert!(Native18ModelInstallation::retained_counter_scratch_data() > 0);
    Ok(())
}
