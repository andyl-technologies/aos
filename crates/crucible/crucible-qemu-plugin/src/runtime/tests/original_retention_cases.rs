//! Pinned runtime lifetime after genuine local userdata exposure.
//!
//! These controls use the existing setup fixture and actual owning proof. They
//! register no native callback and issue no Source operation or retirement loan.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::os::fd::BorrowedFd;

fn mapped_callback_owner(fixture: &LiveInstallFixture) -> RequiredOwnedCallbacksRegistered {
    let model = fixture.model_setup();
    let setup = model
        .borrow()
        .unwrap_or_else(|error| panic!("fixture setup borrow: {error}"));
    let input = crate::setup::SetupPreparationInput::from_native_setup(&setup)
        .unwrap_or_else(|error| panic!("fixture setup fields: {error}"));
    let args = fixture.args();
    let handshake = crate::validate_plugin_handshake(
        &args,
        crucible_qemu_protocol::NegotiatedHandshake {
            proto_version: crucible_qemu_protocol::CONTROL_PROTOCOL_VERSION,
            abi_version: crucible_qemu_shmem::ABI_VERSION,
            slot_index: args.slot(),
            node_count: fixture.resource_manifest_basis().3,
        },
    )
    .unwrap_or_else(|error| panic!("fixture handshake: {error}"));
    // SAFETY: the model owns this exact descriptor throughout setup preparation.
    let plan = unsafe { BorrowedFd::borrow_raw(model.plan_fd()) };
    let completion = crate::setup::prepare_setup_completion_borrowing_plan(
        &mut Vec::new(),
        input,
        plan,
        None,
        handshake,
    )
    .unwrap_or_else(|error| panic!("mapped fixture setup: {error}"));
    RequiredOwnedCallbacksRegistered::for_test(&args, completion)
}

#[test]
fn exposed_original_userdata_retains_box_without_checkpoint_or_parent_registration() {
    let fixture = LiveInstallFixture::new();
    let mut owner = mapped_callback_owner(&fixture);
    let state = owner.state.as_ref().get_ref();
    assert!(
        !state
            .checkpoint_registration_retained
            .load(Ordering::Acquire)
    );
    assert!(!state.checkpoint_owner_retained.load(Ordering::Acquire));
    assert!(!state.parent_park_retained.load(Ordering::Acquire));
    assert!(
        !state
            .parent_park_registration_retained
            .load(Ordering::Acquire)
    );
    let witness = Arc::downgrade(&state.quiescence);
    let userdata = owner.state.as_mut().retain_original_userdata();

    drop(owner);

    assert!(witness.upgrade().is_some());
    // SAFETY: this control registered no callback or Original owner. The exposure
    // call supplied the actual allocation address, and the owning proof retained
    // that sole Box. After the observation, no pointer user remains; reclaim it
    // exactly once without moving its pinned contents.
    unsafe { drop(Box::from_raw(userdata.cast::<OwnedCallbackRuntimeState>())) };
    assert!(witness.upgrade().is_none());
}

#[test]
fn unexposed_callback_owner_releases_its_box() {
    let fixture = LiveInstallFixture::new();
    let owner = mapped_callback_owner(&fixture);
    let witness = Arc::downgrade(&owner.state.as_ref().get_ref().quiescence);

    drop(owner);

    assert!(witness.upgrade().is_none());
}
