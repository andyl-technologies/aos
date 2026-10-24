//! Pins the literal r2 Source SDK layout independently of callback behavior.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::mem::{align_of, offset_of, size_of};

#[test]
fn reader_sdk_r2_matches_literal_source_record_sizes_and_offsets() {
    // The frozen native SDK is LP64. A different pointer ABI must refuse this
    // contract rather than silently truncate its historical identity fields.
    assert_eq!(size_of::<usize>(), 8);
    assert_eq!(size_of::<*const std::ffi::c_void>(), 8);
    assert_eq!(align_of::<usize>(), align_of::<*const std::ffi::c_void>());

    assert_eq!(size_of::<Observation>(), 64);
    assert_eq!(align_of::<Observation>(), 8);
    assert_eq!(offset_of!(Observation, module_child), 24);
    assert_eq!(offset_of!(Observation, birth_attempted), 32);
    assert_eq!(offset_of!(Observation, post_recorded), 48);
    assert_eq!(offset_of!(Observation, first_status), 52);
    assert_eq!(offset_of!(Observation, reserved), 60);

    assert_eq!(size_of::<Disposition>(), 64);
    assert_eq!(offset_of!(Disposition, attempted), 32);
    assert_eq!(offset_of!(Disposition, first_status), 48);
    assert_eq!(offset_of!(Disposition, post_recorded), 56);
    assert_eq!(size_of::<Journal>(), 128);
    assert_eq!(offset_of!(Journal, disposition), 64);

    assert_eq!(size_of::<SourceRead>(), 112);
    assert_eq!(offset_of!(SourceRead, held), 24);
    assert_eq!(offset_of!(SourceRead, module_born), 76);
    assert_eq!(offset_of!(SourceRead, first_status), 84);
    assert_eq!(offset_of!(SourceRead, returned_post_status), 108);
    assert_eq!(size_of::<CompletedReceipt>(), 240);
    assert_eq!(offset_of!(CompletedReceipt, source), 128);

    assert_eq!(size_of::<Completion>(), 160);
    assert_eq!(offset_of!(Completion, delivery_entered), 112);
    assert_eq!(offset_of!(Completion, callback_status), 144);
    assert_eq!(offset_of!(Completion, acknowledgement_status), 156);
    assert_eq!(size_of::<RegistrationReturn>(), 32);
    assert_eq!(size_of::<Callbacks>(), 56);
    assert_eq!(offset_of!(Callbacks, ordinary), 8);
    assert_eq!(offset_of!(Callbacks, completed), 48);
}
