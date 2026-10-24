//! Original callback tuple identity, ABI extent and changed-observation controls.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

extern "C" fn selected_init(_index: u32, _userdata: *mut c_void) {}
static CHANGED_CALLBACK_ENTRIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C" fn changed_init(_index: u32, _userdata: *mut c_void) {
    CHANGED_CALLBACK_ENTRIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn literal_registration_retains_selected_function_and_each_actual_userdata() {
    let roster = RetainedCallbackRoster::default();
    let mut live_allocation = 0u8;
    let live = (&mut live_allocation as *mut u8).cast();
    let mut runtime_allocation = 0u8;
    let runtime = (&mut runtime_allocation as *mut u8).cast();

    assert_eq!(roster.retain_live(selected_init, live), Ok(()));
    assert_eq!(roster.retain_hot_fork(runtime), Ok(()));

    let live_rows = roster.live.get().unwrap();
    assert_eq!(live_rows[0].function, selected_init as *const () as usize);
    for (index, row) in live_rows.iter().enumerate() {
        assert_eq!(row.kind, (index + 1) as u32);
        assert_eq!(row.reserved, 0);
        assert_ne!(row.function, 0);
        assert_eq!(row.userdata, live as usize);
    }
    let runtime_rows = roster.hot_fork.get().unwrap();
    assert_eq!(runtime_rows[0].kind, 29);
    assert_eq!(runtime_rows[1].kind, 30);
    assert!(
        runtime_rows
            .iter()
            .all(|row| row.userdata == runtime as usize)
    );
    assert_ne!(live as usize, runtime as usize);
    assert_eq!(std::mem::size_of::<CallbackTuple>(), 24);
    assert_eq!(std::mem::offset_of!(CallbackTuple, function), 8);
    assert_eq!(std::mem::offset_of!(CallbackTuple, userdata), 16);
}

#[test]
fn changed_observation_preserves_first_function_and_userdata() {
    let roster = RetainedCallbackRoster::default();
    let mut original_allocation = 0u8;
    let original = (&mut original_allocation as *mut u8).cast();
    let mut foreign_allocation = 0u8;
    let foreign = (&mut foreign_allocation as *mut u8).cast();

    // Function addresses are observational native identities. Distinct empty
    // test functions may be merged, so this mutation has a real different body.
    assert_ne!(
        selected_init as *const () as usize,
        changed_init as *const () as usize
    );
    assert_eq!(roster.retain_live(selected_init, original), Ok(()));
    assert_eq!(roster.retain_live(selected_init, original), Ok(()));
    let retained = *roster.live.get().unwrap();

    assert_eq!(
        roster.retain_live(changed_init, original),
        Err(LiveVcpuTimeCallbackError::CallbackRosterChanged)
    );
    assert_eq!(
        roster.retain_live(selected_init, foreign),
        Err(LiveVcpuTimeCallbackError::CallbackRosterChanged)
    );
    assert_eq!(roster.live.get(), Some(&retained));

    assert_eq!(roster.retain_hot_fork(original), Ok(()));
    let hot_fork = *roster.hot_fork.get().unwrap();
    assert_eq!(
        roster.retain_hot_fork(foreign),
        Err(LiveVcpuTimeCallbackError::CallbackRosterChanged)
    );
    assert_eq!(roster.hot_fork.get(), Some(&hot_fork));
}

#[test]
fn absent_userdata_never_becomes_an_original_callback_tuple() {
    let roster = RetainedCallbackRoster::default();

    assert_eq!(
        roster.retain_live(selected_init, std::ptr::null_mut()),
        Err(LiveVcpuTimeCallbackError::CallbackRosterChanged)
    );
    assert_eq!(
        roster.retain_hot_fork(std::ptr::null_mut()),
        Err(LiveVcpuTimeCallbackError::CallbackRosterChanged)
    );

    assert!(roster.live.get().is_none());
    assert!(roster.hot_fork.get().is_none());
}

#[test]
fn complete_image_waits_for_both_seams_and_keeps_the_original_address() {
    let roster = RetainedCallbackRoster::default();
    let mut live_allocation = 0u8;
    let live = (&mut live_allocation as *mut u8).cast();
    let mut runtime_allocation = 0u8;
    let runtime = (&mut runtime_allocation as *mut u8).cast();

    assert!(roster.complete_original().unwrap().is_none());
    roster.retain_live(selected_init, live).unwrap();
    assert!(roster.complete_original().unwrap().is_none());
    roster.retain_hot_fork(runtime).unwrap();

    let original = roster.complete_original().unwrap().unwrap();
    let address = std::ptr::from_ref(original);
    assert_eq!(&original[..28], roster.live.get().unwrap());
    assert_eq!(&original[28..], roster.hot_fork.get().unwrap());
    assert_eq!(original[28].userdata, runtime as usize);
    assert_ne!(original[28].userdata, original[0].userdata);

    roster.retain_live(selected_init, live).unwrap();
    roster.retain_hot_fork(runtime).unwrap();
    assert_eq!(
        std::ptr::from_ref(roster.complete_original().unwrap().unwrap()),
        address
    );
}

#[test]
fn hot_fork_rows_alone_never_publish_a_complete_native_roster() {
    let roster = RetainedCallbackRoster::default();
    let mut allocation = 0u8;
    let runtime = (&mut allocation as *mut u8).cast();

    roster.retain_hot_fork(runtime).unwrap();

    assert!(roster.complete_original().unwrap().is_none());
    assert!(roster.complete.get().is_none());
}
