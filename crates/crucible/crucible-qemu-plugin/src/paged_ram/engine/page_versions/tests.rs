//! Checks the actual same-vector gate with explicitly modeled native owner slots.
//!
//! These controls issue no real native transaction, source authority or Ready.

use super::*;
use std::sync::Mutex;

fn vector() -> PageStates {
    PageStates::new(vec![PageState {
        version: 7,
        resident: true,
        writable: false,
        preserved: None,
    }])
}

fn fence(transaction: u64) -> NativePageFence {
    NativePageFence {
        identity: FenceIdentity {
            transaction,
            source_owner: 11,
            page_owner: 13,
        },
    }
}

#[test]
fn held_whole_vector_stays_readable_but_refuses_all_mutable_elements() {
    let mut states = vector();
    let address = states.values.as_ptr();
    let held = fence(1);
    states.hold(&held).unwrap();

    assert!(states.get_mut(0).is_none());
    assert!(states.get_mut(1).is_none());
    assert_eq!(states.first().unwrap().version, 7);
    assert_eq!(states.values.as_ptr(), address);
    states.check(&held).unwrap();
}

#[test]
fn exact_final_disposition_reopens_same_vector_without_copy_or_renewal() {
    let mut states = vector();
    let address = states.values.as_ptr();
    let held = fence(2);
    states.hold(&held).unwrap();

    states
        .release(&DisposedNativePageFence {
            identity: held.identity,
        })
        .unwrap();
    states.get_mut(0).unwrap().version = 8;

    assert_eq!(states.values.as_ptr(), address);
    assert_eq!(states[0].version, 8);
    assert!(states.hold(&held).is_err());
}

#[test]
fn foreign_or_stale_disposition_retains_actual_mutation_gate() {
    let mut states = vector();
    let held = fence(3);
    states.hold(&held).unwrap();

    assert!(
        states
            .release(&DisposedNativePageFence {
                identity: fence(4).identity
            })
            .is_err()
    );
    assert!(states.get_mut(0).is_none());
    assert!(states.check(&fence(4)).is_err());
    states.check(&held).unwrap();
}

#[test]
fn page_version_equality_does_not_replace_retained_owner_slots() {
    let mut states = vector();
    let held = fence(5);
    states.hold(&held).unwrap();
    let mut other = fence(5);
    other.identity.page_owner += 1;

    assert!(states.hold(&other).is_err());
    assert!(states.check(&other).is_err());
    assert_eq!(states[0].version, 7);
    assert!(states.get_mut(0).is_none());
}

#[test]
fn an_existing_mutable_borrow_prevents_capture_mutex_acquisition() {
    let states = Mutex::new(vector());
    let mut writer = states.lock().unwrap();
    let page = writer.get_mut(0).unwrap();
    page.version = 8;
    assert!(states.try_lock().is_err());
    drop(writer);

    let mut owner = states.try_lock().unwrap();
    owner.hold(&fence(6)).unwrap();
    assert_eq!(owner[0].version, 8);
    assert!(owner.get_mut(0).is_none());
}

#[test]
fn losing_witness_never_reopens_the_gate_by_drop() {
    let mut states = vector();
    {
        let held = fence(7);
        states.hold(&held).unwrap();
    }

    assert!(states.get_mut(0).is_none());
    assert!(states.hold(&fence(8)).is_err());
}
