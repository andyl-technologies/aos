//! Single-slot QEMU registration model and original consumer preservation.
//!
//! Selected QEMU `plugins/core.c::do_plugin_register_cb` replaces the callback
//! and userdata for an existing plugin/event slot. The provider models that
//! registration rule; guest execution, native timers, and VMStop are not modeled.

use std::cell::{Cell, RefCell};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Absent,
    Whitebox,
    Coverage,
    Combined,
    Observer,
}

thread_local! {
    static TEST_WITNESS: RefCell<Option<Witness>> = const { RefCell::new(None) };
    static OWNER: Cell<Owner> = const { Cell::new(Owner::Absent) };
    static REGISTRATIONS: Cell<usize> = const { Cell::new(0) };
    static EXECUTIONS: Cell<usize> = const { Cell::new(0) };
}

extern "C" fn replace_translation(
    _id: QemuPluginId,
    callback: TranslationCallback,
    userdata: *mut c_void,
) {
    assert_eq!(callback as usize, translate as *const () as usize);
    assert!(userdata.is_null());
    OWNER.set(Owner::Observer);
    REGISTRATIONS.set(REGISTRATIONS.get() + 1);
}

extern "C" fn observe_execution(
    _tb: *mut QemuPluginTb,
    callback: ExecutionCallback,
    flags: c_int,
    userdata: *mut c_void,
) {
    assert_eq!(callback as usize, execute as *const () as usize);
    assert_eq!(flags, 0);
    assert_eq!(userdata as usize, 3);
    EXECUTIONS.set(EXECUTIONS.get() + 1);
}

fn preserves_registration(whitebox: bool, coverage: bool) {
    let expected = match (whitebox, coverage) {
        (false, false) => Owner::Observer,
        (true, false) => Owner::Whitebox,
        (false, true) => Owner::Coverage,
        (true, true) => Owner::Combined,
    };
    OWNER.set(if whitebox || coverage {
        expected
    } else {
        Owner::Absent
    });
    REGISTRATIONS.set(usize::from(whitebox || coverage));
    EXECUTIONS.set(0);
    let witness = Witness::new(Apis {
        register_translation: replace_translation,
        register_execution: observe_execution,
        ..super::tests::apis()
    });
    let publication = OnceLock::new();

    install_prepared(7, whitebox || coverage, witness, &publication);

    assert_eq!(
        OWNER.get(),
        expected,
        "observer replaced the original consumer"
    );
    assert_eq!(REGISTRATIONS.get(), 1, "QEMU must retain one event owner");
    assert!(publication.get().is_some(), "observer was not published");
}

#[test]
fn observer_preserves_whitebox_registration() {
    preserves_registration(true, false);
}

#[test]
fn observer_preserves_coverage_registration() {
    preserves_registration(false, true);
}

#[test]
fn observer_preserves_combined_registration() {
    preserves_registration(true, true);
}

#[test]
fn observer_registers_standalone_translation_only_without_consumers() {
    preserves_registration(false, false);
}

/// Scoped provider for native TB instrumentation, without clock/control state.
pub(crate) struct TestTranslationWitness;

impl TestTranslationWitness {
    pub(crate) fn instrumentations(&self) -> usize {
        EXECUTIONS.get()
    }
}

impl Drop for TestTranslationWitness {
    fn drop(&mut self) {
        TEST_WITNESS.with_borrow_mut(|witness| *witness = None);
    }
}

pub(crate) fn scoped_translation_witness() -> TestTranslationWitness {
    TEST_WITNESS.with_borrow_mut(|witness| {
        assert!(witness.is_none(), "test observer scopes must not overlap");
        *witness = Some(Witness::new(Apis {
            register_execution: observe_execution,
            ..super::tests::apis()
        }));
    });
    EXECUTIONS.set(0);
    TestTranslationWitness
}

pub(super) fn observe_for_test(tb: *mut QemuPluginTb) -> bool {
    TEST_WITNESS.with_borrow(|witness| {
        if let Some(witness) = witness {
            witness.instrument_translation(tb);
            true
        } else {
            false
        }
    })
}

#[test]
fn standalone_callback_instruments_the_first_translation() {
    let witness = scoped_translation_witness();
    translate(
        std::ptr::dangling_mut::<QemuPluginTb>(),
        std::ptr::null_mut(),
    );
    assert_eq!(witness.instrumentations(), 1);
}
