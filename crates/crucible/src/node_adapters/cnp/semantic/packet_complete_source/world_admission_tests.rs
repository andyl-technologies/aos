//! Exercises the production finalization guard with modeled callback currentness.
//!
//! These controls hold ordinary test-owned bytes and run the same finalization
//! helper used by completed-Admit consumption. They issue no Source credential,
//! completed SDK pair, Child, graph admission or native permission. The guard is
//! consumed by value; native currentness and realization callbacks are modeled.

use std::{
    cell::{Cell, RefCell},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

use super::*;

struct OriginalFixture {
    current: Cell<bool>,
    callbacks: Cell<usize>,
    terminal_reads: Cell<usize>,
    revocations: Cell<usize>,
    events: RefCell<Vec<&'static str>>,
    original_bytes: Rc<Vec<u8>>,
}

impl OriginalFixture {
    fn new() -> Self {
        Self {
            current: Cell::new(true),
            callbacks: Cell::new(0),
            terminal_reads: Cell::new(0),
            revocations: Cell::new(0),
            events: RefCell::new(Vec::new()),
            original_bytes: Rc::new(b"retained completed protocol data".to_vec()),
        }
    }

    fn attempt(&self) -> WorldAdmissionAttempt<impl FnOnce() + '_> {
        WorldAdmissionAttempt {
            process: std::process::id(),
            revoke: Some(|| {
                self.events.borrow_mut().push("revoke");
                self.revocations.set(self.revocations.get() + 1);
                self.current.set(false);
            }),
        }
    }

    fn observe_callback(&self) {
        self.events.borrow_mut().push("callback");
        self.callbacks.set(self.callbacks.get() + 1);
    }

    fn terminal_read(&self) -> Result<(), OperationFailure> {
        self.events.borrow_mut().push("terminal");
        self.terminal_reads.set(self.terminal_reads.get() + 1);
        if !self.current.get() {
            return Err(refused("modeled original read was revoked"));
        }
        Ok(())
    }

    fn assert_original_retained(&self, original: &Rc<Vec<u8>>) {
        assert!(Rc::ptr_eq(&self.original_bytes, original));
        assert_eq!(original.as_slice(), b"retained completed protocol data");
    }
}

#[test]
fn successful_final_callback_revocation_is_seen_by_terminal_read() {
    // The positive inverse must disarm the same guard exactly once, with no
    // source callback after the terminal read. There is no transport callback.
    let accepted = OriginalFixture::new();
    let original = Rc::clone(&accepted.original_bytes);
    let result = accepted.attempt().finish(
        || {
            accepted.observe_callback();
            Ok(())
        },
        || accepted.terminal_read(),
    );
    assert!(result.is_ok());
    assert_eq!(&*accepted.events.borrow(), &["callback", "terminal"]);
    assert_eq!(accepted.callbacks.get(), 1);
    assert_eq!(accepted.terminal_reads.get(), 1);
    assert_eq!(accepted.revocations.get(), 0);
    accepted.assert_original_retained(&original);

    let revoked = OriginalFixture::new();
    let original = Rc::clone(&revoked.original_bytes);
    let result = revoked.attempt().finish(
        || {
            revoked.observe_callback();
            revoked.current.set(false);
            Ok(())
        },
        || revoked.terminal_read(),
    );
    assert!(result.is_err());
    assert_eq!(
        &*revoked.events.borrow(),
        &["callback", "terminal", "revoke"]
    );
    assert_eq!(revoked.callbacks.get(), 1);
    assert_eq!(revoked.terminal_reads.get(), 1);
    assert_eq!(revoked.revocations.get(), 1);
    assert!(!revoked.current.get());
    revoked.assert_original_retained(&original);
}

#[test]
fn failed_final_callback_revokes_original_without_terminal_success() {
    let fixture = OriginalFixture::new();
    let original = Rc::clone(&fixture.original_bytes);
    let result = fixture.attempt().finish(
        || {
            fixture.observe_callback();
            Err(refused("modeled final realization refused"))
        },
        || fixture.terminal_read(),
    );

    assert!(result.is_err());
    assert_eq!(&*fixture.events.borrow(), &["callback", "revoke"]);
    assert_eq!(fixture.callbacks.get(), 1);
    assert_eq!(fixture.terminal_reads.get(), 0);
    assert_eq!(fixture.revocations.get(), 1);
    assert!(!fixture.current.get());
    fixture.assert_original_retained(&original);
}

#[test]
fn unwinding_final_callback_keeps_original_under_the_same_revoke_guard() {
    let fixture = OriginalFixture::new();
    let original = Rc::clone(&fixture.original_bytes);
    let result = catch_unwind(AssertUnwindSafe(|| {
        fixture.attempt().finish(
            || {
                fixture.observe_callback();
                std::panic::panic_any("modeled final realization unwind");
            },
            || fixture.terminal_read(),
        )
    }));

    assert!(result.is_err());
    assert_eq!(&*fixture.events.borrow(), &["callback", "revoke"]);
    assert_eq!(fixture.callbacks.get(), 1);
    assert_eq!(fixture.terminal_reads.get(), 0);
    assert_eq!(fixture.revocations.get(), 1);
    assert!(!fixture.current.get());
    fixture.assert_original_retained(&original);
}
