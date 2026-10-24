//! Exercises independent policy revocation after successful graph callbacks.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Model controls deliberately panic on violated original-currentness fences.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;

use super::{read_after_callbacks, refused};

#[test]
fn independent_scope_revocation_after_callbacks_prevents_dispatch() {
    for revoked_axis in 0..4 {
        let independent = [
            Cell::new(true),
            Cell::new(true),
            Cell::new(true),
            Cell::new(true),
        ];
        let plan_live = Cell::new(true);
        let native_live = Cell::new(true);
        let callbacks = Cell::new(0);
        let terminal_reads = Cell::new(0);
        let dispatches = Cell::new(0);

        let result = read_after_callbacks(
            || {
                // Schema, authority, inventory and coordinator checks pass,
                // then the last callback independently revokes an earlier axis.
                for axis in &independent {
                    assert!(axis.get());
                    callbacks.set(callbacks.get() + 1);
                }
                independent[revoked_axis].set(false);
                Ok(())
            },
            || {
                terminal_reads.set(terminal_reads.get() + 1);
                if independent.iter().all(Cell::get) {
                    Ok(())
                } else {
                    Err(refused())
                }
            },
        );
        if result.is_ok() {
            dispatches.set(dispatches.get() + 1);
        }

        assert!(result.is_err());
        assert!(plan_live.get());
        assert!(native_live.get());
        assert_eq!(callbacks.get(), 4);
        assert_eq!(terminal_reads.get(), 1);
        assert_eq!(dispatches.get(), 0);
    }
}

#[test]
fn failed_independent_predicate_cannot_reach_terminal_read_or_dispatch() {
    let terminal_reads = Cell::new(0);
    let result = read_after_callbacks(
        || Err(refused()),
        || {
            terminal_reads.set(terminal_reads.get() + 1);
            Ok(())
        },
    );

    assert!(result.is_err());
    assert_eq!(terminal_reads.get(), 0);
}

#[test]
fn successful_callbacks_without_actual_current_scope_still_refuse() {
    let callbacks = Cell::new(0);
    let result = read_after_callbacks(
        || {
            callbacks.set(callbacks.get() + 1);
            Ok(())
        },
        || Err(refused()),
    );

    assert!(result.is_err());
    assert_eq!(callbacks.get(), 1);
}
