//! Counts actual Packed read costs for synchronous unit diagnostics only.
//!
//! A thread-local snapshot contains no object data, descriptors or authority.
//! Resetting counters never resets an account, storage session or operation.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- test diagnostics localize impossible counter overflow.
#![allow(clippy::expect_used)]

use std::cell::Cell;

/// Summarizes selected reads and successful full-manifest authentications.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadViewCost {
    pub(crate) lookups: u64,
    pub(crate) pack_switches: u64,
    pub(crate) authenticated_manifests: u64,
    pub(crate) authenticated_rows: u64,
    pub(crate) authenticated_manifest_bytes: u64,
}

thread_local! {
    static COST: Cell<ReadViewCost> = const {
        Cell::new(ReadViewCost {
            lookups: 0,
            pack_switches: 0,
            authenticated_manifests: 0,
            authenticated_rows: 0,
            authenticated_manifest_bytes: 0,
        })
    };
}

pub(crate) fn reset() {
    COST.with(|cost| cost.set(ReadViewCost::default()));
}

pub(crate) fn snapshot() -> ReadViewCost {
    COST.with(Cell::get)
}

pub(super) fn lookup() {
    COST.with(|cost| {
        let mut value = cost.get();
        value.lookups = value
            .lookups
            .checked_add(1)
            .expect("diagnostic lookup counter");
        cost.set(value);
    });
}

pub(super) fn switch_pack() {
    COST.with(|cost| {
        let mut value = cost.get();
        value.pack_switches = value
            .pack_switches
            .checked_add(1)
            .expect("diagnostic pack counter");
        cost.set(value);
    });
}

pub(super) fn authenticated(rows: usize, bytes: u64) {
    COST.with(|cost| {
        let mut value = cost.get();
        value.authenticated_manifests = value
            .authenticated_manifests
            .checked_add(1)
            .expect("diagnostic manifest counter");
        value.authenticated_rows = value
            .authenticated_rows
            .checked_add(rows as u64)
            .expect("diagnostic row counter");
        value.authenticated_manifest_bytes = value
            .authenticated_manifest_bytes
            .checked_add(bytes)
            .expect("diagnostic manifest-byte counter");
        cost.set(value);
    });
}
