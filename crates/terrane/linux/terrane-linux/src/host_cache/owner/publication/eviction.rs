//! Owns reconstructible eviction state outside durable host policy.
//!
//! Read activity describes actual verified backing but grants no pin or native
//! authority. Physical retirement must separately check original job custody,
//! durable protection and the publisher's acknowledged namespace transitions.

mod activity;
mod graph;
mod lifecycle;
mod permit;
mod queue;
mod reextract;
pub(in crate::host_cache::owner) use permit::CachePermit;

use activity::Registry;
pub(in crate::host_cache::owner) use activity::{ReadActivities, ReadActivity, ReadOrigin};
use lifecycle::Pending;
use queue::Queue;
use std::{collections::BTreeMap, sync::Mutex};

pub use lifecycle::NativeCacheEvictionReport;
pub(in crate::host_cache::owner) use lifecycle::{
    DueRetirements, Schedule, due_retirements, encoded_finished, encoded_restored, finish_due,
    reconcile, restore_for, restore_publication, run,
};

/// Retains bounded reconstructible cache bookkeeping on the physical executor.
#[derive(Default)]
pub(in crate::host_cache::owner) struct Runtime {
    /// Separates read activity from the embedded-store mutex and command queue.
    pub(in crate::host_cache::owner) activities: Mutex<Registry>,
    queue: Option<Queue>,
    pending: BTreeMap<String, Pending>,
    /// Retains original encoded units separately from sealed publication receipts.
    pub(in crate::host_cache::owner) encoded:
        crate::host_cache::owner::admission::eviction::Runtime,
}

/// Bounds one actual body's activity, shared clock and tree-node bookkeeping.
pub(in crate::host_cache::owner) fn activity_storage_bytes() -> usize {
    std::mem::size_of::<ReadActivity>()
        // Every bounded snapshot also retains its original registration tag.
        + std::mem::size_of::<ReadOrigin>()
        + std::mem::size_of::<Mutex<u64>>()
        + std::mem::size_of::<(u64, u64)>()
        + 10 * std::mem::size_of::<usize>()
}

/// Bounds allocation-unit, planner and retained transition headers per original job.
pub(in crate::host_cache::owner) fn entry_storage_bytes() -> usize {
    2 * std::mem::size_of::<graph::Unit>()
        + std::mem::size_of::<Pending>()
        + std::mem::size_of::<Queue>()
        + std::mem::size_of::<terrane_sdk::host::cache::CacheEntry>()
        + std::mem::size_of::<crate::publisher_local::client::PendingCacheBody>()
        + std::mem::size_of::<crate::publisher_local::client::CacheBodyCompletion>()
        // The queue entry and census row each retain the physical registration.
        + 2 * std::mem::size_of::<ReadOrigin>()
        + 1024 // Allocation keys, metadata purposes, member Arcs and map-node growth.
}
