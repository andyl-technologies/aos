//! Tracks externally issued producer reads without retaining their backing.
//!
//! The physical owner alone registers views after genuine source preparation.
//! Weak references avoid a source-to-publication-to-source ownership cycle.
//! Consumer sources are prepared separately and never enter this registry.

use super::{NativeResidentChunkSource, Origin, PublicationJob, Source, invalid, view::ReadView};
use std::{
    io,
    sync::{Arc, Mutex, Weak},
};

/// Reports current external producer-view closure without releasing durable protection.
///
/// This observation supplies no eviction, quota reclamation or serving authority.
/// Internal reassembly sources and independently pinned consumers are separate.
#[derive(Clone, Copy, Debug)]
pub struct NativeProducerReadClosure {
    /// Number of original externally issued views observed by this operation.
    pub observed_views: usize,
    /// Number of those views still retaining already-started operations.
    pub active_views: usize,
}

/// Bounds weak external read registrations on one original physical worker.
#[derive(Default)]
pub(in crate::host_cache::owner) struct ProducerReadRegistry {
    entries: Vec<Entry>,
}

struct Entry {
    view: Weak<ReadView<Source>>,
    publication: Option<Weak<Mutex<PublicationJob>>>,
}

impl ProducerReadRegistry {
    /// Registers an actual prepared view without duplicating its body or origin.
    ///
    /// # Errors
    /// Refuses closed views, exhausted operator bounds or allocation failure.
    pub(in crate::host_cache::owner) fn register(
        &mut self,
        source: &NativeResidentChunkSource,
        limit: usize,
    ) -> io::Result<()> {
        self.entries.retain(|entry| {
            entry
                .view
                .upgrade()
                .is_some_and(|view| !view.closed_and_quiescent())
        });
        if self.entries.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "resident producer read registry exhausted",
            ));
        }
        let read = source.view.begin()?;
        let publication = match &read.source.origin {
            Origin::Publication(job) => {
                if job
                    .lock()
                    .map_err(|_| invalid("producer publication poisoned"))?
                    .producer_reads_closed
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "publication producer reads closed",
                    ));
                }
                Some(Arc::downgrade(job))
            }
            Origin::Recovery(_) | Origin::RecoveredInline(_) => None,
        };
        self.entries.try_reserve(1).map_err(io::Error::other)?;
        self.entries.push(Entry {
            view: Arc::downgrade(&source.view),
            publication,
        });
        Ok(())
    }

    /// Closes only weak views originating in the specified actual publication job.
    pub(in crate::host_cache::owner) fn close_publication(
        &mut self,
        resource: &Arc<Mutex<PublicationJob>>,
    ) -> NativeProducerReadClosure {
        let mut report = NativeProducerReadClosure {
            observed_views: 0,
            active_views: 0,
        };
        self.entries.retain(|entry| {
            let Some(view) = entry.view.upgrade() else {
                return false;
            };
            if entry
                .publication
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|job| Arc::ptr_eq(&job, resource))
            {
                report.observed_views += 1;
                if !view.close() {
                    report.active_views += 1;
                }
            }
            true
        });
        report
    }
}

/// Checks the separate external producer/consumer view and registry storage envelope.
///
/// # Errors
/// Refuses arithmetic overflow in the configured finite record budget.
pub(in crate::host_cache::owner) fn storage_bytes(records: usize) -> io::Result<usize> {
    let slots = records
        .checked_mul(2)
        .ok_or_else(|| invalid("resident read slot bound overflow"))?;
    // External views and consumer jobs each have a finite record budget. One
    // additional source can be prepared before a full registry refuses it;
    // weak registration vectors include their capacity-growth overlap.
    slots
        .checked_add(1)
        .and_then(|count| count.checked_mul(super::header_bytes()))
        .and_then(|bytes| bytes.checked_add(slots.checked_mul(std::mem::size_of::<Entry>())?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProducerReadRegistry>()))
        .ok_or_else(|| invalid("resident read storage bound overflow"))
}
