//! Admits bounded untrusted encoded inputs on the actual running physical owner.
//!
//! Durable reservations precede every namespace or data write. Files, input
//! bytes and unresolved progress remain registered outside embedded custody;
//! dropping an accepted command's waiter cannot cancel its physical execution.
//! Verified inputs may request bounded eviction before reservation. These
//! commands establish neither consumer pins nor full bucket readiness.

mod backing;
mod cache_error;
pub(super) mod chunk;
mod error;
pub(in crate::host_cache::owner) mod eviction;
pub(super) mod handoff;
mod io;
mod memory;
mod metadata;
mod pressure;
pub(in crate::host_cache::owner) mod reads;
mod reconcile;
mod state;
mod ticket;
mod transfer;

pub(in crate::host_cache::owner) use backing::AdmissionJob;
pub use backing::{NativeChunkAdmission, NativeMetadataAdmission};
pub use cache_error::NativeAdmissionHandoffError;
pub use error::{NativeChunkAdmissionError, NativeMetadataAdmissionError};
pub use handoff::NativeAdmissionHandoffReport;
pub use ticket::NativeChunkAdmissionTicket;
pub(in crate::host_cache::owner) use transfer::{TransferSource, TransferredFunding};

use super::{
    NativeCacheOwnerConfig, NativeMetadataOwner,
    retention::{Command, NativeOwnerExecutor},
};
use std::{
    io as std_io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_format::identity::Descriptor;
use terrane_sdk::{pack::PackId, store::ChunkPosition};
use tokio::sync::oneshot;

/// Copies only validated finite resource policy, never native authority.
#[derive(Clone, Copy)]
pub(in crate::host_cache::owner) struct AdmissionBounds {
    bytes: usize,
}

impl AdmissionBounds {
    /// Checks all queued input accounting before the worker starts.
    ///
    /// # Errors
    /// Refuses unrepresentable retained, active and queued encoded input capacity.
    pub(in crate::host_cache::owner) fn new(
        config: &NativeCacheOwnerConfig,
    ) -> std_io::Result<Self> {
        memory::check(config)?;
        Ok(Self {
            bytes: config.reads.max_allocation_bytes,
        })
    }

    pub(in crate::host_cache::owner) fn check(
        self,
        first: usize,
        second: usize,
    ) -> std_io::Result<()> {
        if first == 0
            || first
                .checked_add(second)
                .is_none_or(|bytes| bytes > self.bytes)
        {
            return Err(std_io::Error::new(
                std_io::ErrorKind::StorageFull,
                "encoded admission exceeds configured input window",
            ));
        }
        Ok(())
    }
}

/// Keeps bounded untrusted input bytes alive with their actual physical job.
pub(in crate::host_cache::owner) enum Input {
    /// Describes one untrusted codec envelope and its declared boundary context.
    Chunk {
        descriptor: Descriptor,
        position: ChunkPosition,
        encoded: Arc<Vec<u8>>,
    },
    /// Describes an untrusted complete metadata pack and detached index.
    Metadata {
        expected_id: PackId,
        pack: Arc<Vec<u8>>,
        index: Arc<Vec<u8>>,
    },
}

impl NativeMetadataOwner {
    /// Submits bounded untrusted chunk bytes to the retained physical owner.
    ///
    /// Domain and profile derive from actual preparation. No caller declaration
    /// grants hash, pin, quota, filesystem or publication authority.
    /// Verified input may trigger one bounded cache eviction attempt before
    /// reserving space; pending deletion retains its actual quota charge.
    ///
    /// # Errors
    /// Returns untouched inputs on local/queue refusal; accepted failures retain
    /// physical resources and durable holds in the worker for reconciliation.
    /// Capacity refusal before reservation returns an accepted `StorageFull`
    /// error and leaves no reservation or files for the incoming input.
    pub async fn admit_chunk(
        &self,
        descriptor: Descriptor,
        position: ChunkPosition,
        encoded: Vec<u8>,
    ) -> Result<NativeChunkAdmission, NativeChunkAdmissionError> {
        self.submit_chunk(descriptor, position, encoded)?
            .finish()
            .await
    }

    /// Queues an original owned input without awaiting the worker's completion.
    ///
    /// # Errors
    /// Returns the untouched input if bounds, owner availability or queue
    /// capacity prevent submission. A ticket exists only after actual acceptance.
    pub(in crate::host_cache::owner) fn submit_chunk(
        &self,
        descriptor: Descriptor,
        position: ChunkPosition,
        encoded: Vec<u8>,
    ) -> Result<NativeChunkAdmissionTicket, NativeChunkAdmissionError> {
        let (response, receive) = oneshot::channel();
        let refusal = self
            .admission_bounds
            .check(encoded.len(), 0)
            .and_then(|()| self.admission_bounds.check(encoded.capacity(), 0))
            .err();
        let command = Command::AdmitChunk {
            descriptor,
            position,
            encoded,
            response,
        };
        let result = match (refusal, self.commands.as_ref()) {
            (Some(error), _) => Err((error, command)),
            (None, None) => Err((
                std_io::Error::other("native admission owner stopped"),
                command,
            )),
            (None, Some(commands)) => commands.try_send(command).map_err(submission_error),
        };
        if let Err((
            error,
            Command::AdmitChunk {
                descriptor,
                position,
                encoded,
                ..
            },
        )) = result
        {
            return Err(NativeChunkAdmissionError::Unsubmitted {
                error,
                descriptor,
                position,
                encoded,
            });
        }
        Ok(NativeChunkAdmissionTicket::new(receive))
    }

    /// Submits one bounded untrusted metadata pack and exact detached index.
    ///
    /// Both members are verified before bounded eviction and reservation.
    ///
    /// # Errors
    /// Returns untouched inputs on local/queue refusal. Verification, durability
    /// or accounting failures after acceptance retain all physical custody.
    /// Capacity refusal before reservation returns an accepted `StorageFull`
    /// error and leaves no reservation or files for the incoming pair.
    pub async fn admit_metadata_pack(
        &self,
        expected_id: PackId,
        pack: Vec<u8>,
        detached_index: Vec<u8>,
    ) -> Result<NativeMetadataAdmission, NativeMetadataAdmissionError> {
        let (response, receive) = oneshot::channel();
        let refusal = self
            .admission_bounds
            .check(pack.len(), detached_index.len())
            .and_then(|()| {
                self.admission_bounds
                    .check(pack.capacity(), detached_index.capacity())
            })
            .err();
        let command = Command::AdmitMetadata {
            expected_id,
            pack,
            index: detached_index,
            response,
        };
        let result = match (refusal, self.commands.as_ref()) {
            (Some(error), _) => Err((error, command)),
            (None, None) => Err((
                std_io::Error::other("native admission owner stopped"),
                command,
            )),
            (None, Some(commands)) => commands.try_send(command).map_err(submission_error),
        };
        if let Err((
            error,
            Command::AdmitMetadata {
                expected_id,
                pack,
                index,
                ..
            },
        )) = result
        {
            return Err(NativeMetadataAdmissionError::Unsubmitted {
                error,
                expected_id,
                pack,
                detached_index: index,
            });
        }
        receive
            .await
            .map_err(|_| {
                NativeMetadataAdmissionError::Accepted(std_io::Error::other(
                    "admission worker terminated before reply",
                ))
            })?
            .map_err(NativeMetadataAdmissionError::Accepted)
    }
}

fn submission_error(error: mpsc::TrySendError<Command>) -> (std_io::Error, Command) {
    match error {
        mpsc::TrySendError::Full(command) => (
            std_io::Error::new(
                std_io::ErrorKind::WouldBlock,
                "native admission queue is full",
            ),
            command,
        ),
        mpsc::TrySendError::Disconnected(command) => (
            std_io::Error::other("native admission queue stopped"),
            command,
        ),
    }
}

// Original completed admissions are checked after incoming verification but
// before funding or writes. A restored duplicate must not allocate another body
// or poison the Running owner with a new, unnecessary reservation.
fn refuse_completed(
    executor: &NativeOwnerExecutor,
    owner: &super::retention::Custody,
    resource: &Arc<Mutex<AdmissionJob>>,
    input: &Input,
) -> std_io::Result<()> {
    for registered in executor.admission_jobs() {
        if Arc::ptr_eq(registered, resource) {
            continue;
        }
        let job = backing::lock(registered)?;
        let same_key = match (&job.input, input) {
            (
                Input::Chunk {
                    descriptor: first, ..
                },
                Input::Chunk {
                    descriptor: second, ..
                },
            ) => first.digest() == second.digest(),
            (
                Input::Metadata {
                    expected_id: first, ..
                },
                Input::Metadata {
                    expected_id: second,
                    ..
                },
            ) => first == second,
            _ => false,
        };
        if job.complete && same_key {
            reconcile::verify(owner, &job)?;
            return Err(std_io::Error::new(
                std_io::ErrorKind::AlreadyExists,
                "actual completed native admission already owns the canonical allocation",
            ));
        }
    }
    Ok(())
}

/// Executes one bounded chunk command under the genuine exclusive running owner.
///
/// # Errors
/// Refuses stale authority, invalid bytes, capacity or physical completion failure.
pub(in crate::host_cache::owner) async fn chunk(
    executor: &mut NativeOwnerExecutor,
    descriptor: Descriptor,
    position: ChunkPosition,
    encoded: Vec<u8>,
) -> std_io::Result<NativeChunkAdmission> {
    let context = executor.admission_context()?;
    context.check_current().map_err(std_io::Error::other)?;
    let codec = terrane_format::codec::parse_envelope(&encoded)
        .map_err(std_io::Error::other)?
        .codec;
    eviction::restore_for(executor, &state::hex(descriptor.digest()))?;
    if let terrane_format::codec::Codec::ZstdDictionary(dictionary) = codec {
        eviction::restore_for(executor, &state::hex(&dictionary))?;
    }
    let custody = Arc::clone(executor.custody());
    let job = executor.register_admission(Input::Chunk {
        descriptor: descriptor.clone(),
        position,
        encoded: Arc::new(encoded),
    })?;
    let mut failure = FailureGuard::new(&custody, &job)?;
    let outcome = match chunk::run(executor, &custody, &job).await {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.reclaim_rejected_admission(&job)?;
            return Err(error);
        }
    };
    context.check_current().map_err(std_io::Error::other)?;
    let (future_hold, directory_allocated) = {
        let actual = backing::lock(&job)?;
        (actual.hold, actual.directory_bytes)
    };
    failure.settled = true;
    Ok(NativeChunkAdmission {
        _job: job,
        descriptor,
        allocated: outcome.0,
        charged: outcome.1,
        future_hold,
        directory_allocated,
    })
}

/// Executes one complete metadata-pair command under genuine running custody.
///
/// # Errors
/// Refuses stale authority, invalid pair, capacity or physical completion failure.
pub(in crate::host_cache::owner) async fn metadata(
    executor: &mut NativeOwnerExecutor,
    expected_id: PackId,
    pack: Vec<u8>,
    index: Vec<u8>,
) -> std_io::Result<NativeMetadataAdmission> {
    let context = executor.admission_context()?;
    context.check_current().map_err(std_io::Error::other)?;
    eviction::restore_pack(executor, expected_id)?;
    let custody = Arc::clone(executor.custody());
    let job = executor.register_admission(Input::Metadata {
        expected_id,
        pack: Arc::new(pack),
        index: Arc::new(index),
    })?;
    let mut failure = FailureGuard::new(&custody, &job)?;
    let outcome = match metadata::run(executor, &custody, &job).await {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.reclaim_rejected_admission(&job)?;
            return Err(error);
        }
    };
    context.check_current().map_err(std_io::Error::other)?;
    let (future_hold, directory_allocated) = {
        let actual = backing::lock(&job)?;
        (actual.hold, actual.directory_bytes)
    };
    failure.settled = true;
    Ok(NativeMetadataAdmission {
        _job: job,
        id: expected_id,
        allocated: outcome.0,
        charged: outcome.1,
        future_hold,
        directory_allocated,
    })
}

/// Invalidates abandoned physical work without taking a state or client mutex.
struct FailureGuard {
    fault: Arc<std::sync::atomic::AtomicBool>,
    started: Arc<std::sync::atomic::AtomicBool>,
    settled: bool,
}

impl FailureGuard {
    fn new(
        custody: &Arc<Mutex<super::retention::Custody>>,
        job: &Arc<Mutex<AdmissionJob>>,
    ) -> std_io::Result<Self> {
        let fault = Arc::clone(
            &custody
                .lock()
                .map_err(|_| std_io::Error::other("admission custody poisoned"))?
                .admission_fault,
        );
        let started = Arc::clone(&backing::lock(job)?.started);
        Ok(Self {
            fault,
            started,
            settled: false,
        })
    }
}

impl Drop for FailureGuard {
    fn drop(&mut self) {
        // Cancellation may drop an awaited producer while its embedded guards
        // are still being unwound. Never reacquire either mutex here. This
        // private actual-owner flag invalidates every Custody currentness check.
        if !self.settled && self.started.load(std::sync::atomic::Ordering::Acquire) {
            self.fault.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AdmissionBounds;

    #[test]
    fn untrusted_pair_input_is_bounded_with_checked_addition() {
        let bounds = AdmissionBounds { bytes: 1024 };

        assert!(bounds.check(512, 512).is_ok());
        assert!(bounds.check(512, 513).is_err());
        assert!(bounds.check(usize::MAX, 1).is_err());
        assert!(bounds.check(0, 0).is_err());
    }

    #[test]
    fn cancelled_started_phase_faults_without_native_authority_or_mutexes() {
        use std::{
            future::Future,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            task::{Context, Poll, Waker},
        };
        let fault = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(true));
        let actual = Arc::clone(&fault);
        // Only the guard's cancellation rule is exercised. No preparation,
        // quota observation, filesystem receipt or native command is fabricated.
        let mut pending = Box::pin(async move {
            let _guard = super::FailureGuard {
                fault,
                started,
                settled: false,
            };
            std::future::pending::<()>().await;
        });
        let waker = Waker::noop();
        assert!(matches!(
            pending.as_mut().poll(&mut Context::from_waker(waker)),
            Poll::Pending
        ));
        assert!(!actual.load(Ordering::Acquire));
        drop(pending);
        assert!(actual.load(Ordering::Acquire));
    }
}
