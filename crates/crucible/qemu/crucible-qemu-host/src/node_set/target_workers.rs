//! Borrows Source nodes and prepaid Target rows on scoped concurrent workers.
//!
//! The containing Target Pending owns the entire NodeSet outside the Source
//! mutex. Workers borrow nodes and rows; a panic never owns either value.
//! Requested stack/page geometry is explicit and retained before Source birth.
//! It is not a qualification of private std, pthread/TLS, guard or stack-cache
//! allocation peaks, which remain separate owning resource obligations.

use super::*;

// Every slot borrows a distinct, vacant row in the existing second preborn
// buffer. Unexpected join failures remain there through an outer unwind.
struct ScopedWorker<'scope, 'row, D> {
    handle: Option<std::thread::ScopedJoinHandle<'scope, ()>>,
    panic_row: &'row mut D,
}

struct ScopedWorkers<'scope, 'row, D> {
    handles: Vec<ScopedWorker<'scope, 'row, D>>,
    record_panic: fn(&mut D, Box<dyn std::any::Any + Send>),
    take_panic: fn(&mut D) -> Option<Box<dyn std::any::Any + Send>>,
}

impl<D> ScopedWorkers<'_, '_, D> {
    fn join_all(&mut self) {
        for slot in &mut self.handles {
            if let Some(handle) = slot.handle.take()
                && let Err(payload) = handle.join()
            {
                // Each sink was vacant before birth and receives at most one
                // result. The actual callback is an infallible Option move.
                (self.record_panic)(slot.panic_row, payload);
            }
        }
    }

    fn finish(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        self.join_all();
        for slot in &mut self.handles {
            if let Some(payload) = (self.take_panic)(slot.panic_row) {
                return Some(payload);
            }
        }
        None
    }
}

impl<D> Drop for ScopedWorkers<'_, '_, D> {
    fn drop(&mut self) {
        // Parent-side unwind also physically joins every remaining helper.
        // It neither propagates nor destroys any secondary panic payload.
        self.join_all();
    }
}

/// Captures the exact explicit request used by every selected fork worker.
#[derive(Clone, Copy, Debug)]
pub struct QemuHotForkWorkerGeometry {
    requested_stack_bytes: usize,
    rounded_request_bytes: usize,
}

impl QemuHotForkWorkerGeometry {
    /// Captures the valid inherited override or the matched Linux Rust default.
    ///
    /// The request is captured before the Source query and reused unchanged by
    /// Builder. Invalid environment values follow the matched std parser's
    /// default behavior; zero remains a request, not proof of zero native stack.
    ///
    /// # Errors
    /// Refuses invalid page geometry or overflowing page rounding.
    pub fn capture() -> Result<Self, BackendError> {
        let inherited = std::env::var_os("RUST_MIN_STACK");
        Self::from_environment(inherited.as_deref(), rustix::param::page_size())
    }

    fn from_environment(
        inherited: Option<&std::ffi::OsStr>,
        page: usize,
    ) -> Result<Self, BackendError> {
        let requested = inherited
            .and_then(|value| value.to_str().and_then(|value| value.parse::<usize>().ok()))
            .unwrap_or(2 * 1024 * 1024);
        Self::with_request(requested, page)
    }

    fn with_request(requested: usize, page: usize) -> Result<Self, BackendError> {
        if !page.is_power_of_two() {
            return Err(refused("fork worker page geometry is invalid"));
        }
        let rounded_request_bytes = requested
            .checked_add(page - 1)
            .map(|bytes| bytes & !(page - 1))
            .ok_or_else(|| refused("fork worker stack request overflows"))?;
        Ok(Self {
            requested_stack_bytes: requested,
            rounded_request_bytes,
        })
    }

    /// Measures requested stacks and actual scoped-handle payloads only.
    ///
    /// This term excludes private std/pthread/TLS/guard/control peaks. Their
    /// missing qualification must not be replaced by this partial measurement.
    ///
    /// # Errors
    /// Refuses an empty selection or overflowing payload arithmetic.
    pub fn requested_control_bytes(self, nodes: usize) -> Result<u64, BackendError> {
        if nodes == 0 {
            return Err(refused("fork worker selection is empty"));
        }
        let handles = std::alloc::Layout::array::<ScopedWorker<'static, 'static, ()>>(nodes)
            .map_err(|_| refused("fork worker handle extent overflows"))?;
        self.rounded_request_bytes
            .checked_mul(nodes)
            .and_then(|bytes| bytes.checked_add(handles.size()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| refused("fork worker requested extent overflows"))
    }
}

/// Keeps the actual first refusal while all nodes and rows remain borrowed.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotForkWorkerFailure {
    /// The selected Source/token/row roster refused before spawning workers.
    #[error(transparent)]
    Source(#[from] BackendError),
    /// Preparing the already-priced handle payload failed before spawning.
    #[error("reserve fork worker handles: {0}")]
    Handles(#[source] std::collections::TryReserveError),
    /// The OS refused one worker after earlier workers may already have run.
    #[error("start fork worker: {0}")]
    Spawn(#[source] std::io::Error),
}

/// Borrows the prepared Source roster and its existing Target result rows.
pub struct QemuHotForkWorkerRows<'a, D> {
    /// Exact prepared tokens retained by the containing Target Pending.
    pub prepared: &'a [QemuNodeSetPreparedHotForkTemplate],
    /// Existing per-node rows borrowed by the selected workers.
    pub rows: &'a mut [D],
    /// Vacant companion rows retaining unexpected join failures.
    pub panic_rows: &'a mut [D],
}

/// Defines row access and result handling for the scoped fork workers.
///
/// Panic callbacks move existing payloads between vacant slots. They must not
/// allocate, issue work or panic; the containing Target retains every row.
pub struct QemuHotForkWorkerOperations<D> {
    /// Borrows a row's stable node identity for roster validation.
    pub node_for: fn(&D) -> &NodeId,
    /// Runs one prepared Source operation against its existing Target row.
    pub operation: for<'a> fn(QemuNodeSetPreparedHotForkSource<'a>, &mut D),
    /// Moves the actual panic payload into the row's vacant first-panic slot.
    pub record_panic: fn(&mut D, Box<dyn std::any::Any + Send>),
    /// Takes the retained panic payload after physical worker joining.
    pub take_panic: fn(&mut D) -> Option<Box<dyn std::any::Any + Send>>,
    /// Checks that a companion row can retain an unexpected join failure.
    pub panic_is_vacant: fn(&D) -> bool,
}

impl QemuNodeSet {
    /// Runs the same selected concurrency with no per-node ownership transfer.
    ///
    /// `record_panic` must only move the received existing payload into that
    /// row's vacant first-panic slot. It may not allocate, issue work or panic.
    /// Actual Source permission remains in its genuine prepared token, existing
    /// node supervisor and retained containing resource guard.
    ///
    /// # Errors
    /// Preserves the first validation/allocation/spawn refusal. Every started
    /// worker is explicitly joined before return or panic propagation; all rows
    /// and nodes remain in the caller's
    /// actual Target Pending on either outcome.
    pub fn with_prepared_hot_fork_sources_concurrent<D>(
        &mut self,
        retained: QemuHotForkWorkerRows<'_, D>,
        geometry: QemuHotForkWorkerGeometry,
        operations: QemuHotForkWorkerOperations<D>,
    ) -> Result<(), QemuHotForkWorkerFailure>
    where
        D: Send,
    {
        let QemuHotForkWorkerRows {
            prepared,
            rows,
            panic_rows,
        } = retained;
        let QemuHotForkWorkerOperations {
            node_for,
            operation,
            record_panic,
            take_panic,
            panic_is_vacant,
        } = operations;

        if prepared.is_empty()
            || rows.len() != panic_rows.len()
            || !rows
                .iter()
                .zip(panic_rows.iter())
                .all(|(row, sink)| node_for(row) == node_for(sink) && panic_is_vacant(sink))
            || !rows
                .windows(2)
                .all(|pair| node_for(&pair[0]) < node_for(&pair[1]))
            || !prepared
                .windows(2)
                .all(|pair| pair[0].node() < pair[1].node())
            || !prepared.iter().all(|token| {
                rows.binary_search_by(|row| node_for(row).cmp(token.node()))
                    .is_ok()
            })
        {
            return Err(refused("fork worker rows differ from the exact prepared roster").into());
        }
        geometry.requested_control_bytes(prepared.len())?;
        for token in prepared {
            self.validate_retained_hot_fork_template(token)?;
        }
        let mut first = None;
        let unexpected_panic = thread::scope(|scope| {
            let mut workers = ScopedWorkers {
                handles: Vec::new(),
                record_panic,
                take_panic,
            };
            if let Err(error) = workers.handles.try_reserve_exact(prepared.len()) {
                first = Some(QemuHotForkWorkerFailure::Handles(error));
                return None;
            }
            let nodes = self.nodes.iter_mut().filter(|(node, _)| {
                prepared
                    .binary_search_by(|token| token.node().cmp(node))
                    .is_ok()
            });
            let selected_rows = rows.iter_mut().filter(|row| {
                prepared
                    .binary_search_by(|token| token.node().cmp(node_for(row)))
                    .is_ok()
            });
            let selected_panic_rows = panic_rows.iter_mut().filter(|row| {
                prepared
                    .binary_search_by(|token| token.node().cmp(node_for(row)))
                    .is_ok()
            });
            for ((((node, backend), token), row), panic_row) in nodes
                .zip(prepared)
                .zip(selected_rows)
                .zip(selected_panic_rows)
            {
                // Prior validation and immutable map keys make this exact pairing
                // stable. Nodes are never removed or reconstructed in the map.
                if node != token.node() {
                    first = Some(refused("fork worker source pairing changed").into());
                    break;
                }
                let worker = thread::Builder::new()
                    .stack_size(geometry.requested_stack_bytes)
                    .spawn_scoped(scope, move || {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            operation(
                                QemuNodeSetPreparedHotForkSource {
                                    source: backend,
                                    prepared: token,
                                },
                                row,
                            );
                        }));
                        if let Err(payload) = result {
                            record_panic(row, payload);
                        }
                    });
                match worker {
                    Ok(worker) => workers.handles.push(ScopedWorker {
                        handle: Some(worker),
                        panic_row,
                    }),
                    Err(error) => {
                        first = Some(QemuHotForkWorkerFailure::Spawn(error));
                        break;
                    }
                }
            }
            // The only authored worker-panic callback is an infallible field
            // move. Joining does not dispose any node, target or private file.
            workers.finish()
        });
        if let Some(payload) = unexpected_panic {
            // Every helper has physically joined. The first actual payload is
            // propagated; all independent secondary outcomes remain in Main.
            std::panic::resume_unwind(payload);
        }
        match first {
            Some(first) => Err(first),
            None => Ok(()),
        }
    }
}

fn refused(message: impl Into<String>) -> BackendError {
    BackendError::Rejected {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_linux_default_and_valid_inherited_request_are_preserved() {
        let default = QemuHotForkWorkerGeometry::from_environment(None, 4096).unwrap();
        assert_eq!(default.requested_stack_bytes, 2 * 1024 * 1024);
        let selected = QemuHotForkWorkerGeometry::from_environment(
            Some(std::ffi::OsStr::new("33554432")),
            4096,
        )
        .unwrap();
        assert_eq!(selected.requested_stack_bytes, 32 * 1024 * 1024);
        let invalid = QemuHotForkWorkerGeometry::from_environment(
            Some(std::ffi::OsStr::new("not-an-integer")),
            4096,
        )
        .unwrap();
        assert_eq!(invalid.requested_stack_bytes, default.requested_stack_bytes);
        let zero =
            QemuHotForkWorkerGeometry::from_environment(Some(std::ffi::OsStr::new("0")), 4096)
                .unwrap();
        assert_eq!(zero.requested_stack_bytes, 0);
        // A zero request still has an unqualified native pthread minimum; this
        // control intentionally asserts no mapping/physical-return fact.
    }

    #[test]
    fn requested_stack_rounding_is_explicit_and_overflow_refuses() {
        let exact = QemuHotForkWorkerGeometry::with_request(2 * 1024 * 1024, 4096).unwrap();
        let rounded = QemuHotForkWorkerGeometry::with_request(2 * 1024 * 1024 + 1, 4096).unwrap();
        assert_eq!(
            rounded.rounded_request_bytes - exact.rounded_request_bytes,
            4096
        );
        assert!(QemuHotForkWorkerGeometry::with_request(usize::MAX, 4096).is_err());
        assert!(QemuHotForkWorkerGeometry::with_request(1, 3).is_err());
        assert!(exact.requested_control_bytes(0).is_err());
        assert!(exact.requested_control_bytes(usize::MAX).is_err());
    }
}

#[cfg(test)]
mod join_tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};

    struct BlockingTls {
        entered: Sender<()>,
        release: Receiver<()>,
    }
    impl Drop for BlockingTls {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv();
        }
    }
    thread_local! {
        static BLOCKED_TLS: RefCell<Option<BlockingTls>> = const { RefCell::new(None) };
    }
    type PanicSlot = Option<Box<dyn std::any::Any + Send>>;
    fn record(slot: &mut PanicSlot, payload: Box<dyn std::any::Any + Send>) {
        *slot = Some(payload);
    }
    fn take(slot: &mut PanicSlot) -> PanicSlot {
        slot.take()
    }

    fn blocked_tls_join(parent_unwinds: bool) {
        let (entered, tls_entered) = mpsc::channel();
        let (release_tls, release) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let runner = std::thread::spawn(move || {
            let mut first_slot = None;
            let mut second_slot = None;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::thread::scope(|scope| {
                    let mut workers = ScopedWorkers {
                        handles: Vec::with_capacity(2),
                        record_panic: record,
                        take_panic: take,
                    };
                    let first = scope.spawn(|| std::panic::panic_any("first worker panic"));
                    workers.handles.push(ScopedWorker {
                        handle: Some(first),
                        panic_row: &mut first_slot,
                    });
                    let second = scope.spawn(move || {
                        BLOCKED_TLS.with(|slot| {
                            *slot.borrow_mut() = Some(BlockingTls { entered, release });
                        });
                    });
                    workers.handles.push(ScopedWorker {
                        handle: Some(second),
                        panic_row: &mut second_slot,
                    });
                    if parent_unwinds {
                        std::panic::panic_any("parent before join");
                    }
                    if let Some(payload) = workers.finish() {
                        std::panic::resume_unwind(payload);
                    }
                });
            }));
            let first = result.unwrap_err();
            assert_eq!(
                first.downcast_ref::<&str>(),
                Some(&if parent_unwinds {
                    "parent before join"
                } else {
                    "first worker panic"
                })
            );
            assert_eq!(first_slot.is_some(), parent_unwinds);
            if parent_unwinds {
                assert_eq!(
                    first_slot
                        .as_ref()
                        .and_then(|payload| payload.downcast_ref::<&str>()),
                    Some(&"first worker panic")
                );
            }
            assert!(second_slot.is_none());
            let _ = finished.send(());
        });
        tls_entered
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        // Keep the actual TLS destructor blocked while observing that neither
        // normal join nor parent unwind can publish physical completion.
        assert!(matches!(
            completion.recv_timeout(std::time::Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        ));
        release_tls.send(()).unwrap();
        completion
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        runner.join().unwrap();
    }

    #[test]
    fn first_join_panic_waits_for_other_native_tls() {
        blocked_tls_join(false);
    }

    #[test]
    fn parent_unwind_joins_all_helpers_and_retains_secondary_panic() {
        blocked_tls_join(true);
    }
}
