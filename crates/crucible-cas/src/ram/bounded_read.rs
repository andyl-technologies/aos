//! Opaque, single-use bounded reads borrowing the actual RAM operation.

use crate::content_store::{ImmutableBlobBackend, StoreError};

use super::codec::{TreeNode, TreeRef, read_envelope_from, validate_tree};
use super::{LeasedRamRoot, RamStoreError, Work};
use std::cell::Cell;

#[derive(Clone, Copy)]
enum ReadPhase {
    Ready,
    Active,
    Completed,
    Failed,
    Consumed,
}

enum ReadTask<'read> {
    Tree(TreeRef),
    Canonical {
        id: crate::content_store::ContentId,
        response: &'read crate::owned_decode::DecodeBudget,
        expected: Option<TreeRef>,
    },
    Difference {
        before: &'read LeasedRamRoot,
        after: &'read LeasedRamRoot,
        visitor: &'read mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
    },
}

impl ReadTask<'_> {
    fn reborrow(&mut self) -> ReadTask<'_> {
        match self {
            Self::Tree(expected) => ReadTask::Tree(*expected),
            Self::Canonical {
                id,
                response,
                expected,
            } => ReadTask::Canonical {
                id: *id,
                response,
                expected: *expected,
            },
            Self::Difference {
                before,
                after,
                visitor,
            } => ReadTask::Difference {
                before,
                after,
                visitor: &mut **visitor,
            },
        }
    }
}

enum ReadValue {
    Tree(TreeNode),
    Canonical(Option<Vec<u8>>),
    Difference(u64),
}

struct ReadState {
    phase: ReadPhase,
    pending: Cell<Option<Result<ReadValue, RamStoreError>>>,
}

struct PhysicalReadCheck<'read> {
    guard: &'read dyn crate::content_store::StorePhysicalQuotaGuard,
    checked_backend: &'read dyn ImmutableBlobBackend,
    previous: Option<&'read PhysicalReadCheck<'read>>,
}

fn checked_default<'read>(
    mut physical: Option<&'read PhysicalReadCheck<'read>>,
) -> Option<&'read dyn ImmutableBlobBackend> {
    let mut backend = None;
    while let Some(check) = physical {
        backend = Some(check.checked_backend);
        physical = check.previous;
    }
    backend
}

fn verify_physical(
    original: &crate::owned_decode::DecodeBudget,
    physical: Option<&PhysicalReadCheck<'_>>,
) -> Result<(), StoreError> {
    if let Some(check) = physical {
        // Existing checked facades supervise outer ownership before entering
        // a nested child. A successful verifier may itself close the original.
        verify_physical(original, check.previous)?;
        check.guard.verify()?;
        original
            .verify_live()
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
    }
    Ok(())
}

/// Borrows one bounded RAM read and its original operation custody.
///
/// Only the RAM store constructs this request. Backends may forward the same
/// borrow; they cannot construct a request, reset its state, access its pending
/// value, or select a different admission account. The default backend method
/// executes the existing checked read on that backend exactly once.
///
/// ```compile_fail
/// use crucible_cas::ram::BoundedReadRequest;
/// fn reset(request: &mut BoundedReadRequest<'_, '_>) {
///     request.phase = ();
/// }
/// ```
pub struct BoundedReadRequest<'read, 'operation> {
    work: &'read mut Work<'operation>,
    task: ReadTask<'read>,
    state: &'read mut ReadState,
    physical: Option<&'read PhysicalReadCheck<'read>>,
}

impl<'operation> BoundedReadRequest<'_, 'operation> {
    pub(crate) fn with_physical(
        &mut self,
        guard: &dyn crate::content_store::StorePhysicalQuotaGuard,
        checked_backend: &dyn ImmutableBlobBackend,
        forward: impl FnOnce(&mut BoundedReadRequest<'_, 'operation>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let physical = PhysicalReadCheck {
            guard,
            checked_backend,
            previous: self.physical,
        };
        let mut request = BoundedReadRequest {
            work: self.work,
            task: self.task.reborrow(),
            state: self.state,
            physical: Some(&physical),
        };
        forward(&mut request)
    }

    pub(crate) fn execute_existing_checked<B: ImmutableBlobBackend + ?Sized>(
        &mut self,
        backend: &B,
    ) -> Result<(), StoreError> {
        if let Some(backend) = checked_default(self.physical) {
            return self.execute_existing_on(backend);
        }
        self.execute_existing_on(backend)
    }

    fn execute_existing_on<B: ImmutableBlobBackend + ?Sized>(
        &mut self,
        backend: &B,
    ) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            ReadPhase::Active | ReadPhase::Completed | ReadPhase::Consumed => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        self.state.phase = ReadPhase::Active;
        let result = match &mut self.task {
            ReadTask::Tree(expected) => read_envelope_from(backend, expected.id, self.work, true)
                .and_then(|envelope| validate_tree(&envelope, *expected))
                .map(ReadValue::Tree),
            ReadTask::Canonical { id, expected, .. } => {
                match read_envelope_from(backend, *id, self.work, true) {
                    Ok(envelope) => {
                        let validation = match expected {
                            Some(expected) => validate_tree(&envelope, *expected).map(|_| ()),
                            None => Ok(()),
                        };
                        validation.map(|()| ReadValue::Canonical(Some(envelope.canonical_bytes())))
                    }
                    Err(error) if super::store_boundary::confirmed_absence(&error, *id) => {
                        Ok(ReadValue::Canonical(None))
                    }
                    Err(error) => Err(error),
                }
            }
            ReadTask::Difference {
                before,
                after,
                visitor,
            } => {
                let mut access = super::difference::ExistingDifference {
                    backend,
                    work: self.work,
                    visitor: &mut **visitor,
                };
                super::difference::walk_roots(&mut access, before, after).map(ReadValue::Difference)
            }
        };
        match result {
            Ok(node) => {
                self.state.pending.set(Some(Ok(node)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            Err(error) => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
        }
    }

    pub(crate) fn execute_sqlite(
        &mut self,
        backend: &crate::content_store::SqliteBlobBackend,
    ) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            _ => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        let expected = match &self.task {
            ReadTask::Tree(expected) => *expected,
            ReadTask::Canonical { .. } => return self.execute_sqlite_canonical(backend),
            ReadTask::Difference { .. } => return self.execute_sqlite_difference(backend),
        };
        if expected.id.schema_version() != 1 {
            self.state.phase = ReadPhase::Failed;
            return Err(self
                .work
                .account
                .fail_read(RamStoreError::Invalid("RAM storage schema")));
        }
        if let Err(error) = self.work.reject_exhausted_nonempty_visit() {
            self.state.phase = ReadPhase::Failed;
            return Err(self.work.account.fail_read(error));
        }
        self.state.phase = ReadPhase::Active;
        let pending = &self.state.pending;
        let physical = self.physical;
        let Work {
            limits,
            visits,
            io_bytes,
            boundary,
            account,
            ..
        } = &mut *self.work;
        let result = account.checked(boundary, |original, check| {
            let mut guarded = || {
                crate::content_store::checked_reader::check(original, check)?;
                verify_physical(original, physical)
            };
            let check: &mut dyn FnMut() -> Result<(), StoreError> = if physical.is_some() {
                &mut guarded
            } else {
                check
            };
            backend.consume_canonical_snapshot(
                original,
                expected.id,
                4096,
                check,
                |length| {
                    let validation = (|| {
                        if length > 4096 {
                            return Err(RamStoreError::Limit("single canonical object"));
                        }
                        *visits = visits
                            .checked_add(1)
                            .ok_or(RamStoreError::Limit("object visits"))?;
                        *io_bytes = io_bytes
                            .checked_add(length)
                            .ok_or(RamStoreError::Limit("I/O bytes"))?;
                        if *visits > limits.maximum_object_visits {
                            return Err(RamStoreError::Limit("object visits"));
                        }
                        if *io_bytes > limits.maximum_io_bytes {
                            return Err(RamStoreError::Limit("I/O bytes"));
                        }
                        Ok(())
                    })();
                    validation.map_err(|error| {
                        pending.set(Some(Err(error)));
                        StoreError::Unsupported {
                            capability: "bounded-canonical-validation-refused",
                        }
                    })
                },
                |bytes| {
                    let result = super::canonical_tree::read_tree_canonical(bytes, expected)
                        .map(ReadValue::Tree);
                    let valid = result.is_ok();
                    pending.set(Some(result));
                    valid
                },
            )
        });
        match (pending.take(), result) {
            (Some(Ok(node)), Ok(())) => {
                pending.set(Some(Ok(node)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            (Some(Err(_)), Err(RamStoreError::Store(provider)))
                if matches!(
                    provider.original_failure(),
                    StoreError::DecodeAdmission { .. }
                ) =>
            {
                // This closed producer only emits admission errors from the
                // same original account. Its checked EOF refusal precedes
                // exposing any pending canonical validation or value.
                self.state.phase = ReadPhase::Failed;
                Err(account.fail_read(provider.into()))
            }
            (Some(Err(first)), Err(RamStoreError::Store(provider))) => {
                self.state.phase = ReadPhase::Failed;
                Err(account.fail_validation_with_provider(first, provider))
            }
            (_, Err(error)) => {
                self.state.phase = ReadPhase::Failed;
                Err(account.fail_read(error))
            }
            (_, Ok(())) => {
                self.state.phase = ReadPhase::Failed;
                Err(account.fail_read(
                    StoreError::Unsupported {
                        capability: "bounded-read-request-not-completed",
                    }
                    .into(),
                ))
            }
        }
    }

    fn first_failure(&self) -> StoreError {
        match self.work.account.read_failure() {
            Some(first) => first,
            None => unreachable!("a failed bounded request retains its first failure"),
        }
    }

    fn execute_sqlite_canonical(
        &mut self,
        backend: &crate::content_store::SqliteBlobBackend,
    ) -> Result<(), StoreError> {
        let ReadTask::Canonical {
            id,
            response,
            expected,
        } = self.task
        else {
            unreachable!("only a canonical request enters the single-record read");
        };
        let (maximum, children) = match super::codec::object_limits(id) {
            Ok(limits) => limits,
            Err(error) => {
                self.state.phase = ReadPhase::Failed;
                return Err(self.work.account.fail_read(error));
            }
        };
        if id.schema_version() != 1 {
            self.state.phase = ReadPhase::Failed;
            return Err(self
                .work
                .account
                .fail_read(RamStoreError::Invalid("RAM storage schema")));
        }
        if let Err(error) = self.work.reject_exhausted_nonempty_visit() {
            self.state.phase = ReadPhase::Failed;
            return Err(self.work.account.fail_read(error));
        }
        self.state.phase = ReadPhase::Active;
        let pending_error = Cell::new(None);
        let validation_ran = Cell::new(false);
        let eof_refused = Cell::new(false);
        let physical = self.physical;
        let Work {
            limits,
            visits,
            io_bytes,
            boundary,
            account,
            ..
        } = &mut *self.work;
        let result = account.checked(boundary, |original, check| {
            let mut guarded = || {
                let result = crate::content_store::checked_reader::check(original, check)
                    .and_then(|()| verify_physical(original, physical));
                if validation_ran.get() && result.is_err() {
                    eof_refused.set(true);
                }
                result
            };
            backend.consume_canonical_record(
                original,
                id,
                maximum,
                &mut guarded,
                |length| {
                    let admitted = super::store_boundary::admit_object(
                        *limits, visits, io_bytes, length, maximum,
                    );
                    if let Err(error) = admitted {
                        pending_error.set(Some(error));
                        return Err(StoreError::Unsupported {
                            capability: "bounded-canonical-validation-refused",
                        });
                    }
                    let length = usize::try_from(length).map_err(|_| StoreError::Quota)?;
                    response.charge_array::<u8>(length).map_err(|error| {
                        crate::content_store::batch::admission_under(response, error)
                    })?;
                    original.verify_live().map_err(|error| {
                        crate::content_store::batch::admission_under(original, error)
                    })?;
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(length)
                        .map_err(|source| StoreError::Allocation {
                            source,
                            custody: Some(response.custody()),
                        })?;
                    Ok(bytes)
                },
                |bytes| {
                    validation_ran.set(true);
                    match match expected {
                        Some(expected) => {
                            super::canonical_tree::read_tree_canonical(bytes, expected).map(|_| ())
                        }
                        None => super::canonical_tree::validate_envelope_canonical(bytes, children)
                            .map_err(RamStoreError::from),
                    } {
                        Ok(()) => Ok(true),
                        Err(error) => {
                            pending_error.set(Some(error));
                            Ok(false)
                        }
                    }
                },
            )
        });
        self.complete_session_read(
            pending_error.take(),
            result.map(ReadValue::Canonical),
            eof_refused.get(),
        )
    }

    fn execute_sqlite_difference(
        &mut self,
        backend: &crate::content_store::SqliteBlobBackend,
    ) -> Result<(), StoreError> {
        if let Err(error) = self.work.reject_exhausted_nonempty_visit() {
            self.state.phase = ReadPhase::Failed;
            return Err(self.work.account.fail_read(error));
        }
        let ReadTask::Difference {
            before,
            after,
            visitor,
        } = &mut self.task
        else {
            unreachable!("only a comparison enters the snapshot walk");
        };
        self.state.phase = ReadPhase::Active;
        let pending_error = Cell::new(None);
        let eof_refused = Cell::new(false);
        let physical = self.physical;
        let Work {
            limits,
            visits,
            io_bytes,
            boundary,
            account,
            ..
        } = &mut *self.work;
        let result = account.checked(boundary, |original, check| {
            let mut guarded = || {
                crate::content_store::checked_reader::check(original, check)?;
                verify_physical(original, physical)
            };
            let check: &mut dyn FnMut() -> Result<(), StoreError> = if physical.is_some() {
                &mut guarded
            } else {
                check
            };
            let mut session =
                crate::content_store::SqliteRamReadSession::new(backend, original, check)?;
            let walked = {
                let mut access = super::difference::sqlite::SqliteDifference {
                    session: &mut session,
                    limits: *limits,
                    visits,
                    io_bytes,
                    boundary: check,
                    visitor: &mut **visitor,
                    pending_error: &pending_error,
                };
                super::difference::walk_roots(&mut access, before, after)
            };
            let (value, completion) = match walked {
                Ok(value) => (Some(value), Ok(())),
                Err(RamStoreError::Store(error)) => (None, Err(error)),
                Err(error) => {
                    pending_error.set(Some(error));
                    (None, Err(super::difference::sqlite::validation_marker()))
                }
            };
            let (completion, refused) = session.finish(check, completion);
            eof_refused.set(refused);
            completion?;
            match value {
                Some(value) => Ok(value),
                None => unreachable!("a successful walk retains its changed-page count"),
            }
        });
        self.complete_session_read(
            pending_error.take(),
            result.map(ReadValue::Difference),
            eof_refused.get(),
        )
    }

    fn complete_session_read(
        &mut self,
        pending: Option<RamStoreError>,
        result: Result<ReadValue, RamStoreError>,
        eof_refused: bool,
    ) -> Result<(), StoreError> {
        match (pending, result) {
            (None, Ok(value)) => {
                self.state.pending.set(Some(Ok(value)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            (Some(_), Err(error)) if eof_refused => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
            (Some(first), Err(RamStoreError::Store(provider))) => {
                self.state.phase = ReadPhase::Failed;
                if matches!(
                    provider,
                    StoreError::Unsupported {
                        capability: "bounded-canonical-validation-refused"
                    }
                ) {
                    Err(self.work.account.fail_read(first))
                } else {
                    Err(self
                        .work
                        .account
                        .fail_validation_with_provider(first, provider))
                }
            }
            (_, Err(error)) => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
            (Some(_), Ok(_)) => {
                unreachable!("pending validation cannot yield an accepted closed read")
            }
        }
    }

    fn finish(&mut self, provider: Result<(), StoreError>) -> Result<ReadValue, StoreError> {
        let previous = std::mem::replace(&mut self.state.phase, ReadPhase::Consumed);
        match (previous, provider) {
            (ReadPhase::Completed, Ok(())) => {
                let original = self.work.original();
                if let Err(error) = original.verify_live() {
                    let error = crate::content_store::batch::admission_under(original, error);
                    self.state.pending.take();
                    return Err(self.work.account.fail_read(error.into()));
                }
                match self.state.pending.take() {
                    Some(Ok(node)) => Ok(node),
                    _ => unreachable!("a completed bounded request retains its node"),
                }
            }
            (ReadPhase::Failed, Ok(())) => Err(self.first_failure()),
            (ReadPhase::Failed, Err(error)) => Err(self.work.account.reconcile_failed_read(error)),
            (_, Err(error)) => {
                // A later provider cleanup error remains authoritative even
                // after a complete read. No pending value escapes that error.
                self.state.pending.take();
                if self.work.account.read_failure().is_some() {
                    Err(self.work.account.reconcile_failed_read(error))
                } else {
                    Err(self.work.account.fail_read(error.into()))
                }
            }
            (_, Ok(())) => Err(self.work.account.fail_read(
                StoreError::Unsupported {
                    capability: "bounded-read-request-not-completed",
                }
                .into(),
            )),
        }
    }
}

pub(super) fn read_tree(
    backend: &dyn ImmutableBlobBackend,
    expected: TreeRef,
    work: &mut Work<'_>,
) -> Result<TreeNode, RamStoreError> {
    // A previous failed operation never reaches the provider again, including
    // providers that override the nominal method without using its default.
    if let Some(first) = work.account.read_failure() {
        return Err(first.into());
    }
    if let Err(error) = work.original().verify_live() {
        let error = RamStoreError::from_admission(work.original(), error);
        return Err(work.account.fail_read(error).into());
    }
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work,
        task: ReadTask::Tree(expected),
        state: &mut state,
        physical: None,
    };
    let provider = backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::Tree(node) => Ok(node),
        ReadValue::Difference(_) | ReadValue::Canonical(_) => {
            unreachable!("a tree request retains its tree result")
        }
    }
}

pub(super) fn read_difference(
    backend: &dyn ImmutableBlobBackend,
    before: &LeasedRamRoot,
    after: &LeasedRamRoot,
    visitor: &mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
    work: &mut Work<'_>,
) -> Result<u64, RamStoreError> {
    if let Some(first) = work.account.read_failure() {
        return Err(first.into());
    }
    if let Err(error) = work.original().verify_live() {
        let error = RamStoreError::from_admission(work.original(), error);
        return Err(work.account.fail_read(error).into());
    }
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work,
        task: ReadTask::Difference {
            before,
            after,
            visitor,
        },
        state: &mut state,
        physical: None,
    };
    let provider = backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::Difference(value) => Ok(value),
        ReadValue::Tree(_) | ReadValue::Canonical(_) => {
            unreachable!("a comparison retains its changed-page count")
        }
    }
}

pub(super) fn read_canonical(
    backend: &dyn ImmutableBlobBackend,
    id: crate::content_store::ContentId,
    response: &crate::owned_decode::DecodeBudget,
    work: &mut Work<'_>,
) -> Result<Option<Vec<u8>>, RamStoreError> {
    read_canonical_expected(backend, id, response, None, work)
}

pub(super) fn read_canonical_tree(
    backend: &dyn ImmutableBlobBackend,
    expected: TreeRef,
    response: &crate::owned_decode::DecodeBudget,
    work: &mut Work<'_>,
) -> Result<Option<Vec<u8>>, RamStoreError> {
    read_canonical_expected(backend, expected.id, response, Some(expected), work)
}

fn read_canonical_expected(
    backend: &dyn ImmutableBlobBackend,
    id: crate::content_store::ContentId,
    response: &crate::owned_decode::DecodeBudget,
    expected: Option<TreeRef>,
    work: &mut Work<'_>,
) -> Result<Option<Vec<u8>>, RamStoreError> {
    if let Some(first) = work.account.read_failure() {
        return Err(first.into());
    }
    if let Err(error) = work.original().verify_live() {
        let error = RamStoreError::from_admission(work.original(), error);
        return Err(work.account.fail_read(error).into());
    }
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work,
        task: ReadTask::Canonical {
            id,
            response,
            expected,
        },
        state: &mut state,
        physical: None,
    };
    let provider = backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::Canonical(value) => Ok(value),
        _ => unreachable!("a canonical request retains its own optional bytes"),
    }
}

#[cfg(test)]
pub(crate) fn read_tree_for_test(
    backend: &dyn ImmutableBlobBackend,
    original: &crate::owned_decode::DecodeBudget,
    id: crate::content_store::ContentId,
    digest: crucible_ram::NodeDigest,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<(), RamStoreError> {
    let mut work = Work::new(super::RamStoreLimits::default(), original, boundary)?;
    read_tree(
        backend,
        TreeRef {
            id,
            digest,
            height: 0,
            pages: 1,
        },
        &mut work,
    )
    .map(|_| ())
}

#[cfg(test)]
pub(crate) fn with_failed_work_for_test(
    original: &crate::owned_decode::DecodeBudget,
    operation: impl FnOnce(&mut dyn FnMut(RamStoreError) -> StoreError) -> Result<(), StoreError>,
) -> StoreError {
    with_failure_work_for_test(original, |work| {
        operation(&mut |first| work.account.fail_read(first))
    })
}

#[cfg(test)]
pub(crate) fn with_pending_validation_for_test(
    original: &crate::owned_decode::DecodeBudget,
    operation: impl FnOnce(
        &mut dyn FnMut(RamStoreError, StoreError) -> StoreError,
    ) -> Result<(), StoreError>,
) -> StoreError {
    with_failure_work_for_test(original, |work| {
        operation(&mut |first, provider| {
            work.account.fail_validation_with_provider(first, provider)
        })
    })
}

#[cfg(test)]
fn with_failure_work_for_test(
    original: &crate::owned_decode::DecodeBudget,
    operation: impl FnOnce(&mut Work<'_>) -> Result<(), StoreError>,
) -> StoreError {
    let mut boundary = || panic!("the concrete provider controls its own actual SQL polls");
    let mut work = Work::new(super::RamStoreLimits::default(), original, &mut boundary)
        .expect("both existing failure slots precede actual provider effects");
    let result = operation(&mut work);
    match result {
        Err(returned) => work.account.reconcile_failed_read(returned),
        Ok(()) => work
            .account
            .read_failure()
            .expect("the actual provider produced a first refusal"),
    }
}
