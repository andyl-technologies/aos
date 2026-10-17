//! Retains native lazy-restore transactions through mapping commit and containment.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later
//!
//! The binder releases its mutex before calling the mapping owner. Native
//! mainloop dispatch and fault service therefore never depend on this lock.
//! Commit entry is irreversible even when the owner returns an error.

use std::os::fd::BorrowedFd;
use std::os::raw::{c_int, c_void};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};

use crucible_protocol::ram_page::RamPageBinding;

use super::ValidatedRestoreSource;
use crate::ram_error::RamError;

/// Reserves actual mappings and returns an owned rollback or commit receipt.
pub(crate) trait RestoreMappingOwner: Send + Sync {
    /// Prepares real mapping authority before any guest bytes are discarded.
    ///
    /// # Errors
    /// Refuses unavailable resources, unstable mappings or incomplete exclusion.
    fn prepare(
        &self,
        source: ValidatedRestoreSource,
    ) -> Result<Box<dyn PreparedRestoreMapping>, RamError>;
}

/// Retains mapping and source authority until commit or proven rollback.
pub(crate) trait PreparedRestoreMapping: Send {
    /// Enters the destructive mapping transaction and publishes prepared identity.
    ///
    /// # Errors
    /// Returns an error while retaining all authority for process containment.
    fn commit(&mut self) -> Result<(), RamError>;

    /// Undoes staging before destructive commit entry.
    ///
    /// # Errors
    /// Refuses uncertain rollback or any already destructive transaction.
    fn abort_before_commit(&mut self) -> Result<(), RamError>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Preparing,
    Prepared,
    Aborting,
    CommitEntered,
    Failed,
}

struct Transaction {
    phase: Phase,
    receipt: Option<Box<dyn PreparedRestoreMapping>>,
}

struct Runtime {
    owner: Mutex<Arc<dyn RestoreMappingOwner>>,
    transaction: Mutex<Transaction>,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

type Prepare = extern "C" fn(
    *const u8,
    usize,
    *const u8,
    *const u8,
    *const u8,
    *const u8,
    u64,
    c_int,
    c_int,
) -> c_int;
type Transition = extern "C" fn() -> c_int;
type Register = extern "C" fn(Prepare, Transition, Transition) -> c_int;

/// Installs the actual arena owner and matching native callbacks once.
///
/// # Errors
/// Refuses duplicate installation or unavailable/rejected native registration.
pub(crate) fn install(owner: Arc<dyn RestoreMappingOwner>) -> Result<(), RamError> {
    // SAFETY: this symbol is the matching GPL-private callback registration ABI.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_register_ram_restore_v1".as_ptr(),
        )
    };
    if pointer.is_null() {
        return Err(RamError::MissingSymbol(
            b"qemu_plugin_crucible_register_ram_restore_v1\0",
        ));
    }
    // SAFETY: only private callbacks and scalar arguments cross this native ABI.
    let register = unsafe { std::mem::transmute::<*mut c_void, Register>(pointer) };
    RUNTIME
        .set(Runtime {
            owner: Mutex::new(owner),
            transaction: Mutex::new(Transaction {
                phase: Phase::Idle,
                receipt: None,
            }),
        })
        .map_err(|_| RamError::Invariant("restore binder already installed"))?;
    let status = register(prepare, commit, abort);
    if status != 0 {
        return Err(RamError::Native {
            operation: "register restore mapping binder",
            status,
        });
    }
    Ok(())
}

/// Replaces inherited resident authority only after child ownership reconstruction.
///
/// # Errors
/// Refuses a pending restore receipt or competing binder admission.
pub(crate) fn rebind_resident(owner: Arc<dyn RestoreMappingOwner>) -> Result<(), RamError> {
    let runtime = RUNTIME.get().ok_or("restore binder unavailable")?;
    let transaction = runtime
        .transaction
        .try_lock()
        .map_err(|_| RamError::Invariant("restore binder active"))?;
    if transaction.phase != Phase::Idle || transaction.receipt.is_some() {
        return Err(RamError::Invariant(
            "restore binder retains transaction authority",
        ));
    }
    *runtime
        .owner
        .try_lock()
        .map_err(|_| RamError::Invariant("restore owner active"))? = owner;
    Ok(())
}

/// Disposes inherited receipts after proven child fault and descriptor reconstruction.
///
/// # Errors
/// Refuses a competing transition or an unqualified inherited binder phase.
pub(crate) fn rebind_cold_child(
    custody: &crate::paged_ram::engine::ChildPagingCustody,
) -> Result<(), RamError> {
    let runtime = RUNTIME.get().ok_or("restore binder unavailable")?;
    let mut transaction = runtime
        .transaction
        .try_lock()
        .map_err(|_| RamError::Invariant("restore binder active"))?;
    if !matches!(transaction.phase, Phase::Idle | Phase::CommitEntered) {
        return Err(RamError::Invariant(
            "child cannot dispose uncertain inherited restore",
        ));
    }
    let mut owner = runtime
        .owner
        .try_lock()
        .map_err(|_| RamError::Invariant("restore owner active"))?;
    *owner = custody.owner.clone();
    // The engine custody proves old source wrappers were disarmed and the
    // inherited userfaultfd retains native close custody. Drop cannot close a
    // descriptor that the child subsequently reuses.
    let receipt = transaction.receipt.take();
    transaction.phase = Phase::Idle;
    drop(owner);
    drop(transaction);
    drop(receipt);
    Ok(())
}

extern "C" fn prepare(
    record: *const u8,
    length: usize,
    digest: *const u8,
    topology: *const u8,
    session: *const u8,
    owner: *const u8,
    generation: u64,
    source_fd: c_int,
    cancellation_fd: c_int,
) -> c_int {
    callback(|| {
        if record.is_null()
            || length == 0
            || length > crucible_ram::Limits::default().max_record_bytes
            || digest.is_null()
            || topology.is_null()
            || session.is_null()
            || owner.is_null()
            || generation == 0
            || source_fd < 0
            || cancellation_fd < 0
            || source_fd == cancellation_fd
        {
            return Err(RamError::Invariant("native restore arguments invalid"));
        }
        let runtime = RUNTIME.get().ok_or("restore binder unavailable")?;
        {
            let mut transaction = runtime
                .transaction
                .try_lock()
                .map_err(|_| RamError::Invariant("restore binder active"))?;
            if transaction.phase != Phase::Idle || transaction.receipt.is_some() {
                return Err(RamError::Invariant("restore transaction already retained"));
            }
            transaction.phase = Phase::Preparing;
        }
        let result = (|| {
            // SAFETY: native lends immutable buffers of these exact fixed sizes
            // and retains both authenticated descriptors throughout the callback.
            let bytes = unsafe { std::slice::from_raw_parts(record, length) };
            let root_digest = fixed::<32>(digest);
            let topology_digest = fixed::<32>(topology);
            let binding = RamPageBinding {
                session: fixed::<16>(session),
                owner_incarnation: fixed::<16>(owner),
                source_generation: generation,
                root_digest,
            };
            // SAFETY: checked native descriptor roles remain live while duplicated.
            let source = unsafe { BorrowedFd::borrow_raw(source_fd) }.try_clone_to_owned()?;
            // SAFETY: the cancellation role is likewise retained by native admission.
            let cancel = unsafe { BorrowedFd::borrow_raw(cancellation_fd) };
            let cancellation = cancel.try_clone_to_owned()?;
            crate::paged_ram::controller::retain_source_alias(source_fd)?;
            let operations = crate::paged_ram::controller::operation_factory()?;
            let source = ValidatedRestoreSource::bind(
                UnixStream::from(source),
                cancellation,
                binding,
                bytes,
                topology_digest,
                operations,
            )?;
            let owner = runtime
                .owner
                .lock()
                .map_err(|_| RamError::Invariant("restore owner poisoned"))?
                .clone();
            owner.prepare(source)
        })();
        match result {
            Ok(receipt) => retain_receipt(runtime, receipt, Phase::Prepared),
            Err(error) => {
                let mut transaction = runtime
                    .transaction
                    .lock()
                    .map_err(|_| RamError::Invariant("restore binder poisoned"))?;
                transaction.phase = Phase::Idle;
                Err(error)
            }
        }
    })
}

extern "C" fn commit() -> c_int {
    transition(true)
}
extern "C" fn abort() -> c_int {
    transition(false)
}

fn transition(destructive: bool) -> c_int {
    callback(|| {
        let runtime = RUNTIME.get().ok_or("restore binder unavailable")?;
        let mut receipt = {
            let mut transaction = runtime
                .transaction
                .try_lock()
                .map_err(|_| RamError::Invariant("restore binder active"))?;
            if transaction.phase != Phase::Prepared {
                return Err(RamError::Invariant("restore transition phase invalid"));
            }
            transaction.phase = if destructive {
                Phase::CommitEntered
            } else {
                Phase::Aborting
            };
            transaction
                .receipt
                .take()
                .ok_or("restore mapping receipt missing")?
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if destructive {
                receipt.commit()
            } else {
                receipt.abort_before_commit()
            }
        }))
        .unwrap_or(Err(RamError::Invariant("restore owner panicked")));
        if !destructive && result.is_ok() {
            let mut transaction = runtime
                .transaction
                .lock()
                .map_err(|_| RamError::Invariant("restore binder poisoned"))?;
            transaction.phase = Phase::Idle;
            drop(transaction);
            drop(receipt);
            return Ok(());
        }
        let phase = if result.is_ok() {
            Phase::CommitEntered
        } else {
            Phase::Failed
        };
        retain_receipt(runtime, receipt, phase)?;
        result
    })
}

fn retain_receipt(
    runtime: &Runtime,
    receipt: Box<dyn PreparedRestoreMapping>,
    phase: Phase,
) -> Result<(), RamError> {
    match runtime.transaction.lock() {
        Ok(mut transaction) if transaction.receipt.is_none() => {
            transaction.receipt = Some(receipt);
            transaction.phase = phase;
            Ok(())
        }
        _ => {
            // Uncertain handoff cannot release a potentially live fault authority.
            std::mem::forget(receipt);
            Err(RamError::Invariant("restore receipt publication uncertain"))
        }
    }
}

fn fixed<const N: usize>(pointer: *const u8) -> [u8; N] {
    let mut value = [0; N];
    // SAFETY: only callers that validated the native fixed-size buffer call this.
    unsafe {
        std::ptr::copy_nonoverlapping(pointer, value.as_mut_ptr(), N);
    }
    value
}

fn callback(operation: impl FnOnce() -> Result<(), RamError>) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            crate::ram_diagnostics::emit(crate::ram_diagnostics::RamDiagnostic::RestoreFailed(
                &error,
            ));
            -libc::EIO
        }
        Err(_) => -libc::EIO,
    }
}
