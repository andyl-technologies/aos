//! Retains the distinct required native RUN and teardown controls.
//!
//! Their actual whole Arc bodies have separate role claims before birth. RUN
//! receives the sole lifecycle stream only after setup enters RUN. Teardown
//! retains the existing sole consumer and mapped handle before native creation.
//! Readiness and local sequencing never confer Source operation authority.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::startup_source::runtime_purpose::{
    RuntimeInterrupt, RuntimeInterruptReceipt, RuntimePurpose,
};
use std::any::Any;
use std::ffi::c_void;
use std::sync::MutexGuard;

pub(crate) mod abi;
mod health;

use health::{History, State, TerminalReport};
#[cfg(not(test))]
mod control;
#[cfg(not(test))]
mod module;
#[cfg(not(test))]
mod owner;

#[cfg(not(test))]
pub(in crate::runtime) use owner::RequiredWorkers;

/// Identifies the actual role selected by its separate Native constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Run,
    Teardown,
}

impl Kind {
    fn mask(self) -> u64 {
        match self {
            Self::Run => WORKER_RUN_CONTROL,
            Self::Teardown => WORKER_TEARDOWN,
        }
    }
}

#[derive(Clone, Copy)]
struct Handle {
    id: u64,
    worker: usize,
    api: abi::Api,
    kind: Kind,
}

/// Keeps actual typed failures alongside independent Native effect journals.
#[derive(Debug)]
enum Cause {
    Registration(crate::ram_error::RamError),
    Read(crate::PluginTeardownError),
    Teardown(crate::PluginTeardownError),
    Native { cut: NativeCut, status: i32 },
    Ownership(&'static str),
    Interruption(crate::StartupSourceError),
    Panic,
}

#[derive(Clone, Copy, Debug)]
enum NativeCut {
    Ready,
    ScopeReturn,
    HandoffCommitted,
    Close,
}

#[derive(Clone, Copy, Debug)]
enum FailureKind {
    Registration,
    Read,
    Teardown,
    Native,
    Ownership,
    Interruption,
    Panic,
}

struct RunControl {
    stream: Mutex<Option<ControlLifecycleStream<SetupControlSocket>>>,
}

struct TeardownControl {
    consumer: teardown_latch::TeardownConsumer,
    handle: LiveControlTeardownHandle,
    request_shutdown: QemuRequestShutdownFn,
    selected: Mutex<Option<LiveRuntimeTeardownTrigger>>,
    completed: AtomicBool,
}

enum Body {
    Run(RunControl),
    Teardown(TeardownControl),
}

/// Owns one genuine role allocation; the two controls never share an Arc owner.
struct Control {
    native: Handle,
    workers: Arc<LiveWorkerQuiescence>,
    router: Arc<LiveRuntimeTeardownRouter>,
    interrupt: RuntimeInterrupt,
    owner_process: u32,
    closing: AtomicBool,
    state: Mutex<State>,
    body: Body,
}

impl Control {
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn refuse(&self, cause: Cause) {
        self.lock().refuse(cause);
    }
}

/// Retains the real control while its typed history is reported outside a loan.
#[derive(Clone)]
pub struct Failure {
    control: Arc<Control>,
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.control.lock();
        formatter
            .debug_struct("RequiredWorkerFailure")
            .field("role", &self.control.native.kind)
            .field("first", &state.first)
            .field("registration", &state.registration)
            .field("read", &state.read)
            .field("teardown", &state.teardown)
            .field("ownership", &state.ownership)
            .field("native", &state.native)
            .field("interruption_error", &state.interruption_error)
            .field("interruption", &state.interruption)
            .field("entry_panicked", &state.entry_panic.is_some())
            .field("control_panicked", &state.control_panic.is_some())
            .field("close_panicked", &state.close_panic.is_some())
            .field("handoff_panicked", &state.handoff_panic.is_some())
            .finish()
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "required worker failed: {self:?}")
    }
}

impl std::error::Error for Failure {}

/// Keeps a native status distinct from an actual owning module failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The same installing Source refused before an effect or at its raw post.
    #[error("required worker original refused: {source}")]
    Original {
        /// Actual retained Source refusal.
        source: crate::StartupSourceError,
    },
    /// A literal Native or physical-disposition cut refused.
    #[error("required native worker {operation} refused with status {status}")]
    Native {
        /// Exact attempted cut.
        operation: &'static str,
        /// Independent signed result.
        status: i32,
    },
    /// The actual module failed; its separate owning payload may be released.
    ///
    /// This permanent negative receipt retains no Arc after physical destruction
    /// and cannot be interpreted as a Native signed status or return permission.
    #[error("required worker retains an observed module failure")]
    ModuleHealth,
    /// An owning control retains its actual typed failure and panic history.
    #[error("{source}")]
    Module {
        /// Actual ordinary Arc retaining the failed control.
        source: Failure,
    },
    /// A module failure and independent native scope return both remain owned.
    #[error("{source}; native control return {status}")]
    Scope {
        /// Actual module failure.
        source: Failure,
        /// Independent scope return.
        status: i32,
    },
}

/// Reports bounded factual history without lending a Native owner or authority.
#[derive(Clone, Copy, Default)]
pub struct Receipt {
    ready_status: Option<i32>,
    module_failed: bool,
    creation: Option<i32>,
    transfer: Option<i32>,
    handoff: Option<i32>,
    handoff_moved: bool,
    handoff_commit: Option<i32>,
    close: Option<i32>,
    join: Option<i32>,
    observation: Option<i32>,
    identity_return: Option<i32>,
    native: Option<abi::Status>,
    installation_post: Option<crate::StartupSourceError>,
    handoff_post: Option<crate::StartupSourceError>,
    constructor_panicked: bool,
}

impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequiredWorkerReceipt")
            .field("ready_status", &self.ready_status)
            .field("module_failed", &self.module_failed)
            .field("creation", &self.creation)
            .field("transfer", &self.transfer)
            .field("handoff", &self.handoff)
            .field("handoff_moved", &self.handoff_moved)
            .field("handoff_commit", &self.handoff_commit)
            .field("close", &self.close)
            .field("join", &self.join)
            .field("observation", &self.observation)
            .field("identity_return", &self.identity_return)
            .field("native", &self.native)
            .field("installation_post", &self.installation_post)
            .field("handoff_post", &self.handoff_post)
            .field("constructor_panicked", &self.constructor_panicked)
            .finish()
    }
}

/// Preserves both required-role cleanup failures without allocating an error box.
#[derive(Debug, thiserror::Error)]
#[error(
    "{first}; independent={independent:?}; unused-role return={unborn_status:?}; roles={receipts:?}; readiness={readiness:?}"
)]
pub struct CleanupError {
    /// Primary actual role failure.
    #[source]
    pub first: Error,
    /// Independently attempted sibling's owning or signed failure.
    pub independent: Option<Error>,
    /// Raw excluded-creator rollback result, separate from either worker.
    pub unborn_status: Option<i32>,
    /// Independently saved installer and native role histories.
    pub receipts: [Receipt; 2],
    /// Last readiness query and its same-Original post.
    pub readiness: (Option<i32>, Option<crate::StartupSourceError>),
}

impl From<Error> for CleanupError {
    fn from(first: Error) -> Self {
        Self {
            first,
            independent: None,
            unborn_status: None,
            receipts: [Receipt::default(); 2],
            readiness: (None, None),
        }
    }
}

fn native_status(operation: &'static str, status: i32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Native { operation, status })
    }
}

fn failed(control: &Arc<Control>) -> Error {
    Error::Module {
        source: Failure {
            control: Arc::clone(control),
        },
    }
}

/// Derives both real role allocation layouts before the roster is reserved.
///
/// # Errors
/// Refuses overflow in the actual shared-header/body geometry before birth.
pub(super) fn control_layout() -> Result<std::alloc::Layout, crate::StartupSourceError> {
    prebirth::shared_layout::<Control>()
}
