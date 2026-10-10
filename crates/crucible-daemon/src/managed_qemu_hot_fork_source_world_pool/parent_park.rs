//! Pool-issued exclusion for the real managed parent park transaction.
//!
//! The pool retains its complete world and exact outstanding lease record.
//! Only a checkout with no other child loan can enter this phase. The global
//! pool lock is released before original-bound source or QMP work begins.
//! The one-shot family assignment is not renewed for another checkout; a
//! repeated acquisition remains refused until a genuine retained-stage
//! reborrow and current-generation consumer are implemented.

use std::alloc::Layout;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{OnceLock, TryLockError};

use crucible_api::ProductionVmParentParkDrainRefusal as Refusal;
use crucible_linux_resource::host_supervision::HostSupervisionError;
use crucible_qemu::{QmpParentParkDrainReceipt, QmpParentParkDrainState};
use crucible_ram::ResourceLoan;

use super::*;
use crate::private_original_capture::OriginalPackagedParkCaller;

const ACQUIRING: u8 = 0;
const HELD: u8 = 1;
const RELINQUISHED: u8 = 2;
const TERMINAL: u8 = 3;

struct ManagedParentParkState {
    source: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    caller: OriginalPackagedParkCaller,
    node: crucible::NodeId,
    provider: u64,
    lease: u64,
    template: HotCheckpointPoolKey,
    state: AtomicU8,
    first: OnceLock<Refusal>,
    original_after: OnceLock<HostSupervisionError>,
}

/// Retains the same precreated phase body before its external original credit.
#[derive(Clone)]
pub(crate) struct ManagedParentParkGate {
    body: Arc<ManagedParentParkState>,
    _credit: ResourceLoan,
}

/// Carries a typed refusal and, after publication, its real pool-held custody.
pub(crate) enum ManagedParentParkError {
    Early(Refusal),
    Retained(ManagedParentParkGate),
}

impl std::fmt::Debug for ManagedParentParkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Early(first) => formatter.debug_tuple("Early").field(first).finish(),
            Self::Retained(gate) => formatter
                .debug_struct("Retained")
                .field("first", &gate.body.first.get())
                .field("original_after", &gate.body.original_after.get())
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Display for ManagedParentParkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Early(first) => first.fmt(formatter),
            Self::Retained(_) => formatter.write_str("managed parent park remains retained"),
        }
    }
}

impl std::error::Error for ManagedParentParkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Early(first) => Some(first),
            Self::Retained(gate) => match gate.body.first.get() {
                Some(first) => Some(first),
                None => None,
            },
        }
    }
}

impl From<Refusal> for ManagedParentParkError {
    fn from(first: Refusal) -> Self {
        Self::Early(first)
    }
}

/// One move-only session minted from the actual outstanding pool lease.
struct ManagedParentParkSession {
    gate: ManagedParentParkGate,
}

impl ManagedParentParkGate {
    #[cfg(test)]
    pub(super) fn first_cause_retained(&self) -> bool {
        self.body.first.get().is_some() && self.body.state.load(Ordering::Acquire) == TERMINAL
    }

    fn prepare(
        provider: u64,
        lease: &QemuHotForkSourceWorldLease,
        caller: &OriginalPackagedParkCaller,
    ) -> Result<Self, Refusal> {
        let sequence = lease
            .managed_lease
            .ok_or(Refusal::Unavailable("managed lease absent"))?;
        if sequence == 0 || sequence == u64::MAX {
            return Err(Refusal::Unavailable("managed park identity exhausted"));
        }
        let node = lease.identity.single_node().ok_or(Refusal::Unavailable(
            "managed park requires one declared parent process",
        ))?;
        caller.verify_original()?;

        // Cover the shared body, control, name, construction overlap and the
        // pool/session/refusal aliases before any phase record is published.
        let (layout, _) = Layout::new::<(usize, usize)>()
            .extend(Layout::new::<ManagedParentParkState>())
            .map_err(|_| Refusal::Unavailable("managed park layout overflow"))?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<ManagedParentParkState>())
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(node.name.len()))
            .and_then(|bytes| {
                bytes.checked_add(ResourceLoan::allocation_bytes::<
                    crucible::owned_decode::DecodeScratch,
                >() as usize)
            })
            .ok_or(Refusal::Unavailable("managed park extent overflow"))?;
        let credit = caller.reserve_session_storage(bytes)?;
        let gate = Self {
            body: Arc::new(ManagedParentParkState {
                source: Arc::clone(&lease.source),
                caller: caller.clone(),
                node: node.clone(),
                provider,
                lease: sequence,
                template: lease.template,
                state: AtomicU8::new(ACQUIRING),
                first: OnceLock::new(),
                original_after: OnceLock::new(),
            }),
            _credit: ResourceLoan::new(credit),
        };
        gate.body.caller.verify_original()?;
        Ok(gate)
    }

    fn refuse(&self, first: Refusal) -> ManagedParentParkError {
        let _ = self.body.first.set(first);
        if let Some(post) = self.body.caller.original_after() {
            let _ = self.body.original_after.set(post);
        }
        self.body.state.store(TERMINAL, Ordering::Release);
        ManagedParentParkError::Retained(self.clone())
    }

    fn step(
        &self,
        invoke: impl FnOnce(
            &mut ProductionVmHotForkSourceWorld,
        ) -> Result<QmpParentParkDrainReceipt, Refusal>,
    ) -> Result<QmpParentParkDrainReceipt, ManagedParentParkError> {
        if let Err(first) = self.body.caller.verify_original() {
            return Err(self.refuse(first.into()));
        }
        let mut source = match self.body.source.try_lock() {
            Ok(source) => source,
            Err(TryLockError::WouldBlock) => {
                return Err(self.refuse(Refusal::Unavailable("managed source busy")));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.refuse(Refusal::Unavailable("managed source poisoned")));
            }
        };
        let result = invoke(&mut source);
        // The initiating command outcome remains first even on a late original
        // refusal. The same caller's raw post is independently retained.
        let post = self.body.caller.verify_original();
        if let Some(raw) = self.body.caller.original_after() {
            let _ = self.body.original_after.set(raw);
        }
        match (result, post) {
            (Err(first), _) => Err(self.refuse(first)),
            (Ok(_), Err(first)) => Err(self.refuse(first.into())),
            (Ok(receipt), Ok(())) => Ok(receipt),
        }
    }
}

impl ManagedParentParkSession {
    fn run(&mut self) -> Result<(), ManagedParentParkError> {
        let body = &self.gate.body;
        let acquired = self.gate.step(|source| {
            body.caller
                .acquire_retained_world(source, &body.node, body.lease)
        })?;
        if acquired.state != QmpParentParkDrainState::Held || !acquired.retained {
            return Err(self
                .gate
                .refuse(Refusal::Unavailable("native acquire did not retain parent")));
        }
        body.state.store(HELD, Ordering::Release);
        let queried = self
            .gate
            .step(|source| source.query_parent_park_retained(&body.node))?;
        if queried.state != QmpParentParkDrainState::Held
            || !queried.retained
            || queried.generation != acquired.generation
        {
            return Err(self
                .gate
                .refuse(Refusal::Unavailable("native held owner changed")));
        }
        let released = self
            .gate
            .step(|source| source.relinquish_parent_park_retained(&body.node))?;
        if released.state != QmpParentParkDrainState::Relinquished
            || released.retained
            || released.generation != acquired.generation
        {
            return Err(self
                .gate
                .refuse(Refusal::Unavailable("native disposition remains uncertain")));
        }
        body.state.store(RELINQUISHED, Ordering::Release);
        Ok(())
    }
}

impl Drop for ManagedParentParkSession {
    fn drop(&mut self) {
        if self.gate.body.state.load(Ordering::Acquire) != RELINQUISHED {
            self.gate.body.state.store(TERMINAL, Ordering::Release);
            if let Ok(mut source) = self.gate.body.source.try_lock() {
                let _ = source.contain_parent_park_retained();
            }
            // The pool's actual gate keeps the complete world and credit. A
            // facade Drop neither removes its lease nor proves physical reap.
        }
    }
}

impl<D, R> SharedQemuHotForkSourceWorldProvider<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Performs the fixed invocation before the caller exposes any child loan.
    ///
    /// # Errors
    /// Refuses another outstanding checkout, changed pool record, either real
    /// original, or native uncertainty. Published failures stay pool-owned.
    pub(crate) fn park_parent_before_fork(
        &mut self,
        lease: &QemuHotForkSourceWorldLease,
        caller: &OriginalPackagedParkCaller,
    ) -> Result<(), ManagedParentParkError> {
        let mut pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(TryLockError::WouldBlock) => {
                return Err(Refusal::Unavailable("managed pool busy").into());
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(Refusal::Unavailable("managed pool poisoned").into());
            }
        };
        let gate = pool.begin_parent_park(self.provider, lease, caller)?;
        drop(pool);

        let mut session = ManagedParentParkSession { gate };
        session.run()?;
        let mut pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(TryLockError::WouldBlock) => {
                return Err(session
                    .gate
                    .refuse(Refusal::Unavailable("managed pool busy after disposition")));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(session.gate.refuse(Refusal::Unavailable(
                    "managed pool poisoned after disposition",
                )));
            }
        };
        pool.finish_parent_park(self.provider, lease, &session.gate)
    }
}

impl<D, R> ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    pub(super) fn authenticate_parent_park_lease(
        &self,
        provider: u64,
        lease: &QemuHotForkSourceWorldLease,
    ) -> Result<(), ManagedParentParkError> {
        let Some(record) = self.leased_out.get(&provider) else {
            return Err(Refusal::Unavailable("actual managed lease record absent").into());
        };
        if Some(record.lease) != lease.managed_lease
            || record.template != lease.template
            || record.identity != lease.identity
            || !record
                .source
                .upgrade()
                .is_some_and(|source| Arc::ptr_eq(&source, &lease.source))
        {
            return Err(Refusal::Unavailable("actual managed lease identity changed").into());
        }
        if self
            .leased_out
            .iter()
            .any(|(other, record)| *other != provider && record.template == lease.template)
            || self
                .checked_out
                .values()
                .any(|(template, _, _)| *template == lease.template)
        {
            return Err(Refusal::Unavailable("parent still has another child loan").into());
        }
        let Some(world) = self.worlds.get(&lease.template) else {
            return Err(Refusal::Unavailable("managed parent world absent").into());
        };
        if world.invalidated
            || world.parent_park.is_some()
            || !world
                .leased_source
                .as_ref()
                .is_some_and(|source| Arc::ptr_eq(source, &lease.source))
        {
            return Err(Refusal::Unavailable("managed parent exclusion unavailable").into());
        }
        Ok(())
    }

    fn begin_parent_park(
        &mut self,
        provider: u64,
        lease: &QemuHotForkSourceWorldLease,
        caller: &OriginalPackagedParkCaller,
    ) -> Result<ManagedParentParkGate, ManagedParentParkError> {
        self.authenticate_parent_park_lease(provider, lease)?;
        let world = self.worlds.get_mut(&lease.template).ok_or_else(|| {
            ManagedParentParkError::Early(Refusal::Unavailable("managed parent world disappeared"))
        })?;
        let gate = ManagedParentParkGate::prepare(provider, lease, caller)?;
        // Publication is terminal before releasing the global lock. No second
        // checkout can pass begin_lease while original-bound QMP waits run.
        world.parent_park = Some(gate.clone());
        Ok(gate)
    }

    fn finish_parent_park(
        &mut self,
        provider: u64,
        lease: &QemuHotForkSourceWorldLease,
        gate: &ManagedParentParkGate,
    ) -> Result<(), ManagedParentParkError> {
        if gate.body.state.load(Ordering::Acquire) != RELINQUISHED
            || gate.body.provider != provider
            || Some(gate.body.lease) != lease.managed_lease
            || gate.body.template != lease.template
        {
            return Err(gate.refuse(Refusal::Unavailable("managed disposition identity changed")));
        }
        let Some(record) = self.leased_out.get(&provider) else {
            return Err(gate.refuse(Refusal::Unavailable("managed disposition record absent")));
        };
        if Some(record.lease) != lease.managed_lease
            || record.template != lease.template
            || record.identity != lease.identity
            || !record
                .source
                .upgrade()
                .is_some_and(|source| Arc::ptr_eq(&source, &lease.source))
        {
            return Err(gate.refuse(Refusal::Unavailable("managed disposition record changed")));
        }
        let Some(world) = self.worlds.get_mut(&lease.template) else {
            return Err(gate.refuse(Refusal::Unavailable("managed disposition world absent")));
        };
        if !world
            .parent_park
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(&held.body, &gate.body))
        {
            return Err(gate.refuse(Refusal::Unavailable("managed disposition owner changed")));
        }
        gate.body
            .caller
            .verify_original()
            .map_err(|first| gate.refuse(first.into()))?;
        let source = gate.body.source.try_lock().map_err(|_| {
            gate.refuse(Refusal::Unavailable(
                "managed disposition source unavailable",
            ))
        })?;
        if !lease.identity.matches(&source) || source.parent_park_drain_is_owned() {
            return Err(gate.refuse(Refusal::Unavailable(
                "native parent disposition not complete",
            )));
        }
        drop(source);
        // Keep the exact record and child reservation. Ordinary fork/rearm may
        // proceed after the explicit native disposition and both actual cuts.
        world.parent_park = None;
        Ok(())
    }
}
