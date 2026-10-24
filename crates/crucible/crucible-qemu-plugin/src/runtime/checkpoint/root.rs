//! Borrows the same native root journal under the actual Rust admission guard.
//!
//! A root is issued only by the active registered callback. Scoped observers
//! retain its native slot on their actual calling thread; physical journal facts
//! remain observable after an initiating original failure. Ending an observer
//! retires that observation alone. No journal scalar constructs a root owner.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_void;

use crate::ram_error::RamError;

#[repr(C)]
struct ProofHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct ProducerLoan {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
struct Disposition {
    schema_version: u32,
    struct_size: u32,
    state: u32,
    first_status: i32,
    post_status: i32,
    root_acknowledged: u32,
    native_transaction_generation: u64,
}

#[repr(C)]
#[derive(Default)]
struct CallbackReturnStatus {
    schema_version: u32,
    struct_size: u32,
    returned: u32,
    mailbox_restored: u32,
    first_status: i32,
    post_status: i32,
    native_transaction_generation: u64,
}

#[repr(C)]
#[derive(Default)]
struct PlacementDisposition {
    schema_version: u32,
    struct_size: u32,
    disposition: u32,
    held_kind: u32,
    native_transaction_generation: u64,
    accepted_placement_generation: u64,
}

type PlacementCallback = extern "C" fn(*mut c_void) -> i32;
type Detach = extern "C" fn(
    u64,
    *mut ProofHandle,
    Option<PlacementCallback>,
    *mut c_void,
    *mut PlacementDisposition,
) -> i32;
type Restore = extern "C" fn(u64, *mut ProofHandle, *mut PlacementDisposition) -> i32;
type ProofCheck = extern "C" fn(u64, *mut ProofHandle) -> i32;

/// Retains a mailbox observation issued only by the same active native root.
///
/// The accepted generation names native mailbox ownership and is deliberately
/// separate from the queued operation's policy generation.
pub(crate) struct NativeMailbox {
    transaction: u64,
    accepted_generation: u64,
    queued: bool,
}

impl NativeMailbox {
    pub(crate) fn transaction(&self) -> u64 {
        self.transaction
    }
}

type Hold = extern "C" fn(u64, *mut *mut ProofHandle) -> i32;
type Return = extern "C" fn(u64, *mut ProofHandle) -> i32;
type ReturnObserve = extern "C" fn(u64, *mut ProofHandle, *mut CallbackReturnStatus) -> i32;
type Borrow = extern "C" fn(u64, *mut ProofHandle, *mut c_void, *mut *mut ProducerLoan) -> i32;
type Observe = extern "C" fn(u64, *mut ProducerLoan, *mut Disposition) -> i32;
type Retire = extern "C" fn(u64, *mut ProofHandle, *mut ProducerLoan) -> i32;
type Acknowledge = extern "C" fn(u64, *mut ProducerLoan) -> i32;
type End = extern "C" fn(u64, *mut ProducerLoan) -> i32;

#[derive(Clone, Copy)]
pub(super) struct RootApi {
    hold: Hold,
    check: ProofCheck,
    detach: Detach,
    restore: Restore,
    return_root: Return,
    return_observe: ReturnObserve,
    borrow: Borrow,
    observe: Observe,
    retire: Retire,
    acknowledge: Acknowledge,
    end: End,
}

/// Names physical journal facts obtained from a live native observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootStage {
    Held,
    LocalDisposition,
    RootReturned,
    Retired,
}

/// Borrows authenticated LOCAL_DISPOSITION only during its live observer.
///
/// No caller can construct this loan from a copied stage or generation.
pub(crate) struct LocalDisposition<'a> {
    root: &'a NativeRoot,
}

impl LocalDisposition<'_> {
    pub(crate) fn transaction(&self) -> u64 {
        self.root.transaction
    }
}

/// Retains the authentic native root in the same controller State allocation.
///
/// Addresses stay opaque to Rust and are never dereferenced. Native authenticates
/// process/module/userdata on every use. The State lock orders every observation
/// and keeps this owner until acknowledgment plus successful observer end.
pub(crate) struct NativeRoot {
    api: RootApi,
    plugin_id: u64,
    address: usize,
    userdata: usize,
    transaction: u64,
    observation_uncertain: bool,
    acknowledged: bool,
    first_status: std::cell::Cell<i32>,
    post_status: std::cell::Cell<i32>,
}

impl RootApi {
    /// Resolves the complete matched process-private root SDK before registration.
    ///
    /// # Errors
    /// Refuses any missing symbol before publishing the callback allocation.
    pub(super) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $signature:ty) => {{
                // SAFETY: these fixed symbol names name the frozen GPL-private
                // SDK; resolution never attests a later original or callback.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(-libc::ENOSYS);
                }
                // SAFETY: the non-null symbol has exactly this C declaration.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            hold: resolve!(c"qemu_plugin_crucible_checkpoint_proof_hold_v1", Hold),
            check: resolve!(
                c"qemu_plugin_crucible_checkpoint_proof_check_v1",
                ProofCheck
            ),
            detach: resolve!(
                c"qemu_plugin_crucible_checkpoint_placement_detach_v2",
                Detach
            ),
            restore: resolve!(
                c"qemu_plugin_crucible_checkpoint_placement_restore_v2",
                Restore
            ),
            return_root: resolve!(c"qemu_plugin_crucible_checkpoint_proof_return_v1", Return),
            return_observe: resolve!(
                c"qemu_plugin_crucible_checkpoint_proof_return_observe_v1",
                ReturnObserve
            ),
            borrow: resolve!(
                c"qemu_plugin_crucible_checkpoint_producer_borrow_v1",
                Borrow
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_checkpoint_producer_observe_v1",
                Observe
            ),
            retire: resolve!(c"qemu_plugin_crucible_checkpoint_proof_retire_v1", Retire),
            acknowledge: resolve!(
                c"qemu_plugin_crucible_checkpoint_proof_acknowledge_v1",
                Acknowledge
            ),
            end: resolve!(c"qemu_plugin_crucible_checkpoint_producer_end_v1", End),
        })
    }

    /// Retains a root issued by the genuine active registered invocation.
    ///
    /// # Errors
    /// Preserves actual native refusal or an invalid empty successful output.
    pub(super) fn acquire(
        self,
        plugin_id: u64,
        userdata: *mut c_void,
        transaction: u64,
    ) -> Result<NativeRoot, RamError> {
        let mut address = std::ptr::null_mut();
        status(
            "checkpoint proof hold",
            (self.hold)(plugin_id, &mut address),
        )?;
        if address.is_null() {
            return Err(RamError::Invariant("native checkpoint root absent"));
        }
        Ok(NativeRoot {
            api: self,
            plugin_id,
            address: address as usize,
            userdata: userdata as usize,
            transaction,
            observation_uncertain: false,
            acknowledged: false,
            first_status: std::cell::Cell::new(0),
            post_status: std::cell::Cell::new(0),
        })
    }
}

impl NativeRoot {
    pub(crate) fn transaction(&self) -> u64 {
        self.transaction
    }

    /// Reports the cached final acknowledgment without touching its retired pointer.
    pub(crate) fn is_acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// Checks the exact held proof inside its active native callback.
    ///
    /// # Errors
    /// Preserves native identity, original or whole physical fence refusal.
    pub(crate) fn check_active(&self) -> Result<(), RamError> {
        self.require_retained()?;
        status(
            "checkpoint proof check",
            (self.api.check)(self.plugin_id, self.address as *mut ProofHandle),
        )
    }

    /// Detaches the exact callback tuple while its actual queue guard is held.
    ///
    /// # Errors
    /// Refuses another native tuple, an active borrower or malformed disposition.
    /// A queued accepted native generation is never a policy generation.
    pub(crate) fn detach(
        &self,
        callback: Option<PlacementCallback>,
        opaque: *mut c_void,
    ) -> Result<NativeMailbox, RamError> {
        self.require_retained()?;
        let mut observed = PlacementDisposition::default();
        status(
            "checkpoint mailbox detach",
            (self.api.detach)(
                self.plugin_id,
                self.address as *mut ProofHandle,
                callback,
                opaque,
                &mut observed,
            ),
        )?;
        self.check_placement(&observed, 1, callback.is_some())?;
        Ok(NativeMailbox {
            transaction: self.transaction,
            accepted_generation: observed.accepted_placement_generation,
            queued: callback.is_some(),
        })
    }

    /// Restores the same native journal, including its genuine empty mailbox.
    ///
    /// # Errors
    /// Preserves actual restore/post refusal or changed retained identity. The
    /// caller retains an attempted marker before this possibly journaled effect.
    pub(crate) fn restore(&self, mailbox: &NativeMailbox) -> Result<(), RamError> {
        self.require_retained()?;
        if mailbox.transaction != self.transaction {
            return Err(RamError::Invariant("checkpoint mailbox root changed"));
        }
        let mut observed = PlacementDisposition::default();
        status(
            "checkpoint mailbox restore",
            (self.api.restore)(
                self.plugin_id,
                self.address as *mut ProofHandle,
                &mut observed,
            ),
        )?;
        self.check_placement(&observed, 2, mailbox.queued)?;
        if observed.accepted_placement_generation != mailbox.accepted_generation {
            return Err(RamError::Invariant(
                "checkpoint accepted mailbox generation changed",
            ));
        }
        Ok(())
    }

    fn check_placement(
        &self,
        observed: &PlacementDisposition,
        disposition: u32,
        queued: bool,
    ) -> Result<(), RamError> {
        if observed.schema_version != 1
            || observed.struct_size as usize != std::mem::size_of::<PlacementDisposition>()
            || observed.native_transaction_generation != self.transaction
            || observed.disposition != disposition
            || observed.held_kind != if queued { 2 } else { 1 }
            || (!queued && observed.accepted_placement_generation != 0)
        {
            return Err(RamError::Invariant(
                "checkpoint native mailbox disposition changed",
            ));
        }
        Ok(())
    }

    /// Returns only the callback-local proof loan inside an authentic RELEASE.
    ///
    /// # Errors
    /// Preserves the native initiating refusal even when the same root's journal
    /// proves physical return. Neither return nor observation opens admission.
    pub(crate) fn return_from_callback(&self) -> Result<(), RamError> {
        let before = self.read_callback_return()?;
        if before.returned == 1 {
            return Ok(());
        }
        if before.mailbox_restored != 1 {
            return Err(RamError::Invariant("checkpoint mailbox remains detached"));
        }

        let initiating = (self.api.return_root)(self.plugin_id, self.address as *mut ProofHandle);
        let observed = self.read_callback_return();
        // A negative return can follow a successful journal transition. Always
        // observe the same root, retaining the initiating cause on observation
        // refusal; a later call must not repeat an authenticated physical return.
        status("checkpoint callback proof return", initiating)?;
        if observed?.returned != 1 {
            return Err(RamError::Invariant(
                "checkpoint callback return still retained",
            ));
        }
        Ok(())
    }

    fn read_callback_return(&self) -> Result<CallbackReturnStatus, RamError> {
        self.require_retained()?;
        let mut observed = CallbackReturnStatus::default();
        status(
            "checkpoint callback return journal",
            (self.api.return_observe)(
                self.plugin_id,
                self.address as *mut ProofHandle,
                &mut observed,
            ),
        )?;
        if observed.schema_version != 1
            || observed.struct_size as usize != std::mem::size_of::<CallbackReturnStatus>()
            || observed.native_transaction_generation != self.transaction
            || observed.returned > 1
            || observed.mailbox_restored > 1
            || (observed.returned == 1 && observed.mailbox_restored != 1)
        {
            return Err(RamError::Invariant(
                "checkpoint callback return identity changed",
            ));
        }
        if self.first_status.get() == 0 && observed.first_status != 0 {
            self.first_status.set(observed.first_status);
        }
        self.post_status.set(observed.post_status);
        Ok(observed)
    }

    /// Observes physical disposition on this thread while State remains locked.
    ///
    /// # Errors
    /// Refuses identity/contention or a malformed journal. Failure to end the
    /// observer taints this owner and retains the native slot; no retry can erase it.
    pub(crate) fn observe(&mut self) -> Result<RootStage, RamError> {
        self.with_observation(|root, loan| root.read_stage(loan))
    }

    /// Returns the root after the caller disposes real local loans under State.
    ///
    /// # Errors
    /// Refuses any stage except LOCAL_DISPOSITION or a retained observer. A
    /// negative retire may have advanced the journal; that same observer reads
    /// the physical stage while retaining independent first/post facts.
    pub(crate) fn retire_local(
        &mut self,
        dispose: impl FnOnce(&LocalDisposition<'_>) -> Result<(), RamError>,
    ) -> Result<RootStage, RamError> {
        self.with_observation(|root, loan| {
            let before = root.read_stage(loan)?;
            if before != RootStage::LocalDisposition {
                return Ok(before);
            }
            dispose(&LocalDisposition { root })?;
            let retired = (root.api.retire)(root.plugin_id, root.address as *mut ProofHandle, loan);
            let after = root.read_stage(loan)?;
            if after == RootStage::RootReturned || after == RootStage::Retired {
                return Ok(after);
            }
            status("checkpoint native root return", retired)?;
            Err(RamError::Invariant("checkpoint root return journal absent"))
        })
    }

    /// Acknowledges only genuine full retirement and consumes its last observer.
    ///
    /// # Errors
    /// Refuses earlier stages or native identity/contention. On success the caller
    /// must remove this root under the same State guard without another native read.
    pub(crate) fn acknowledge_retired(&mut self) -> Result<(), RamError> {
        if self.acknowledged {
            return Ok(());
        }
        self.with_observation(|root, loan| {
            if root.read_stage(loan)? != RootStage::Retired {
                return Err(RamError::Invariant(
                    "checkpoint native cleanup still retained",
                ));
            }
            status(
                "checkpoint root acknowledgment",
                (root.api.acknowledge)(root.plugin_id, loan),
            )
        })?;
        self.acknowledged = true;
        Ok(())
    }

    fn read_stage(&self, loan: *mut ProducerLoan) -> Result<RootStage, RamError> {
        let mut observed = Disposition::default();
        status(
            "checkpoint producer journal",
            (self.api.observe)(self.plugin_id, loan, &mut observed),
        )?;
        if observed.schema_version != 1
            || observed.struct_size as usize != std::mem::size_of::<Disposition>()
            || observed.native_transaction_generation != self.transaction
            || observed.root_acknowledged > 1
        {
            return Err(RamError::Invariant(
                "checkpoint root journal identity changed",
            ));
        }
        if self.first_status.get() == 0 && observed.first_status != 0 {
            self.first_status.set(observed.first_status);
        }
        self.post_status.set(observed.post_status);
        // Signed first/post are original facts, not a veto on observing physical
        // cleanup. Admission still requires the authentic RETIRED journal.
        match observed.state {
            1 => Ok(RootStage::Held),
            2 => Ok(RootStage::LocalDisposition),
            3 => Ok(RootStage::RootReturned),
            4 => Ok(RootStage::Retired),
            _ => Err(RamError::Invariant("checkpoint root journal stage invalid")),
        }
    }

    fn require_retained(&self) -> Result<(), RamError> {
        if self.acknowledged {
            return Err(RamError::Invariant("checkpoint root already acknowledged"));
        }
        if self.observation_uncertain {
            return Err(RamError::Invariant("checkpoint observer return uncertain"));
        }
        Ok(())
    }

    fn with_observation<T>(
        &mut self,
        action: impl FnOnce(&Self, *mut ProducerLoan) -> Result<T, RamError>,
    ) -> Result<T, RamError> {
        self.require_retained()?;
        let mut loan = std::ptr::null_mut();
        status(
            "checkpoint producer borrow",
            (self.api.borrow)(
                self.plugin_id,
                self.address as *mut ProofHandle,
                self.userdata as *mut c_void,
                &mut loan,
            ),
        )?;
        if loan.is_null() {
            self.observation_uncertain = true;
            return Err(RamError::Invariant("checkpoint producer loan absent"));
        }
        let work = action(self, loan);
        let ended = (self.api.end)(self.plugin_id, loan);
        if ended != 0 {
            self.observation_uncertain = true;
            if work.is_err() {
                return work;
            }
            return Err(RamError::Native {
                operation: "checkpoint producer return",
                status: ended,
            });
        }
        // end(0) consumes the observer. In particular, after acknowledgment no
        // native pointer may be read before State removes its retained root.
        work
    }
}

fn status(operation: &'static str, value: i32) -> Result<(), RamError> {
    if value == 0 {
        Ok(())
    } else {
        Err(RamError::Native {
            operation,
            status: value,
        })
    }
}

#[cfg(test)]
mod tests;
