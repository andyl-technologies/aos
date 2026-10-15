//! Retains Source-owned command storage and lends its exact typed physical body.
//!
//! Source owns allocation, canonical registration, use serials and sole free.
//! This inline Runtime owner never constructs a Box from that allocation. Its
//! callback-child adapter grants no action, Original, Root or frontier authority.
//! Current provider callback invocation provenance is incomplete: genuine TCG
//! callers fail closed at Native borrow; no arbitrary-thread fallback is used.
// SPDX-License-Identifier: GPL-2.0-only

use super::live_callbacks::LiveFaultCommandControl;
use crate::StartupSourceError;
use crate::fault_command::{FaultCommandBridge, FaultCommandBridgeError};
use crate::startup_source::runtime_purpose::{CommandClaim, RuntimePurpose};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::ptr::NonNull;

mod abi;
mod placement;
pub(super) use abi::Storage as NativeStorage;
use abi::{Api, PhysicalUse, Status, Storage};

/// Lives inside the actual prepaid pinned Runtime before Native retains a field.
///
/// Native exclusively accesses holder contents under its registry lock. Rust
/// lends only the UnsafeCell address and receives distinct local projections.
/// Moving this owner after transfer is prohibited by its pinned containing owner.
pub(super) struct CommandStorage {
    holder: UnsafeCell<*mut Storage>,
    projection: *mut Storage,
    api: Option<Api>,
    id: u64,
    attempted: bool,
    transferred: bool,
}

impl CommandStorage {
    pub(super) const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            projection: std::ptr::null_mut(),
            api: None,
            id: 0,
            attempted: false,
            transferred: false,
        }
    }

    /// Creates and places the actual Bridge once under the installing Source.
    ///
    /// # Errors
    /// Preserves missing SDK, real native or constructor refusal and born storage.
    /// Negative initialization or transfer never invokes another allocator.
    ///
    /// # Safety
    /// This owner already resides inside the pinned paid Runtime; its address
    /// must remain stable through every Native holder/callback/material last use.
    pub(super) unsafe fn create<F>(
        &mut self,
        material: (u64, *mut RuntimePurpose, *mut CommandClaim),
        constructor: F,
    ) -> Result<(), FaultCommandBridgeError>
    where
        F: FnOnce() -> Result<FaultCommandBridge, FaultCommandBridgeError>,
    {
        if self.attempted {
            return Err(physical_error(-libc::EALREADY));
        }
        let api = Api::resolve().map_err(source_error)?;
        self.create_using(material, constructor, api)
    }

    fn create_using<F>(
        &mut self,
        material: (u64, *mut RuntimePurpose, *mut CommandClaim),
        constructor: F,
        api: Api,
    ) -> Result<(), FaultCommandBridgeError>
    where
        F: FnOnce() -> Result<FaultCommandBridge, FaultCommandBridgeError>,
    {
        if self.attempted {
            return Err(physical_error(-libc::EALREADY));
        }
        let (id, runtime, claim) = material;
        self.attempted = true;
        self.id = id;
        self.api = Some(api);
        let status = (api.create)(id, runtime, claim, &mut self.projection);
        // The Source canonical creation field and this durable projection retain
        // all births before signed status. The caller retains the entire Runtime.
        native_status(status)?;
        if self.projection.is_null() {
            return Err(physical_error(-libc::EPROTO));
        }

        let initialized =
            placement::initialize::<FaultCommandBridge, F>(id, self.projection, api, constructor);
        initialized?;
        let storage = self.projection;
        let status = (api.transfer)(id, runtime, &mut self.projection, self.holder.get());
        // Observe copied Native journals from a distinct local output. The
        // transferred flag records a real move even when its signed post fails.
        let mut journal = Status::default();
        let observed = (api.observe)(id, storage, &mut journal);
        if observed == 0
            && journal.schema_version == 1
            && journal.struct_size as usize == size_of::<Status>()
        {
            self.transferred = journal.transferred == 1;
        }
        native_status(status)?;
        native_status(observed)?;
        if !self.transferred {
            return Err(physical_error(-libc::EPROTO));
        }
        Ok(())
    }

    fn projection(&self) -> Result<(Api, *mut Storage), FaultCommandBridgeError> {
        let api = self.api.ok_or_else(|| physical_error(-libc::ENOKEY))?;
        let mut projection = std::ptr::null_mut();
        let field = if self.transferred {
            self.holder.get()
        } else {
            std::ptr::null_mut()
        };
        native_status((api.holder_observe)(self.id, field, &mut projection))?;
        if projection.is_null() {
            return Err(physical_error(-libc::EPROTO));
        }
        Ok((api, projection))
    }

    /// Observes the actual retained Bridge parent without lending its body.
    ///
    /// # Errors
    /// Refuses missing or invalid canonical custody; copied addresses grant none.
    pub(super) fn native_parent(&self) -> Result<*mut NativeStorage, FaultCommandBridgeError> {
        self.projection().map(|(_, storage)| storage)
    }

    pub(super) fn retains_storage(&self) -> bool {
        self.attempted
    }

    /// Returns physical custody only where the real Runtime proves no users.
    ///
    /// A refusal leaves the exact canonical field and Runtime intact. This is
    /// never called merely because a callback finished, ACK arrived or time ended.
    pub(super) fn identity_return(&mut self) -> bool {
        let Some(api) = self.api else {
            return true;
        };
        let holder = if self.transferred {
            self.holder.get()
        } else {
            &mut self.projection
        };
        (api.return_storage)(self.id, holder) == 0
    }
}

/// One move-only borrowed adapter stored in the paid callback child mutex.
///
/// It never frees Native storage and retains failed return debt in its own pair.
/// The pinned Runtime outlives this child and every callback borrowing it.
pub(super) struct Adapter {
    owner: NonNull<CommandStorage>,
    physical_use: Option<RetainedUse>,
}

struct RetainedUse {
    projection: *mut PhysicalUse,
    serial: u64,
}

impl Adapter {
    /// Binds the already-initialized owner without allocating another wrapper.
    ///
    /// # Safety
    /// The real pinned Runtime retains this exact owner through all child uses.
    pub(super) unsafe fn new(owner: &CommandStorage) -> Self {
        Self {
            owner: NonNull::from(owner),
            physical_use: None,
        }
    }

    fn with_bridge<T>(
        &mut self,
        action: impl FnOnce(&mut FaultCommandBridge) -> Result<T, FaultCommandBridgeError>,
    ) -> Result<T, FaultCommandBridgeError> {
        if self.physical_use.is_some() {
            return Err(physical_error(-libc::EBUSY));
        }
        // SAFETY: creation binds the actual pinned Runtime; its failure and
        // registration retention keep this owner live through every child use.
        let owner_pointer = self.owner;
        let owner = unsafe { owner_pointer.as_ref() };
        let (api, storage) = owner.projection()?;
        let mut loan = RetainedUse {
            projection: std::ptr::null_mut(),
            serial: 0,
        };
        let status = (api.borrow)(owner.id, storage, &mut loan.projection, &mut loan.serial);
        // Never reborrow into retained output. PendingUse has no new loan;
        // any born pair is saved before interpreting signed status.
        if !loan.projection.is_null() || loan.serial != 0 {
            self.physical_use = Some(loan);
        }
        if status != 0 {
            let _returned = self.return_use(api, owner.id);
            return Err(if status == 1 {
                FaultCommandBridgeError::PhysicalStoragePending
            } else {
                physical_error(status)
            });
        }
        let result = self.use_body(api, owner.id, action);
        let returned = self.return_use(api, owner.id);
        result.and_then(|value| returned.map(|()| value))
    }

    fn use_body<T>(
        &mut self,
        api: Api,
        id: u64,
        action: impl FnOnce(&mut FaultCommandBridge) -> Result<T, FaultCommandBridgeError>,
    ) -> Result<T, FaultCommandBridgeError> {
        let loan = self
            .physical_use
            .as_ref()
            .ok_or_else(|| physical_error(-libc::EPROTO))?;
        let mut address = std::ptr::null_mut();
        let mut bytes = 0;
        let mut alignment = 0;
        native_status((api.current)(
            id,
            loan.projection,
            loan.serial,
            &mut address,
            &mut bytes,
            &mut alignment,
        ))?;
        let layout = std::alloc::Layout::new::<FaultCommandBridge>();
        if address.is_null()
            || bytes != layout.size()
            || alignment < layout.align()
            || !alignment.is_power_of_two()
            || !(address as usize).is_multiple_of(layout.align())
        {
            return Err(physical_error(-libc::EPROTO));
        }
        // SAFETY: the genuine same-thread loan excludes destruction; the child
        // bridge mutex serializes Rust access. Checked exact geometry and Native
        // initialized journals describe this T, not a caller-nominated pointer.
        action(unsafe { &mut *address.cast::<FaultCommandBridge>() })
    }

    fn return_use(&mut self, api: Api, id: u64) -> Result<(), FaultCommandBridgeError> {
        let Some(loan) = self.physical_use.as_mut() else {
            return Ok(());
        };
        let status = (api.return_use)(id, &mut loan.projection, loan.serial);
        if status == 0 {
            if !loan.projection.is_null() {
                // A success projection alone cannot erase outstanding debt.
                // The matched byref method consumes this actual field on return.
                return Err(physical_error(-libc::EPROTO));
            }
            self.physical_use = None;
        }
        native_status(status)
    }
}

impl LiveFaultCommandControl for Adapter {
    fn initialize(&mut self) -> Result<(), FaultCommandBridgeError> {
        self.with_bridge(FaultCommandBridge::initialize)
    }

    fn pump(&mut self, offset: u64, raw: u64) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| bridge.pump(offset, raw))
    }

    fn pump_with_offset_reader(
        &mut self,
        raw: u64,
        reader: &dyn Fn() -> Result<u64, FaultCommandBridgeError>,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| bridge.pump_with_offset_reader(raw, reader))
    }

    fn pump_through_frontier(
        &mut self,
        offset: u64,
        raw: u64,
        frontier: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| bridge.pump_through_frontier(offset, raw, frontier))
    }

    fn pump_through_frontier_with_offset_reader(
        &mut self,
        raw: u64,
        frontier: u64,
        reader: &dyn Fn() -> Result<u64, FaultCommandBridgeError>,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| {
            bridge.pump_through_frontier_with_offset_reader(raw, frontier, reader)
        })
    }

    fn dispatch_node_boundary(&mut self, raw: u64) -> Result<(), FaultCommandBridgeError> {
        self.with_bridge(|bridge| bridge.dispatch_node_boundary(raw))
    }

    fn drain_publications(&mut self, offset: u64) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| bridge.drain_publications(offset))
    }

    fn command_frontier_is_settled(
        &mut self,
        frontier: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        self.with_bridge(|bridge| Ok(bridge.command_frontier_is_settled(frontier)))
    }
}

fn source_error(source: StartupSourceError) -> FaultCommandBridgeError {
    FaultCommandBridgeError::StorageSource { source }
}

fn physical_error(status: i32) -> FaultCommandBridgeError {
    FaultCommandBridgeError::PhysicalStorage { status }
}

fn native_status(status: i32) -> Result<(), FaultCommandBridgeError> {
    if status == 0 {
        Ok(())
    } else {
        Err(physical_error(status))
    }
}

#[cfg(test)]
mod tests;
