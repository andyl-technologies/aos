//! Actual source construction callback registration and retained channel replies.

use std::ffi::c_void;
use std::sync::atomic::Ordering;

use crucible_protocol::node_control::{
    NativeCommandError, NativeFrame, NativeInitializationPreparation,
};

use super::NativeNodeControl;
use crate::native_node_control::{
    initialization_abi, initialization_custody::InitializationCustody,
};

impl NativeNodeControl {
    pub(crate) fn with_initialization(
        mut self,
        preparation: NativeInitializationPreparation,
    ) -> Result<Self, NativeCommandError> {
        if self.initialization.is_some()
            || preparation.preparation.scope.identity_digest()? != self.prepared_scope_hash
        {
            return Err(NativeCommandError::Conflict);
        }
        {
            let state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            let original = state.journal.snapshot()?;
            if state.quarantined
                || original.entry_count() != 0
                || original.preparation() != &preparation.preparation
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        let query = initialization_abi::resolve_query_initialization_cut().ok_or(
            NativeCommandError::Invalid("native initialization source API unavailable"),
        )?;
        self.initialization = Some(std::sync::Arc::new(InitializationCustody::new(
            preparation,
            query,
        )?));
        Ok(self)
    }

    pub(super) fn register_initialization(&'static self) -> Result<(), NativeCommandError> {
        let Some(initialization) = &self.initialization else {
            return Ok(());
        };
        let register = initialization_abi::resolve_register_initialization().ok_or(
            NativeCommandError::Invalid("native initialization registration unavailable"),
        )?;
        let result = register(
            1,
            initialization.scope.as_ptr(),
            initialization.commitment.as_ptr(),
            initialization.preparation.realize_request_digest.as_ptr(),
            initialization.preparation.policy_digest.as_ptr(),
            initialization.preparation.class_mask,
            initialization.preparation.maximum_callbacks,
            Some(get_initialization_command),
            Some(publish_initialization_receipt),
            (self as *const Self).cast_mut().cast(),
        );
        if result != 0 {
            return Err(NativeCommandError::Conflict);
        }
        self.initialization_registered
            .store(true, Ordering::Release);
        Ok(())
    }

    /// Returns an actual registered initializer commitment, never a feature declaration.
    pub(crate) fn registered_initialization_commitment(&self) -> Option<[u8; 32]> {
        self.initialization_registered
            .load(Ordering::Acquire)
            .then_some(())?;
        Some(self.initialization.as_ref()?.commitment)
    }

    pub(super) fn poll_initialization_frame(
        &self,
        frame: NativeFrame,
    ) -> Result<(), NativeCommandError> {
        let initialization = self
            .initialization
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        let channel = self.channel.as_ref().ok_or(NativeCommandError::Conflict)?;
        match frame {
            NativeFrame::QueryInitialization(query) => {
                if query.prepared_scope_hash != initialization.scope
                    || query.initialization_commitment != initialization.commitment
                {
                    return Err(NativeCommandError::Conflict);
                }
                if let Some(cut) = initialization.original_cut() {
                    channel
                        .send(&NativeFrame::InitializationCut(Box::new(cut)))
                        .map_err(|_| NativeCommandError::Conflict)?;
                }
            }
            NativeFrame::Initialize(command) => {
                initialization.retain(*command)?;
                if let Some(receipt) = initialization.original_receipt() {
                    channel
                        .send(&NativeFrame::InitializationStopped(Box::new(receipt)))
                        .map_err(|_| NativeCommandError::Conflict)?;
                }
            }
            NativeFrame::AcknowledgeInitialization(ack) => {
                if self
                    .state
                    .lock()
                    .map_err(|_| NativeCommandError::Conflict)?
                    .quarantined
                {
                    return Err(NativeCommandError::Conflict);
                }
                initialization.acknowledge(&ack)?;
                channel
                    .send(&NativeFrame::InitializationAcknowledged(ack))
                    .map_err(|_| NativeCommandError::Conflict)?;
            }
            _ => return Err(NativeCommandError::Conflict),
        }
        Ok(())
    }

    fn fail_initialization(&self) {
        if let Some(initialization) = &self.initialization {
            initialization.fail();
        }
        if let Ok(mut state) = self.state.lock() {
            state.quarantined = true;
            state.current = None;
        }
    }
}

extern "C" fn get_initialization_command(
    output: *mut initialization_abi::NativeInitializationCommand,
    userdata: *mut c_void,
) -> bool {
    if output.is_null() || userdata.is_null() {
        return false;
    }
    // SAFETY: Source registration retains this process-lifetime owner and supplies
    // a writable ABI-sized output only at the authentic preparation callback seam.
    let owner = unsafe { &*userdata.cast::<NativeNodeControl>() };
    if owner.administration_faulted.load(Ordering::Acquire) {
        return false;
    }
    if owner
        .state
        .lock()
        .ok()
        .is_none_or(|state| state.quarantined)
    {
        return false;
    }
    let Some(initialization) = &owner.initialization else {
        return false;
    };
    match initialization.observe_original_cut() {
        Ok(Some(cut)) => {
            if let Some(channel) = &owner.channel
                && channel
                    .send(&NativeFrame::InitializationCut(Box::new(cut)))
                    .is_err()
            {
                owner.fail_initialization();
                return false;
            }
        }
        Ok(None) => return false,
        Err(_) => {
            owner.fail_initialization();
            return false;
        }
    }
    // The initializer runs before the execution getter. Retain its actual
    // initial observational cuts at this same native seam; reader queries
    // recover these historical bytes without querying QEMU or granting work.
    if owner.observe_initial_cpu_park().is_err()
        || owner
            .observe_writers(crucible_node_contract::U64::new(0))
            .is_err()
        || owner
            .observe_timers(crucible_node_contract::U64::new(0))
            .is_err()
        || owner
            .observe_phase_timers(crucible_node_contract::U64::new(0))
            .is_err()
    {
        owner.fail_initialization();
        return false;
    }
    if let Some(construction) = &owner.construction {
        // A busy reader keeps original custody; its retry recovers this cache.
        if construction.recover().is_err() {
            owner.fail_initialization();
            return false;
        }
    }
    let Some(command) = initialization.command() else {
        return false;
    };
    // SAFETY: QEMU supplied exclusive correctly aligned command output storage.
    unsafe {
        output.write(command);
    }
    true
}

extern "C" fn publish_initialization_receipt(
    receipt: *const initialization_abi::NativeInitializationReceipt,
    userdata: *mut c_void,
) {
    if receipt.is_null() || userdata.is_null() {
        return;
    }
    // SAFETY: Source callback lifetime supplies one complete immutable ABI receipt
    // and the original registered process-lifetime owner, both in this GPL process.
    let owner = unsafe { &*userdata.cast::<NativeNodeControl>() };
    // SAFETY: The source keeps this complete immutable receipt alive for the callback.
    let raw = unsafe { receipt.read() };
    let Some(initialization) = &owner.initialization else {
        owner.fail_initialization();
        return;
    };
    let retained = match initialization.record_receipt(raw) {
        Ok(receipt) => receipt,
        Err(_) => {
            owner.fail_initialization();
            return;
        }
    };
    if retained.status
        == crucible_protocol::node_control::NativeInitializationStatus::EffectsUnknown
    {
        owner.fail_initialization();
    }
    if retained.status == crucible_protocol::node_control::NativeInitializationStatus::Applied
        && owner.observe_preparation_successor(&retained).is_err()
    {
        owner.fail_initialization();
        return;
    }
    if let Some(construction) = &owner.construction
        && construction.recover().is_err()
    {
        owner.fail_initialization();
        return;
    }
    if let Some(channel) = &owner.channel
        && channel
            .send(&NativeFrame::InitializationStopped(Box::new(retained)))
            .is_err()
    {
        owner.fail_initialization();
    }
}
