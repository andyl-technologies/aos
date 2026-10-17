//! Original native root-policy registration beneath the retained full preparation.
//!
//! Registration compares the source's early constructor pin and supplies no
//! source-root closure, input epoch or effect permission. The full preparation
//! stays retained after registration. Opaque epoch acquisition and finite native
//! effect admission are separate source interfaces and remain unavailable here.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_protocol::node_control::{NativeCommandError, NativeFixedMicrovmPreparation};

use super::NativeNodeControl;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeRootPolicy {
    version: u32,
    size: u32,
    digests: [[u8; 32]; 8],
    firmware_length: u64,
    ram_length: u64,
    seed: u64,
    maximum_microsteps: u64,
    maximum_service_span: u64,
    mapping: u32,
    controller_edition: u32,
    profile: u32,
    digest_algorithm: u32,
    maximum_callbacks: u32,
    reserved: u32,
}

impl NativeRootPolicy {
    pub(super) fn from_preparation(
        preparation: &NativeFixedMicrovmPreparation,
    ) -> Result<Self, NativeCommandError> {
        preparation.validate()?;
        let administration = &preparation.administration;
        let phase = &administration.phase;
        let initialization = &phase.initialization;
        Ok(Self {
            version: 1,
            size: 328,
            digests: [
                initialization.preparation.scope.identity_digest()?,
                preparation.identity_digest()?,
                initialization.realize_request_digest,
                preparation.policy_digest,
                initialization.identity_digest()?,
                phase.identity_digest()?,
                administration.identity_digest()?,
                preparation.firmware_sha256,
            ],
            firmware_length: preparation.firmware_length.get(),
            ram_length: preparation.ram_length.get(),
            seed: preparation.seed.get(),
            maximum_microsteps: preparation.maximum_microstep.get(),
            maximum_service_span: preparation.maximum_service_span.get(),
            mapping: preparation.mapping as u32,
            controller_edition: 7,
            profile: 1,
            digest_algorithm: 1,
            maximum_callbacks: preparation.maximum_callbacks,
            reserved: 0,
        })
    }
}

type RegisterRootPolicy = extern "C" fn(*const NativeRootPolicy) -> c_int;

pub(super) struct RootPolicyCustody {
    preparation: NativeFixedMicrovmPreparation,
    register: RegisterRootPolicy,
    registered: AtomicBool,
}

impl RootPolicyCustody {
    fn new(preparation: NativeFixedMicrovmPreparation) -> Result<Self, NativeCommandError> {
        preparation.validate()?;
        // SAFETY: This optional GPL-side declaration registers an immutable scalar
        // Root328 policy within QEMU. No native structure crosses the public boundary.
        let pointer = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_register_crucible_node_root_policy".as_ptr(),
            )
        };
        if pointer.is_null() {
            return Err(NativeCommandError::Invalid(
                "native original root registration unavailable",
            ));
        }
        // SAFETY: The independently versioned source export has exactly this
        // const Root328 signature. The owned value remains live throughout its call.
        let register = unsafe { std::mem::transmute::<*mut c_void, RegisterRootPolicy>(pointer) };
        Ok(Self {
            preparation,
            register,
            registered: AtomicBool::new(false),
        })
    }

    fn register_original(&self) -> Result<(), NativeCommandError> {
        if self.registered.load(Ordering::Acquire) {
            return Err(NativeCommandError::Conflict);
        }
        let policy = NativeRootPolicy::from_preparation(&self.preparation)?;
        if (self.register)(&policy) != 0 {
            return Err(NativeCommandError::Conflict);
        }
        self.registered.store(true, Ordering::Release);
        Ok(())
    }
}

impl NativeNodeControl {
    pub(crate) fn install_root_run_control(
        &self,
        custody: std::sync::Arc<crate::runtime::native_run_control::NativeRunControlCustody>,
        workers: &std::sync::Arc<crate::runtime::worker_quiescence::LiveWorkerQuiescence>,
    ) -> Result<(), NativeCommandError> {
        if self.registered_root_commitment().is_none()
            || self
                .administrative_modeled_workers()
                .is_none_or(|owner| !std::sync::Arc::ptr_eq(owner, workers))
        {
            return Err(NativeCommandError::Conflict);
        }
        // Retain the actual socket owner before inspecting preparation status.
        // An unavailable snapshot or invalid phase cannot drop refused custody.
        self.root_run_control
            .set(std::sync::Arc::clone(&custody))
            .map_err(|_| NativeCommandError::Conflict)?;
        let snapshot = custody
            .snapshot()
            .map_err(|_| NativeCommandError::Conflict)?;
        if snapshot.received != 0
            || snapshot.terminal
            || snapshot.lifecycle
                != crucible_protocol::ControlLifecycleState::RunningViaSharedMemory
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn with_fixed_microvm(
        mut self,
        preparation: NativeFixedMicrovmPreparation,
    ) -> Result<Self, NativeCommandError> {
        if self.root_policy.is_some()
            || preparation
                .administration
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?
                != *self
                    .administrative_actor
                    .as_ref()
                    .ok_or(NativeCommandError::Conflict)?
                    .scope()
            || self.administration.is_none()
        {
            return Err(NativeCommandError::Conflict);
        }
        self.root_policy = Some(RootPolicyCustody::new(preparation)?);
        Ok(self)
    }

    pub(super) fn register_root_policy(&self) -> Result<(), NativeCommandError> {
        if let Some(policy) = &self.root_policy {
            policy.register_original()?;
        }
        Ok(())
    }

    pub(crate) fn original_registered_root_policy(&self) -> Option<NativeRootPolicy> {
        let policy = self.root_policy.as_ref()?;
        policy.registered.load(Ordering::Acquire).then_some(())?;
        NativeRootPolicy::from_preparation(&policy.preparation).ok()
    }

    pub(crate) fn registered_root_commitment(&self) -> Option<[u8; 32]> {
        let policy = self.root_policy.as_ref()?;
        policy.registered.load(Ordering::Acquire).then_some(())?;
        policy.preparation.identity_digest().ok()
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeRootPolicy>() == 328);
    assert!(std::mem::offset_of!(NativeRootPolicy, digests) == 8);
    assert!(std::mem::offset_of!(NativeRootPolicy, firmware_length) == 264);
    assert!(std::mem::offset_of!(NativeRootPolicy, mapping) == 304);
};
