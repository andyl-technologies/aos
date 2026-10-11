//! GPL-local ABI for original administrative reader self-registration.
//!
//! Native pointers remain in this process. Portable scalar facts carry only
//! historical observations; they never establish current thread liveness or
//! qualify a native readiness, execution, input or capture contract.

use std::ffi::{c_int, c_void};

use crucible_protocol::node_control::{
    NativeAdministrativeFacts, NativeAdministrativePreparation, NativeCommandError,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeAdministrationPolicy {
    version: u32,
    size: u32,
    scope: [u8; 32],
    role_commitment: [u8; 32],
    realize_request_digest: [u8; 32],
    policy_digest: [u8; 32],
    kind: u32,
    count: u32,
    descriptor_slot: i32,
    reserved: u32,
    socket_device: u64,
    socket_inode: u64,
}

impl NativeAdministrationPolicy {
    pub(crate) fn from_preparation(
        preparation: &NativeAdministrativePreparation,
    ) -> Result<Self, NativeCommandError> {
        preparation.validate()?;
        Ok(Self {
            version: 1,
            size: 168,
            scope: preparation
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?,
            role_commitment: preparation.identity_digest()?,
            realize_request_digest: preparation.phase.initialization.realize_request_digest,
            policy_digest: preparation.policy_digest,
            kind: 1,
            count: 1,
            descriptor_slot: preparation.descriptor_slot,
            reserved: 0,
            socket_device: preparation.socket_device,
            socket_inode: preparation.socket_inode,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeAdministrationFacts {
    version: u32,
    size: u32,
    kind: u32,
    flags: u32,
    registration_id: u64,
    thread_id: u64,
    socket_device: u64,
    socket_inode: u64,
    process_id: u64,
    descriptor_slot: i32,
    reserved: u32,
    scope: [u8; 32],
    role_commitment: [u8; 32],
    realize_request_digest: [u8; 32],
    policy_digest: [u8; 32],
}

impl NativeAdministrationFacts {
    pub(crate) fn decode(self) -> Result<NativeAdministrativeFacts, NativeCommandError> {
        let mut bytes = [0; 192];
        for (offset, value) in [
            (0, self.version),
            (4, self.size),
            (8, self.kind),
            (12, self.flags),
            (60, self.reserved),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (16, self.registration_id),
            (24, self.thread_id),
            (32, self.socket_device),
            (40, self.socket_inode),
            (48, self.process_id),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[56..60].copy_from_slice(&self.descriptor_slot.to_be_bytes());
        for (offset, value) in [
            (64, &self.scope),
            (96, &self.role_commitment),
            (128, &self.realize_request_digest),
            (160, &self.policy_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(value);
        }
        NativeAdministrativeFacts::decode(&bytes)
    }
}

pub(crate) type RegisterAdministration =
    extern "C" fn(*const NativeAdministrationPolicy, *mut NativeAdministrationFacts) -> c_int;

pub(crate) type QueryAdministration =
    extern "C" fn(*const u8, *const u8, *mut NativeAdministrationFacts) -> c_int;

pub(crate) fn resolve_register_administration() -> Option<RegisterAdministration> {
    // SAFETY: The optional source exports the exact scalar version-one ABI.
    // Absence refuses this role; no legacy callback substitutes for enrollment.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_register_crucible_node_administration".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The source declaration has this Policy168/Facts192 signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, RegisterAdministration>(pointer) })
    }
}

pub(crate) fn resolve_query_administration() -> Option<QueryAdministration> {
    // SAFETY: The optional source declares historical facts for exact scope and
    // role commitment; it installs no callback or dispatch permit.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_administration".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The source declaration has this exact historical query ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryAdministration>(pointer) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeAdministrationPolicy>() == 168);
    assert!(std::mem::offset_of!(NativeAdministrationPolicy, scope) == 8);
    assert!(std::mem::offset_of!(NativeAdministrationPolicy, descriptor_slot) == 144);
    assert!(std::mem::offset_of!(NativeAdministrationPolicy, socket_device) == 152);
    assert!(std::mem::size_of::<NativeAdministrationFacts>() == 192);
    assert!(std::mem::offset_of!(NativeAdministrationFacts, descriptor_slot) == 56);
    assert!(std::mem::offset_of!(NativeAdministrationFacts, scope) == 64);
};

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These administration abi tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
pub(crate) fn model_record(
    preparation: &NativeAdministrativePreparation,
    registration_id: u64,
    flags: u32,
) -> NativeAdministrationFacts {
    // Model-only ABI data; this never registers a native reader or qualifies a profile.
    NativeAdministrationFacts {
        version: 1,
        size: 192,
        kind: 1,
        flags,
        registration_id,
        // SAFETY: The syscall reads this model test's actual OS thread identity.
        thread_id: unsafe { libc::syscall(libc::SYS_gettid) } as u64,
        socket_device: preparation.socket_device,
        socket_inode: preparation.socket_inode,
        process_id: u64::from(std::process::id()),
        descriptor_slot: preparation.descriptor_slot,
        reserved: 0,
        scope: preparation
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap(),
        role_commitment: preparation.identity_digest().unwrap(),
        realize_request_digest: preparation.phase.initialization.realize_request_digest,
        policy_digest: preparation.policy_digest,
    }
}
