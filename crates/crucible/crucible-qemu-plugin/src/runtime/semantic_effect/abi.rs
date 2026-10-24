//! Source-private semantic owner installation beside the unchanged V9 registrar.
//!
//! These process-local pointers never enter a socket frame or shared memory.
//! Native installation copies the exact original callback tuple and correlates
//! its policy and already registered Role64 owner before any invocation. The
//! declarations install no owner or effect scope by themselves.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{c_int, c_void};

/// Identifies an opaque source-issued root slot, with no Rust-readable fields.
#[repr(C)]
pub struct SourceRootSeal {
    _private: [u8; 0],
}

/// Identifies an opaque source-selected original cut, with no Rust-readable fields.
#[repr(C)]
pub struct SourceEffectCut {
    _private: [u8; 0],
}

/// Identifies the already installed source-owned original endpoint handle.
#[repr(C)]
pub struct InstalledEndpointOwner {
    _private: [u8; 0],
}

/// Names the source's exact original 200-byte effect policy type.
#[repr(C)]
pub struct SourceEffectPolicy {
    _private: [u8; 0],
}

/// Supplies the four immutable original callbacks copied by native installation.
#[repr(C)]
pub struct SemanticInputOps {
    /// Selects the closed version-one callback tuple.
    pub version: u32,
    /// Specifies 40 bytes on the supported 64-bit native targets.
    pub size: u32,
    /// Retains the original ACK, roles, callback holds and actual transport owners.
    pub prepare: Prepare,
    /// Revalidates that same epoch before a new original source effect.
    pub validate_held: ValidateHeld,
    /// Stages only the source-selected pending context without semantic work.
    pub begin: Effect,
    /// Revokes the staged scope before any validation, error or stopped inventory.
    pub end: Effect,
}

/// Correlates a process-life semantic owner with its actual native installation.
#[repr(C)]
pub struct SemanticInputRegistration {
    /// Selects closed registration version one.
    pub version: u32,
    /// Specifies 40 bytes on the supported 64-bit native targets.
    pub size: u32,
    /// Borrows the exact already registered original EffectPolicy200.
    pub effect_policy: *const SourceEffectPolicy,
    /// Borrows the already installed actual Role64 owner, checked before dereference.
    pub endpoint_owner: *mut InstalledEndpointOwner,
    /// Borrows the process-life Rust owner of the actual reducer, roles and FIFOs.
    pub userdata: *mut c_void,
    /// Borrows the immutable callback tuple copied before publication.
    pub ops: *const SemanticInputOps,
}

/// Prepares the same retained original epoch without consuming partial holds.
///
/// # Safety
/// Native code authenticates the issued root handle before invocation and keeps
/// it live for the call. Userdata is the exact process-life owner registered at
/// installation. Output is writable aligned storage, disjoint from custody;
/// the callback clears it before refusal and never adopts an arbitrary root.
pub type Prepare = unsafe extern "C" fn(
    root: *const SourceRootSeal,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int;

/// Revalidates the same retained epoch while all original modeled holds remain held.
///
/// # Safety
/// Native code validates root and epoch against its retained original registry
/// before invocation. Userdata remains the registration's process-life owner;
/// opaque handles are compared or passed to authentic source validators and
/// never dereferenced as Rust allocations.
pub type ValidateHeld = unsafe extern "C" fn(
    root: *const SourceRootSeal,
    epoch: *mut c_void,
    userdata: *mut c_void,
) -> c_int;

/// Stages or revokes one same-original scoped callback admission.
///
/// # Safety
/// Native code validates the original root, owned epoch and selected cut before
/// invocation and retains them synchronously. Userdata names the exact pinned
/// owner. Begin observes only the pending-begin getter and performs no semantic
/// work; end revokes Rust scope before every validation or error return.
pub type Effect = unsafe extern "C" fn(
    root: *const SourceRootSeal,
    epoch: *mut c_void,
    cut: *const SourceEffectCut,
    userdata: *mut c_void,
) -> c_int;

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use super::*;

    #[test]
    fn original_native_registration_and_four_callbacks_have_exact_extents() {
        assert_eq!(size_of::<SemanticInputOps>(), 40);
        assert_eq!(offset_of!(SemanticInputOps, prepare), 8);
        assert_eq!(offset_of!(SemanticInputOps, validate_held), 16);
        assert_eq!(offset_of!(SemanticInputOps, begin), 24);
        assert_eq!(offset_of!(SemanticInputOps, end), 32);

        assert_eq!(size_of::<SemanticInputRegistration>(), 40);
        assert_eq!(offset_of!(SemanticInputRegistration, effect_policy), 8);
        assert_eq!(offset_of!(SemanticInputRegistration, endpoint_owner), 16);
        assert_eq!(offset_of!(SemanticInputRegistration, userdata), 24);
        assert_eq!(offset_of!(SemanticInputRegistration, ops), 32);
    }
}
