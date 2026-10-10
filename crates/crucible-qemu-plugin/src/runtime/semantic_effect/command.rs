//! Retained original command retrieval inside the native semantic owner.
//!
//! The source getter runs at its genuine held RR seam and copies only the
//! already host-admitted original record. Epoch addresses remain process-local;
//! source validates the exact retained epoch before any cut selection. No old
//! scalar command or portable digest becomes a native effect permission.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{c_int, c_void};

/// Copies a complete native Position without a pointer or Rust enum layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct NativeEffectPosition {
    /// Copies the original physical picosecond coordinate.
    pub time_ps: u64,
    /// Copies the original causal microstep.
    pub microstep: u64,
    /// Copies the closed public phase number zero through three.
    pub phase: u32,
    /// Remains zero in version one.
    pub reserved: u32,
}

/// Copies the exact original journal command for native source selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NativeEffectCommand {
    /// Selects the closed version-one native command.
    pub version: u32,
    /// Specifies the complete 224-byte native record.
    pub size: u32,
    /// Selects finite Compute as one; no other kind is admitted initially.
    pub kind: u32,
    /// Remains zero in version one.
    pub reserved: u32,
    /// Identifies the already retained original command sequence.
    pub sequence: u64,
    /// Correlates the original prepared scope.
    pub scope: [u8; 32],
    /// Correlates the complete original effect preparation.
    pub effect_preparation: [u8; 32],
    /// Retains the independently host-admitted original grant identity.
    pub grant_digest: [u8; 32],
    /// Identifies the immutable complete original journal command.
    pub command_digest: [u8; 32],
    /// References the exact acquired process-private epoch, never a wire address.
    pub owned_epoch: *mut c_void,
    /// Retains the original full start position, checked against the source cursor.
    pub start: NativeEffectPosition,
    /// Retains the original exclusive full-position limit.
    pub limit: NativeEffectPosition,
    /// Bounds callbacks to no more than the separately pinned EffectPolicy200.
    pub maximum_callbacks: u32,
    /// Remains zero in version one.
    pub budget_reserved: u32,
    /// Bounds CPU service to no more than the separately pinned EffectPolicy200.
    pub maximum_service_span: u64,
}

/// Borrows one already retained original command beside backed receipt storage.
///
/// # Safety
/// Native code supplies the same retained epoch and process-life userdata from
/// the semantic registration, on the genuine held RR seam. Output is writable,
/// aligned complete command storage disjoint from the journal. The callback
/// zeros it before every refusal; success retains the original command and its
/// receipt credit before exposing fields. It never receives another packet.
pub type OriginalCommandGetter = unsafe extern "C" fn(
    owned_epoch: *mut c_void,
    output: *mut NativeEffectCommand,
    userdata: *mut c_void,
) -> c_int;

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use super::*;

    #[test]
    fn original_native224_retains_separate_grant_and_command_and_full_positions() {
        assert_eq!(size_of::<NativeEffectPosition>(), 24);
        assert_eq!(offset_of!(NativeEffectPosition, phase), 16);
        assert_eq!(size_of::<NativeEffectCommand>(), 224);
        assert_eq!(offset_of!(NativeEffectCommand, sequence), 16);
        assert_eq!(offset_of!(NativeEffectCommand, scope), 24);
        assert_eq!(offset_of!(NativeEffectCommand, effect_preparation), 56);
        assert_eq!(offset_of!(NativeEffectCommand, grant_digest), 88);
        assert_eq!(offset_of!(NativeEffectCommand, command_digest), 120);
        assert_eq!(offset_of!(NativeEffectCommand, owned_epoch), 152);
        assert_eq!(offset_of!(NativeEffectCommand, start), 160);
        assert_eq!(offset_of!(NativeEffectCommand, limit), 184);
        assert_eq!(offset_of!(NativeEffectCommand, maximum_callbacks), 208);
        assert_eq!(offset_of!(NativeEffectCommand, maximum_service_span), 216);
    }
}
