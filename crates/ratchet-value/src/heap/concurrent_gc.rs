//! Concurrent moving-GC barrier contract for the daemon heap.
//!
//! The active runtime does not yet include a concurrent collector. This module
//! defines the safe, daemon-only policy surface that later ZGC/Shenandoah-style
//! machinery will implement: already-uncolored aligned heap addresses are paired
//! with collector-supplied color metadata, and stale colors route to relocation
//! repair. It does not decode high-bit-colored pointer words, move objects,
//! dereference addresses, allocate memory, or change the bump arena.

use crate::value::tag::POINTER_TAG_MASK;

/// The runtime tier in which a concurrent moving collector may be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConcurrentGcTier {
    /// One-shot CLI or harness evaluation; no concurrent collector runs.
    OneShotArena,
    /// Long-lived daemon evaluation; concurrent load barriers may be enabled.
    Daemon,
}

/// Collector color metadata associated with a daemon heap address.
///
/// This precursor stores color out of band. The future concurrent collector owns
/// decoding high-bit-colored pointer words and must construct authoritative
/// barrier inputs after stripping those bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GcColor {
    /// The address is known current for the active relocation epoch.
    Current,
    /// The address may refer to an object that has been relocated.
    RemapRequired,
    /// The address has not been marked live for the current cycle.
    MarkRequired,
}

impl GcColor {
    /// Returns whether this color can pass the load-barrier fast path.
    pub const fn is_current(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// An already-uncolored heap address plus collector color metadata.
///
/// The address bits must be aligned and must not contain the low pointer-tag
/// metadata used by [`crate::value::tag`]. High-bit color decoding is outside
/// this precursor; callers pass the uncolored address and out-of-band color that
/// the collector has already decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BarrierAddress {
    address_bits: usize,
    color: GcColor,
}

impl BarrierAddress {
    /// Creates a barrier address from already-uncolored address bits and color.
    ///
    /// # Errors
    ///
    /// Returns [`ConcurrentGcError::NullAddress`] when the uncolored address is
    /// zero, or [`ConcurrentGcError::LowTagBitsPresent`] when the address still
    /// carries low pointer-tag bits that must be masked before barrier use.
    pub fn new(address_bits: usize, color: GcColor) -> Result<Self, ConcurrentGcError> {
        if address_bits & POINTER_TAG_MASK != 0 {
            return Err(ConcurrentGcError::LowTagBitsPresent { address_bits });
        }
        if address_bits == 0 {
            return Err(ConcurrentGcError::NullAddress);
        }
        Ok(Self {
            address_bits,
            color,
        })
    }

    /// Returns the uncolored aligned address bits.
    pub const fn address_bits(self) -> usize {
        self.address_bits
    }

    /// Returns the collector color metadata.
    pub const fn color(self) -> GcColor {
        self.color
    }
}

/// The decision made by a concurrent-GC read barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadBarrierAction {
    /// Return the address immediately.
    FastPath,
    /// Call the collector runtime to repair or mark the address.
    Repair {
        /// The reason the slow path is required.
        reason: LoadBarrierSlowReason,
    },
    /// No barrier is active for this runtime tier.
    Disabled,
}

/// The slow-path reason selected by a load barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadBarrierSlowReason {
    /// The address may be stale because relocation is in progress.
    Relocation,
    /// The address needs marking for the current concurrent cycle.
    Marking,
}

impl LoadBarrierAction {
    /// Returns whether the action allows the mutator to use the address without
    /// calling the collector runtime.
    pub const fn is_fast(self) -> bool {
        matches!(self, Self::FastPath | Self::Disabled)
    }
}

/// The thunk-state mutation operation being protected by a GC barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThunkMutation {
    /// Claim a suspended thunk before forcing it.
    ClaimForForce,
    /// Publish the forced result into the thunk cell.
    PublishForced,
}

/// The barrier discipline required before a thunk-state mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThunkMutationBarrier {
    /// No concurrent collector is active for this tier.
    Disabled,
    /// The mutation may proceed after the daemon load barrier fast path.
    BarrierFastPath {
        /// The protected thunk-state mutation.
        mutation: ThunkMutation,
    },
    /// The collector must repair or mark the thunk address before mutation.
    RepairBeforeMutation {
        /// The protected thunk-state mutation.
        mutation: ThunkMutation,
        /// The reason the collector slow path is required.
        reason: LoadBarrierSlowReason,
    },
}

impl ThunkMutationBarrier {
    /// Returns whether the mutation can proceed without calling the collector
    /// runtime.
    pub const fn permits_immediate_mutation(self) -> bool {
        matches!(self, Self::Disabled | Self::BarrierFastPath { .. })
    }
}

/// Classifies a barrier address for a daemon load barrier.
pub const fn classify_load_barrier(
    tier: ConcurrentGcTier,
    address: BarrierAddress,
) -> LoadBarrierAction {
    match tier {
        ConcurrentGcTier::OneShotArena => LoadBarrierAction::Disabled,
        ConcurrentGcTier::Daemon => match address.color {
            GcColor::Current => LoadBarrierAction::FastPath,
            GcColor::RemapRequired => LoadBarrierAction::Repair {
                reason: LoadBarrierSlowReason::Relocation,
            },
            GcColor::MarkRequired => LoadBarrierAction::Repair {
                reason: LoadBarrierSlowReason::Marking,
            },
        },
    }
}

/// Classifies the barrier step required before mutating a thunk state word.
///
/// The future concurrent collector must run the load barrier before claiming or
/// publishing a thunk state transition. This decision table keeps that ordering
/// explicit while the active single-threaded tree-walk thunk machinery remains
/// unchanged.
pub const fn classify_thunk_mutation_barrier(
    tier: ConcurrentGcTier,
    thunk: BarrierAddress,
    mutation: ThunkMutation,
) -> ThunkMutationBarrier {
    match classify_load_barrier(tier, thunk) {
        LoadBarrierAction::Disabled => ThunkMutationBarrier::Disabled,
        LoadBarrierAction::FastPath => ThunkMutationBarrier::BarrierFastPath { mutation },
        LoadBarrierAction::Repair { reason } => {
            ThunkMutationBarrier::RepairBeforeMutation { mutation, reason }
        }
    }
}

/// A failed concurrent-GC address or barrier operation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConcurrentGcError {
    /// A barrier address decoded to a null uncolored address.
    #[error("barrier heap address is null")]
    NullAddress,
    /// A barrier address still carried low pointer-tag bits.
    #[error("barrier heap address still has low pointer-tag bits set: 0x{address_bits:x}")]
    LowTagBitsPresent {
        /// The rejected address bits.
        address_bits: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_addresses_reject_null_and_low_pointer_tags() {
        assert_eq!(
            BarrierAddress::new(0, GcColor::Current),
            Err(ConcurrentGcError::NullAddress)
        );
        assert_eq!(
            BarrierAddress::new(0b1001, GcColor::Current),
            Err(ConcurrentGcError::LowTagBitsPresent {
                address_bits: 0b1001,
            })
        );
    }

    #[test]
    fn current_daemon_addresses_take_the_fast_path() {
        let address =
            BarrierAddress::new(0x1000, GcColor::Current).expect("aligned address is accepted");

        assert_eq!(
            classify_load_barrier(ConcurrentGcTier::Daemon, address),
            LoadBarrierAction::FastPath
        );
        assert!(classify_load_barrier(ConcurrentGcTier::Daemon, address).is_fast());
    }

    #[test]
    fn stale_daemon_colors_require_repair() {
        for (color, reason) in [
            (GcColor::RemapRequired, LoadBarrierSlowReason::Relocation),
            (GcColor::MarkRequired, LoadBarrierSlowReason::Marking),
        ] {
            let address = BarrierAddress::new(0x1000, color).expect("aligned address is accepted");

            assert_eq!(
                classify_load_barrier(ConcurrentGcTier::Daemon, address),
                LoadBarrierAction::Repair { reason }
            );
            assert!(!classify_load_barrier(ConcurrentGcTier::Daemon, address).is_fast());
        }
    }

    #[test]
    fn one_shot_arena_disables_concurrent_barriers() {
        let address = BarrierAddress::new(0x1000, GcColor::RemapRequired)
            .expect("aligned address is accepted");

        assert_eq!(
            classify_load_barrier(ConcurrentGcTier::OneShotArena, address),
            LoadBarrierAction::Disabled
        );
        assert!(classify_load_barrier(ConcurrentGcTier::OneShotArena, address).is_fast());
    }

    #[test]
    fn thunk_mutation_barrier_runs_after_load_barrier_fast_path() {
        let thunk =
            BarrierAddress::new(0x1000, GcColor::Current).expect("aligned address is accepted");

        let barrier = classify_thunk_mutation_barrier(
            ConcurrentGcTier::Daemon,
            thunk,
            ThunkMutation::ClaimForForce,
        );

        assert_eq!(
            barrier,
            ThunkMutationBarrier::BarrierFastPath {
                mutation: ThunkMutation::ClaimForForce,
            }
        );
        assert!(barrier.permits_immediate_mutation());
    }

    #[test]
    fn thunk_mutation_barrier_repairs_stale_addresses_before_state_cas() {
        let thunk = BarrierAddress::new(0x1000, GcColor::RemapRequired)
            .expect("aligned address is accepted");

        let barrier = classify_thunk_mutation_barrier(
            ConcurrentGcTier::Daemon,
            thunk,
            ThunkMutation::PublishForced,
        );

        assert_eq!(
            barrier,
            ThunkMutationBarrier::RepairBeforeMutation {
                mutation: ThunkMutation::PublishForced,
                reason: LoadBarrierSlowReason::Relocation,
            }
        );
        assert!(!barrier.permits_immediate_mutation());
    }

    #[test]
    fn thunk_mutation_barrier_is_disabled_in_one_shot_mode() {
        let thunk = BarrierAddress::new(0x1000, GcColor::RemapRequired)
            .expect("aligned address is accepted");

        let barrier = classify_thunk_mutation_barrier(
            ConcurrentGcTier::OneShotArena,
            thunk,
            ThunkMutation::ClaimForForce,
        );

        assert_eq!(barrier, ThunkMutationBarrier::Disabled);
        assert!(barrier.permits_immediate_mutation());
    }

    #[test]
    fn barrier_addresses_keep_address_and_color_metadata_separate() {
        let address = BarrierAddress::new(0x2000, GcColor::MarkRequired)
            .expect("aligned address is accepted");

        assert_eq!(address.address_bits(), 0x2000);
        assert_eq!(address.color(), GcColor::MarkRequired);
    }
}
