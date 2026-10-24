//! Derives five independently prepaid output-bank limits from the actual launch.
//!
//! ```text
//! {native_snapshot_bytes,current_control_bytes,native_before_bytes,
//!  anchor_bytes,native_after_bytes}
//! ```
//!
//! These are finite new17 ceilings, not old credits or promises that an actual
//! graph fits. The native counting writer compares each real output before its
//! effects, and leaves a bank unpopulated until that bank's cut is frozen.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

/// Retains independent new17 output ceilings selected by the same launch DATA.
///
/// Equal before/after limits still fund two distinct owners. Full Source/holder
/// identity, private startup17 admission and the actual Capture claim remain
/// separate; deserializing these numbers creates no output or receive authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledCaptureOutputLimits {
    /// Bounds the complete current native17 snapshot in its own output bank.
    pub native_snapshot_bytes: U64,
    /// Bounds the separately retained current Control17 snapshot.
    pub current_control_bytes: U64,
    /// Bounds the independently retained before-protocol object.
    pub native_before_bytes: U64,
    /// Bounds the new17 anchor by the actual negotiated frame ceiling.
    pub anchor_bytes: U64,
    /// Bounds the separately retained after-protocol object.
    pub native_after_bytes: U64,
}

impl PacketRestoredSettledCaptureOutputLimits {
    /// Derives the exact five-bank policy after checking all full declarations.
    ///
    /// The original launch storage remains unchanged. This helper computes DATA;
    /// the Core issuer must still check the explicit Source17 marker and same
    /// genuine holder/launch before independently admitting every new owner.
    ///
    /// # Errors
    /// Refuses invalid original storage, empty binding roster, any missing or
    /// changed full17 declaration, or invalid derived finite limits.
    pub fn from_launch_data(launch: &PacketNative5SourceLaunch) -> Result<Self, ProviderError> {
        launch.storage.validate(&launch.limits)?;
        if launch.selection.realization.bindings.is_empty() {
            return Err(invalid());
        }
        for binding in &launch.selection.realization.bindings {
            authenticate_restored_settled_capture_immutable_declaration_data(
                &launch.selection.provider.implementation.formats,
                &binding.compatibility.implementation.formats,
                &launch.selection.provider.extensions_supported,
            )?;
        }
        let result = Self {
            native_snapshot_bytes: launch.storage.snapshot_bytes,
            current_control_bytes: launch.storage.control_snapshot_bytes,
            native_before_bytes: launch.storage.protocol_snapshot_bytes,
            anchor_bytes: launch.limits.frame_bytes,
            native_after_bytes: launch.storage.protocol_snapshot_bytes,
        };
        result.validate_data()?;
        Ok(result)
    }

    /// Checks the closed finite policy without creating an allocation or grant.
    ///
    /// # Errors
    /// Refuses zero, out-of-family ceilings, a Control limit above the snapshot
    /// limit, or before/after limits not derivable from one actual launch.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.native_snapshot_bytes.get() == 0
            || self.native_snapshot_bytes.get() > 8 * 1024 * 1024
            || self.current_control_bytes.get() == 0
            || self.current_control_bytes > self.native_snapshot_bytes
            || self.native_before_bytes.get() == 0
            || self.native_before_bytes.get() > 512 * 1024 * 1024
            || self.native_after_bytes != self.native_before_bytes
            || self.anchor_bytes.get() == 0
            || self.anchor_bytes.get() > 65_536
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares all five limits to the same complete declared launch DATA.
    ///
    /// # Errors
    /// Refuses invalid declarations/limits or any changed quantity. This cannot
    /// replace actual issuer, source, currentness or private carrier checks.
    pub fn authenticate_same_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        if *self != Self::from_launch_data(launch)? {
            return Err(invalid());
        }
        Ok(())
    }

    /// Walks the fixed retained limit fields without resetting the owner pass.
    pub(crate) fn observe_owned_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            native_snapshot_bytes,
            current_control_bytes,
            native_before_bytes,
            anchor_bytes,
            native_after_bytes,
        } = self;
        observer.observe(native_snapshot_bytes)?;
        observer.observe(current_control_bytes)?;
        observer.observe(native_before_bytes)?;
        observer.observe(anchor_bytes)?;
        observer.observe(native_after_bytes)
    }

    /// Reports defining full-declaration and fixed scalar/borrow/result views.
    ///
    /// Dynamic raw/DOM/typed/alias/error banks and every output's simultaneous
    /// owner remain independent terms in the genuine whole native17 producer.
    pub fn counter_scratch_data() -> usize {
        use std::mem::{size_of, size_of_val};
        let terms = [
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<Result<Self, ProviderError>>(),
            size_of::<&PacketNative5SourceLaunch>(),
            size_of::<(&U64, &U64, &U64, &U64, &U64)>(),
            size_of::<std::slice::Iter<'_, crucible_node_format::NodeBinding>>(),
            size_of::<Option<&crucible_node_format::NodeBinding>>(),
            size_of::<&crucible_node_format::NodeBinding>(),
            size_of::<&mut crate::retained_metadata::MetadataObserver<'_>>(),
            size_of::<Result<(), ProviderError>>(),
            size_of::<[(U64, u64); 5]>(),
            size_of::<std::array::IntoIter<(U64, u64), 5>>(),
            size_of::<Option<u64>>(),
            size_of::<u64>(),
            restored_settled_capture_selection_counter_scratch_data(),
        ];
        size_of_val(&terms)
            + size_of::<std::array::IntoIter<usize, 15>>()
            + terms.into_iter().sum::<usize>()
    }
}
