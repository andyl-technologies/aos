//! Holds one physical attachment throughout capture and backend admission.
//!
//! The captured owner moves into its backend only after genuine admission.
//! These mutually exclusive destinations share storage without allocating or
//! changing the physical owner, its payment, its diagnostics or its posts.

use super::{PhysicalTpmNvIoV1, TpmNvExtendFloorBackendV1};

pub(super) enum AttachmentPhysicalV1 {
    Empty,
    Captured(PhysicalTpmNvIoV1),
    Backend(TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1>),
}

impl AttachmentPhysicalV1 {
    pub(super) const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub(super) fn captured_ref(&self) -> Option<&PhysicalTpmNvIoV1> {
        match self {
            Self::Captured(original) => Some(original),
            Self::Empty | Self::Backend(_) => None,
        }
    }

    pub(super) fn captured_mut(&mut self) -> Option<&mut PhysicalTpmNvIoV1> {
        match self {
            Self::Captured(original) => Some(original),
            Self::Empty | Self::Backend(_) => None,
        }
    }

    /// Moves only captured custody into the same infallible backend wrapper.
    ///
    /// The caller performs no fallible work between this move and parking the
    /// backend. A wrong-phase observation restores the exact owning variant.
    pub(super) fn take_captured(&mut self) -> Option<PhysicalTpmNvIoV1> {
        match std::mem::replace(self, Self::Empty) {
            Self::Captured(original) => Some(original),
            other => {
                *self = other;
                None
            }
        }
    }

    pub(super) fn backend_ref(
        &self,
    ) -> Option<&TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1>> {
        match self {
            Self::Backend(original) => Some(original),
            Self::Empty | Self::Captured(_) => None,
        }
    }

    pub(super) fn backend_mut(
        &mut self,
    ) -> Option<&mut TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1>> {
        match self {
            Self::Backend(original) => Some(original),
            Self::Empty | Self::Captured(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn empty_destination_does_not_select_either_native_phase() {
        let mut destination = AttachmentPhysicalV1::Empty;

        assert!(destination.is_empty());
        assert!(destination.captured_ref().is_none());
        assert!(destination.captured_mut().is_none());
        assert!(destination.backend_ref().is_none());
        assert!(destination.backend_mut().is_none());

        assert!(destination.take_captured().is_none());
        assert!(destination.take_captured().is_none());
        assert!(destination.is_empty());
    }

    #[test]
    fn one_closed_slot_replaces_both_compiled_owning_planes() {
        type Backend = TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1>;

        let old_planes = size_of::<Option<PhysicalTpmNvIoV1>>()
            .checked_add(size_of::<Option<Backend>>())
            .unwrap();
        let largest_owner = size_of::<PhysicalTpmNvIoV1>().max(size_of::<Backend>());
        let tag_and_alignment = align_of::<AttachmentPhysicalV1>()
            .checked_mul(2)
            .unwrap();

        // Bound the actual compiled enum rather than guessing native layouts.
        // Both full owners are still charged by the existing physical invoice;
        // the new destination shares their dormant inline representation.
        assert!(size_of::<AttachmentPhysicalV1>() <= largest_owner + tag_and_alignment);
        assert!(size_of::<AttachmentPhysicalV1>() < old_planes);
    }
}
