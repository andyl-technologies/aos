//! Moves the actual fresh tuple once after the enclosing original census.
//!
//! Legacy preparation retains its inline originals. Funded preparation moves
//! those same buffers into one immutable holder before any member is built.

use super::*;
use crucible_engine::node_adapters::cnp::source_birth_derivation::original_launch::{
    OriginalSourceBirthLaunch, OriginalSourceBirthLaunches,
};
use crucible_engine::node_contract::RuntimeError;
use std::mem::size_of;

pub(super) struct PreparedLaunches {
    inline: Option<[PacketNative5SourceLaunch; 3]>,
    retained: Option<OriginalSourceBirthLaunches>,
}

impl PreparedLaunches {
    pub(super) fn inline(launches: [PacketNative5SourceLaunch; 3]) -> Self {
        Self {
            inline: Some(launches),
            retained: None,
        }
    }

    pub(super) fn originals(&self) -> Result<&[PacketNative5SourceLaunch; 3], RuntimeError> {
        match (&self.inline, &self.retained) {
            (Some(original), None) => Ok(original),
            (None, Some(original)) => Ok(original.originals()),
            _ => Err(RuntimeError::ForeignAuthority),
        }
    }

    pub(super) fn get(&self, member: usize) -> Result<&PacketNative5SourceLaunch, RuntimeError> {
        self.originals()?
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(super) fn retain_into(&mut self) -> Result<(), RuntimeError> {
        OriginalSourceBirthLaunches::retain_into(&mut self.inline, &mut self.retained)
    }

    pub(super) fn selected(
        &self,
        member: usize,
    ) -> Result<OriginalSourceBirthLaunch, RuntimeError> {
        self.retained
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .selected(member)
    }

    pub(super) fn retained_allocation_data(&self) -> Result<usize, RuntimeError> {
        match (&self.inline, &self.retained) {
            (Some(_), None) => Ok(0),
            (None, Some(_)) => OriginalSourceBirthLaunches::allocation_storage_data(usize::MAX),
            _ => Err(RuntimeError::ForeignAuthority),
        }
    }

    pub(super) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        self.retained
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_requested_storage_data(usize::MAX)
    }

    pub(super) fn counter_scratch_data() -> usize {
        OriginalSourceBirthLaunches::counter_scratch_data()
            + size_of::<&Self>() * 2
            + size_of::<&mut Self>()
            + size_of::<Result<&[PacketNative5SourceLaunch; 3], RuntimeError>>()
            + size_of::<Result<&PacketNative5SourceLaunch, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
    }

    #[cfg(test)]
    pub(super) fn inline_mut(
        &mut self,
    ) -> Result<&mut [PacketNative5SourceLaunch; 3], RuntimeError> {
        if self.retained.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.inline.as_mut().ok_or(RuntimeError::OwnerUnavailable)
    }
}

impl PreparedCompleteRestoration {
    pub(super) fn retain_fresh_original_launches_data(&mut self) -> Result<(), RuntimeError> {
        if self.import18_templates.deployment.is_none() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let allocation = OriginalSourceBirthLaunches::allocation_storage_data(usize::MAX)?;
        // This is the same complete Prepared/deployment conjunction used before
        // actual template effects, not a caller-supplied allocation permission.
        self.observe_import18_templates_data([
            allocation,
            0,
            PreparedLaunches::counter_scratch_data(),
        ])?;
        self.launches.retain_into()?;
        // The holder stays installed if any later original census refuses.
        self.observe_import18_templates_data([0; 3])
    }
}
