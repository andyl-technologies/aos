//! Retains the actual fixed launch-presence comparison and its native prefixes.
//!
//! Both ordinary and selected callers share the binding→confinement→mode
//! recipe. This is comparison custody under a genuine prepaid caller, never a
//! launch-image, floor, resource account or permission to use physical TPM.

use super::*;
use super::super::backend::confinement::OwnerConfinementOriginalV1;
use super::super::provisioning::{CredentialReadCustodyV1, ModeRevalidationOriginalV1};

/// Owns one presence binding and the original observations it reaches.
pub(crate) struct ModePresenceOriginalV1 {
    binding: Option<Result<(), FloorErrorV1>>,
    confinement: OwnerConfinementOriginalV1,
    mode: ModeRevalidationOriginalV1,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
}

impl ModePresenceOriginalV1 {
    /// Creates inert destinations before the caller's financial/native entry.
    pub(crate) fn new() -> Self {
        Self {
            binding: None,
            confinement: OwnerConfinementOriginalV1::new(),
            mode: ModeRevalidationOriginalV1::new(),
            result: None,
            entered: false,
        }
    }

    pub(super) fn capture_once(
        &mut self,
        endpoint: FloorEndpointV1,
        mode: &ModePinV1,
        supplied: bool,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.result = Some(self.capture(endpoint, mode, supplied, custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    fn capture(
        &mut self,
        endpoint: FloorEndpointV1,
        mode: &ModePinV1,
        supplied: bool,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        self.binding = Some(require_mode_image_presence(mode.mode(), supplied));
        match self.binding {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(error),
            None => return Err(FloorErrorV1::Unavailable),
        }
        if mode.mode() == ImageFloorModeV1::Required {
            match custody {
                CredentialReadCustodyV1::Ordinary => {
                    // Preserve the consuming ordinary owner/context boundary
                    // before the following mode canonicalization/native IO.
                    super::super::backend::confinement::require_owner(endpoint)?;
                }
                CredentialReadCustodyV1::Retained => {
                    self.confinement.capture_once(endpoint, custody)?;
                }
            }
        }
        match custody {
            CredentialReadCustodyV1::Ordinary => mode.revalidate(),
            CredentialReadCustodyV1::Retained => mode.revalidate_retaining(&mut self.mode),
        }
    }

    /// Borrows only the earliest actual reached binding or native error.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.binding.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.confinement.failure())
            .or_else(|| self.mode.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}

/// Describes one actual retained launch-presence observation before native IO.
pub(crate) fn mode_presence_receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as Dimension, ResourceVector};

    let memory = std::mem::size_of::<ModePresenceOriginalV1>()
        .checked_add(super::super::provisioning::canonical_currentness_work_bytes_v1()?)?
        .checked_add(super::super::provisioning::MAXIMUM_MODE_PATH_BYTES_V1.checked_mul(4)?)?
        .checked_add(4 * 258)?
        .checked_add(aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
            joined_path_receiving_bytes_for_lengths_v1(
                super::super::provisioning::MAXIMUM_MODE_PATH_BYTES_V1,
                super::super::provisioning::MAXIMUM_MODE_PATH_BYTES_V1,
            )?)?
        .checked_add(8 * 256)?;
    // One mode comparison21, two five-result raw confinement readers plus
    // their two bindings/whole13, and this binding/whole2:36 exact slots.
    let cells = super::super::provisioning::MODE_REVALIDATION_RESULT_CELLS_V1
        .checked_add(13)?
        .checked_add(2)?;
    Some(ResourceVector::ZERO
        .with(Dimension::MemoryBytes, u64::try_from(memory).ok()?)
        .with(Dimension::OpenFiles, 3)
        .with(Dimension::MetadataEntries, cells))
}
