//! Retains both recurring reads of Root's actual independent public issuers.
//!
//! Each reached directory, file and bounded read remains in the destination
//! before the next fallible operation. The original Root roster supplies the
//! two private pinned originals; callers cannot nominate a path or public key.

use super::*;
use crate::systemd_credentials::{
    CredentialFailureClass, CredentialOperation, CredentialReadProfile, DirectoryCustody,
    open_directory_with_custody, open_read_credential_with_profile, require_present_credential,
};

struct IssuerReadbackSlot {
    ancestors: CredentialAncestors,
    named: CredentialReadSlot,
}

impl IssuerReadbackSlot {
    fn new() -> Self {
        Self {
            ancestors: CredentialAncestors::new(),
            named: CredentialReadSlot::new(),
        }
    }
}

/// Retains one recurring recheck of the same two fixed Root issuer originals.
///
/// An enclosing actual Root owner pays this finite native recipe before the
/// inert constructor. A failed readback stays with that same enclosing owner;
/// this value neither replaces the originals nor returns a role capability.
pub struct RootCurrentIssuerReadbackOriginalV1 {
    slots: [IssuerReadbackSlot; 2],
    outcome: Option<CredentialResult<()>>,
    entered: bool,
    reentered: bool,
}

impl RootCurrentIssuerReadbackOriginalV1 {
    /// Creates vacant native destinations without observation or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| IssuerReadbackSlot::new()),
            outcome: None,
            entered: false,
            reentered: false,
        }
    }

    /// Bounds incremental backing and native slots for this fixed readback.
    ///
    /// The enclosing constructor owns this type's inline representation. This
    /// supplier adds the two bounded read buffers and ten real native objects.
    #[must_use]
    pub fn observation_demand_v1() -> Option<ResourceVector> {
        let buffers = 2_u64.checked_mul(81)?.checked_mul(4)?;
        let memory = buffers.checked_add(10 * 4096)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::OpenFiles, 10)
                .with(D::MetadataEntries, 10)
                .with(D::OutputBytes, buffers),
        )
    }

    /// Rechecks the actual captured Root issuers through the shared leaf reader.
    ///
    /// The two original name/content comparisons retain their original order.
    /// This closed recipe accepts neither supplied paths nor another roster.
    ///
    /// # Errors
    /// Returns a marker while the first actual native or name/content cause
    /// and every reached directory, descriptor and read remain in this value.
    pub fn observe_once(
        &mut self,
        original: &RootCurrentIssuerCredentialCustodyV1,
    ) -> Result<(), ()> {
        if self.entered {
            self.reentered = true;
            return Err(());
        }
        self.entered = true;
        self.outcome = Some((|| {
            if original.bytes().is_none() {
                return Err(credential_state_rejected());
            }
            for (index, slot) in self.slots.iter_mut().enumerate() {
                let public = original.originals[index]
                    .public
                    .as_ref()
                    .ok_or_else(credential_state_rejected)?;
                if rustix::process::geteuid().as_raw() != public.uid {
                    return Err(ControllerNixPublicCredentialErrorV1::rejected(
                        CredentialFailureClass::Stale,
                        CredentialOperation::DirectoryProvenance,
                    ));
                }
                open_directory_with_custody(
                    &public.path,
                    public.uid,
                    &mut DirectoryCustody::Resident(&mut slot.ancestors),
                )?;
                let directory = slot.ancestors.directory()?;
                let stat = rustix::fs::fstat(directory).map_err(|cause| {
                    ControllerNixPublicCredentialErrorV1::io(
                        CredentialFailureClass::Stale,
                        CredentialOperation::DirectoryMetadata,
                        cause,
                    )
                })?;
                if (stat.st_dev, stat.st_ino) != public.directory_identity {
                    return Err(ControllerNixPublicCredentialErrorV1::rejected(
                        CredentialFailureClass::Stale,
                        CredentialOperation::DirectoryProvenance,
                    ));
                }
                let identity = require_present_credential(open_read_credential_with_profile(
                    directory,
                    NAMES[index],
                    public.uid,
                    CredentialReadProfile::Ordinary(MAXIMUM_BYTES[index]),
                    &mut slot.named,
                )?)?;
                if identity != public.file_identity
                    || slot.named.bytes.as_ref().map(|bytes| bytes.as_slice())
                        != Some(public.bytes())
                {
                    return Err(ControllerNixPublicCredentialErrorV1::rejected(
                        CredentialFailureClass::Stale,
                        CredentialOperation::FileChanged,
                    ));
                }
            }
            Ok(())
        })());
        if matches!(self.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Borrows the original first native refusal without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.outcome
            .as_ref()
            .and_then(|outcome| outcome.as_ref().err())
    }
}

impl Default for RootCurrentIssuerReadbackOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}
