//! Nonauthorizing guest execution identity readback from a retained sandbox spec.
//!
//! The signed assignment names a sandbox specification, whose identity profile
//! bounds the guest-visible IDs that can be mapped into a private user namespace.
//! This readback checks that bound against one canonical execution credential
//! projection. It does not select or authorize the UID, GID, or supplementary
//! groups: the current portable policy has no such field, so a separate
//! protected policy producer is required before Host Authorize.

use aos_sandbox_core::model::spec::IdentityProfile;
use aos_sandbox_core::{ExecutionCredentialsV1, ObjectDescriptor};

use crate::Journal;
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::sandbox_spec_state::{self, SandboxSpecStateError};

/// Holds a checked mapping projection from an exact retained sandbox spec.
///
/// This value only proves that the IDs fit the spec's private namespace range.
/// It is not an execution authorization or a current-assignment observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGuestIdentityReadbackV1 {
    sandbox_spec: ObjectDescriptor,
    credentials: ExecutionCredentialsV1,
    id_range_size: u32,
}

impl ExecutionGuestIdentityReadbackV1 {
    /// Borrows the exact descriptor used for the protected spec readback.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Borrows the exact canonical credential projection that was checked.
    #[must_use]
    pub const fn credentials(&self) -> &ExecutionCredentialsV1 {
        &self.credentials
    }

    /// Returns the private namespace's count of guest-visible IDs.
    #[must_use]
    pub const fn id_range_size(&self) -> u32 {
        self.id_range_size
    }
}

/// Reports missing or incompatible guest identity mapping evidence.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionGuestIdentityReadbackErrorV1 {
    /// The nominated descriptor has no retained protected specification.
    #[error("sandbox specification is absent from protected custody")]
    MissingSandboxSpec,
    /// A host-identity profile cannot establish a private guest mapping.
    #[error("sandbox identity profile has no private guest ID mapping")]
    NoPrivateMapping,
    /// At least one requested guest ID lies outside the assigned range.
    #[error("execution credential ID is outside the sandbox identity range")]
    UnmappedCredential,
    /// Protected specification state is malformed or cannot be read.
    #[error(transparent)]
    SandboxSpec(#[from] SandboxSpecStateError),
}

/// Reads a retained sandbox spec and checks an execution credential projection.
///
/// The target supplies the signed assignment's exact spec descriptor. It still
/// needs a currentness recheck at any effect boundary. A passing readback does
/// not establish who may execute with these credentials or authorize Host
/// dispatch.
///
/// # Errors
///
/// Returns [`ExecutionGuestIdentityReadbackErrorV1`] for absent or corrupt
/// protected state, a host-identity profile, or any unmapped UID or GID.
pub fn read_execution_guest_identity_v1(
    journal: &Journal,
    target: &CurrentAssignmentTarget,
    credentials: &ExecutionCredentialsV1,
) -> Result<ExecutionGuestIdentityReadbackV1, ExecutionGuestIdentityReadbackErrorV1> {
    read_from_spec(journal, target.sandbox_spec(), credentials)
}

fn read_from_spec(
    journal: &Journal,
    sandbox_spec: &ObjectDescriptor,
    credentials: &ExecutionCredentialsV1,
) -> Result<ExecutionGuestIdentityReadbackV1, ExecutionGuestIdentityReadbackErrorV1> {
    let retained = sandbox_spec_state::get(journal, sandbox_spec)?
        .ok_or(ExecutionGuestIdentityReadbackErrorV1::MissingSandboxSpec)?;
    let id_range_size = validate_mapping(retained.spec().identity_profile(), credentials)?;

    Ok(ExecutionGuestIdentityReadbackV1 {
        sandbox_spec: sandbox_spec.clone(),
        credentials: credentials.clone(),
        id_range_size,
    })
}

fn validate_mapping(
    profile: &IdentityProfile,
    credentials: &ExecutionCredentialsV1,
) -> Result<u32, ExecutionGuestIdentityReadbackErrorV1> {
    let IdentityProfile::PrivateUserns { id_range_size, .. } = profile else {
        return Err(ExecutionGuestIdentityReadbackErrorV1::NoPrivateMapping);
    };
    let id_range_size = id_range_size.get();
    if credentials.user_id() >= id_range_size
        || credentials.primary_group_id() >= id_range_size
        || credentials
            .supplementary_group_ids()
            .iter()
            .any(|group_id| *group_id >= id_range_size)
    {
        return Err(ExecutionGuestIdentityReadbackErrorV1::UnmappedCredential);
    }

    Ok(id_range_size)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_sandbox_core::model::spec::UnmappableIdentityPolicy;
    use tempfile::TempDir;

    use super::*;

    fn private_profile(range: u32) -> IdentityProfile {
        IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(range).unwrap(),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        }
    }

    #[test]
    fn accepts_exact_upper_boundary_with_supplementary_groups() {
        let credentials = ExecutionCredentialsV1::new(7, 5, vec![0, 9]).unwrap();

        assert_eq!(
            validate_mapping(&private_profile(10), &credentials).unwrap(),
            10
        );
    }

    #[test]
    fn rejects_each_unmapped_credential_dimension() {
        let profile = private_profile(10);
        for credentials in [
            ExecutionCredentialsV1::new(10, 1, vec![]).unwrap(),
            ExecutionCredentialsV1::new(1, 10, vec![]).unwrap(),
            ExecutionCredentialsV1::new(1, 2, vec![10]).unwrap(),
        ] {
            assert!(matches!(
                validate_mapping(&profile, &credentials),
                Err(ExecutionGuestIdentityReadbackErrorV1::UnmappedCredential)
            ));
        }
    }

    #[test]
    fn host_identity_profile_has_no_private_mapping() {
        let credentials = ExecutionCredentialsV1::new(0, 0, vec![]).unwrap();
        let profile = IdentityProfile::Host {
            required_features: Vec::new(),
        };

        assert!(matches!(
            validate_mapping(&profile, &credentials),
            Err(ExecutionGuestIdentityReadbackErrorV1::NoPrivateMapping)
        ));
    }

    #[test]
    fn readback_requires_and_reopens_exact_protected_specification() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("controller.journal"),
            Default::default(),
        )
        .unwrap();
        let publication = sandbox_spec_state::slot_spec_publication_for_test(Vec::new(), 4);
        let descriptor = publication.descriptor().clone();
        let credentials = ExecutionCredentialsV1::new(1000, 1000, vec![1, 2000]).unwrap();

        assert!(matches!(
            read_from_spec(&journal, &descriptor, &credentials),
            Err(ExecutionGuestIdentityReadbackErrorV1::MissingSandboxSpec)
        ));

        sandbox_spec_state::commit(&mut journal, publication).unwrap();
        let readback = read_from_spec(&journal, &descriptor, &credentials).unwrap();
        assert_eq!(readback.sandbox_spec(), &descriptor);
        assert_eq!(readback.credentials(), &credentials);
        assert_eq!(readback.id_range_size(), 65_536);

        journal.compact().unwrap();
        let readback = read_from_spec(&journal, &descriptor, &credentials).unwrap();
        assert_eq!(readback.credentials(), &credentials);
    }
}
