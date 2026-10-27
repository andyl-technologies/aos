//! Owns the closed twelve-member startup credential DATA and original bounds.
//!
//! Members select existing literal inputs only. These quotes grant no file,
//! writer, funding account or selected receiving authority.

use super::RootPolicyStartupDeploymentV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

/// Selects one existing normal-Root startup credential, never a caller path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootStartupCredentialMemberV1 {
    /// Selects the independent deployment signer credential.
    DeploymentKey,
    /// Selects the signed deployment-head packet.
    DeploymentHead,
    /// Selects the exact node-policy JSON input.
    Node,
    /// Selects the exact site-policy JSON input.
    Site,
    /// Selects the exact backend-capability JSON input.
    Backend,
    /// Selects the exact endpoint/destination JSON input.
    Catalogs,
    /// Selects the independent Project signer credential.
    ProjectKey,
    /// Selects the optional explicit V2 Project-head packet.
    ProjectHead,
    /// Selects the optional explicit V2 Project policy input.
    ProjectInput,
    /// Selects the optional Cache-owner readback signer credential.
    CachePin,
    /// Selects the optional Controller-hold readback signer credential.
    ControllerPin,
    /// Selects the optional Source-hold readback signer credential.
    SourcePin,
}

impl RootStartupCredentialMemberV1 {
    /// Lists the finite input destinations in their actual read order.
    pub const ALL: [Self; 12] = [
        Self::DeploymentKey,
        Self::DeploymentHead,
        Self::Node,
        Self::Site,
        Self::Backend,
        Self::Catalogs,
        Self::ProjectKey,
        Self::ProjectHead,
        Self::ProjectInput,
        Self::CachePin,
        Self::ControllerPin,
        Self::SourcePin,
    ];

    /// Returns the literal basename inside the existing service credential root.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DeploymentKey => "deployment-public-key",
            Self::DeploymentHead => "deployment-head.packet",
            Self::Node => "node-policy.json",
            Self::Site => "site-policy.json",
            Self::Backend => "backend-capabilities.json",
            Self::Catalogs => "catalogs.json",
            Self::ProjectKey => "project-public-key",
            Self::ProjectHead => "project-head-v2.packet",
            Self::ProjectInput => "project-layer-v2.json",
            Self::CachePin => "cache-owner-readback-public-key",
            Self::ControllerPin => "controller-hold-public-key",
            Self::SourcePin => "source-hold-public-key",
        }
    }

    /// Returns the unchanged bounded input length selected by the actual schema.
    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        match self {
            Self::DeploymentKey
            | Self::ProjectKey
            | Self::CachePin
            | Self::ControllerPin
            | Self::SourcePin => 80,
            Self::DeploymentHead => 224,
            Self::Node | Self::Site | Self::Backend | Self::Catalogs => 64 * 1024,
            Self::ProjectHead => 328,
            Self::ProjectInput => 3 * 1024,
        }
    }

    /// Returns the stable fixed destination index without allocating metadata.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::DeploymentKey => 0,
            Self::DeploymentHead => 1,
            Self::Node => 2,
            Self::Site => 3,
            Self::Backend => 4,
            Self::Catalogs => 5,
            Self::ProjectKey => 6,
            Self::ProjectHead => 7,
            Self::ProjectInput => 8,
            Self::CachePin => 9,
            Self::ControllerPin => 10,
            Self::SourcePin => 11,
        }
    }
}

/// Reports checked overflow in the unchanged closed credential DATA recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("fixed Root credential receiving representation overflowed")]
pub struct RootStartupCredentialGeometryErrorV1;

/// Quotes the existing raw/decoded startup representation before input reads.
///
/// # Errors
/// Refuses checked overflow without choosing a cheaper credential recipe.
pub fn fixed_root_credential_demand_v1()
-> Result<ResourceVector, RootStartupCredentialGeometryErrorV1> {
    let error = || RootStartupCredentialGeometryErrorV1;
    let mut raw = 0usize;
    for member in RootStartupCredentialMemberV1::ALL {
        raw = raw
            .checked_add(member.maximum_bytes().checked_add(1).ok_or_else(error)?)
            .ok_or_else(error)?;
    }
    let decoding = super::fixed_root_startup_decoding_bytes_v1().ok_or_else(error)?;
    // The old bounded-buffer, decoded-source and scratch recipe is unchanged.
    // New canonical token/error return planes are explicit additional Memory.
    let memory = raw
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(decoding))
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .and_then(|bytes| {
            bytes.checked_add(RootPolicyStartupDeploymentV1::receiving_control_bytes_v1()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<Result<ResourceVector, RootStartupCredentialGeometryErrorV1>>()
                    .checked_mul(2)?,
            )
        })
        .ok_or_else(error)?;
    let memory = u64::try_from(memory).map_err(|_| error())?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::OpenFiles, 12)
        .with(D::MetadataEntries, u64::try_from(raw).map_err(|_| error())?)
        .with(D::PublicationStagingBytes, memory)
        .with(D::OutputBytes, memory))
}
