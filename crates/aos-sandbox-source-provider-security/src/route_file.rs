//! Fixed protected SourceProvider route and peer policy.
//!
//! ```text
//! AOSPRTE1 || version:u16be=1 || reserved[6]=0 ||
//! route-id[16] || generation:u64be || digest[32] ||
//! provider-authority-id[16] || resource-namespace-digest[32] ||
//! capabilities:u8 || recursive:u8 || kernel-coupled:u8 || reserved[5]=0 ||
//! provider-uid:u32be || provider-gid:u32be || provider-cgroup-digest[32] ||
//! root-authority-id[16] || root-uid:u32be || root-gid:u32be ||
//! root-cgroup-digest[32]
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ProtectedRootMountPeerV1, ProtectedSourceProviderRouteV1,
};

use crate::SourceProviderSecurityError;
use crate::manifest::{decode_bool, read_array, read_u16, read_u64, require_zero};

/// Exact byte length of an `AOSPRTE1` route file.
pub const SOURCE_PROVIDER_ROUTE_FILE_BYTES: usize = 224;
const MAGIC: &[u8; 8] = b"AOSPRTE1";

/// Holds the two protected protocol policy projections in one exact route file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderRouteFileV1 {
    route: ProtectedSourceProviderRouteV1,
    root_mount_peer: ProtectedRootMountPeerV1,
    proof_capabilities: u8,
    allow_recursive: bool,
    allow_kernel_coupled: bool,
    root_mount_authority_id: [u8; 16],
    root_mount_uid: u32,
    root_mount_gid: u32,
    root_mount_cgroup_digest: ObjectDigest,
    exact: [u8; SOURCE_PROVIDER_ROUTE_FILE_BYTES],
}

impl SourceProviderRouteFileV1 {
    /// Decodes the exact canonical route file without granting provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for any malformed field or
    /// invalid protocol policy projection.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceProviderSecurityError> {
        if bytes.len() != SOURCE_PROVIDER_ROUTE_FILE_BYTES
            || &bytes[..8] != MAGIC
            || read_u16(bytes, 8)? != 1
        {
            return Err(SourceProviderSecurityError::format("route", "header"));
        }
        require_zero(bytes, 10, 16, "route", "header reserved")?;
        require_zero(bytes, 123, 128, "route", "capability reserved")?;
        let capabilities = bytes[120];
        if capabilities == 0 || capabilities & !0x0f != 0 {
            return Err(SourceProviderSecurityError::format(
                "route",
                "proof capabilities",
            ));
        }
        let allow_recursive = decode_bool(bytes[121], "route recursive")?;
        let allow_kernel_coupled = decode_bool(bytes[122], "route kernel coupled")?;
        let root_mount_authority_id = read_array(bytes, 168)?;
        let root_mount_uid = read_u32(bytes, 184)?;
        let root_mount_gid = read_u32(bytes, 188)?;
        let root_mount_cgroup_digest = ObjectDigest::from_bytes(read_array(bytes, 192)?);
        let route = ProtectedSourceProviderRouteV1::new(
            read_array(bytes, 16)?,
            read_u64(bytes, 32)?,
            ObjectDigest::from_bytes(read_array(bytes, 40)?),
            read_array(bytes, 72)?,
            ObjectDigest::from_bytes(read_array(bytes, 88)?),
            capabilities,
            allow_recursive,
            allow_kernel_coupled,
            read_u32(bytes, 128)?,
            read_u32(bytes, 132)?,
            ObjectDigest::from_bytes(read_array(bytes, 136)?),
        )
        .map_err(|_| SourceProviderSecurityError::format("route", "provider policy"))?;
        let root_mount_peer = ProtectedRootMountPeerV1::new(
            root_mount_authority_id,
            root_mount_uid,
            root_mount_gid,
            root_mount_cgroup_digest,
        )
        .map_err(|_| SourceProviderSecurityError::format("route", "Root Mount policy"))?;
        Ok(Self {
            route,
            root_mount_peer,
            proof_capabilities: capabilities,
            allow_recursive,
            allow_kernel_coupled,
            root_mount_authority_id,
            root_mount_uid,
            root_mount_gid,
            root_mount_cgroup_digest,
            exact: bytes
                .try_into()
                .map_err(|_| SourceProviderSecurityError::format("route", "canonical length"))?,
        })
    }

    /// Returns the exact canonical protected route-file bytes.
    #[must_use]
    pub const fn to_canonical_bytes(&self) -> [u8; SOURCE_PROVIDER_ROUTE_FILE_BYTES] {
        self.exact
    }

    /// Returns the protected provider route projection.
    #[must_use]
    pub const fn route(&self) -> &ProtectedSourceProviderRouteV1 {
        &self.route
    }

    /// Returns the protected Root Mount peer projection.
    #[must_use]
    pub const fn root_mount_peer(&self) -> &ProtectedRootMountPeerV1 {
        &self.root_mount_peer
    }

    pub(crate) const fn proof_capabilities(&self) -> u8 {
        self.proof_capabilities
    }

    pub(crate) const fn allow_recursive(&self) -> bool {
        self.allow_recursive
    }

    pub(crate) const fn allow_kernel_coupled(&self) -> bool {
        self.allow_kernel_coupled
    }

    pub(crate) const fn root_mount_authority_id(&self) -> [u8; 16] {
        self.root_mount_authority_id
    }

    pub(crate) const fn root_mount_uid(&self) -> u32 {
        self.root_mount_uid
    }

    pub(crate) const fn root_mount_gid(&self) -> u32 {
        self.root_mount_gid
    }

    pub(crate) const fn root_mount_cgroup_digest(&self) -> ObjectDigest {
        self.root_mount_cgroup_digest
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SourceProviderSecurityError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}
