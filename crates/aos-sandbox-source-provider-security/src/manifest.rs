//! Fixed protected SourceProvider security manifest.
//!
//! The format is exactly 752 bytes:
//!
//! ```text
//! AOSPSEC1 || version:u16be=1 || role:u8 || reserved[5]=0 ||
//! node-id[16] || security-domain-id[16] || protocol:1.0 ||
//! configuration-generation:u64be || trust-generation:u64be ||
//! trust-digest[32] || revocation-generation:u64be ||
//! revocation-digest[32] || route-id[16] || route-generation:u64be ||
//! route-digest[32] || capabilities:u8 || recursive:u8 ||
//! kernel-coupled:u8 || reserved[5]=0 || four signer-reference[120] ||
//! trust-file-sha256[32] || route-file-sha256[32] || reserved[4]=0
//! ```
//!
//! The signer order is RootMountHello, ProviderHello, RootMountRecord, then
//! ProviderOutcome. Decoding establishes canonical shape, not protected
//! provenance.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderKeyUsageV1, SourceProviderPeerRole, SourceProviderSigningKeyV1,
};

use crate::SourceProviderSecurityError;

/// Exact byte length of an `AOSPSEC1` manifest.
pub const SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES: usize = 752;
const MAGIC: &[u8; 8] = b"AOSPSEC1";
const FORMAT_VERSION: u16 = 1;
const SIGNER_BYTES: usize = 120;
const SIGNER_OFFSET: usize = 204;
/// Exact number of physically separated SourceProvider signing roles.
pub const SOURCE_PROVIDER_SECURITY_SIGNER_COUNT: usize = 4;

/// Names the role whose local secrets may be present in one protected directory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderSecurityRoleV1 {
    /// Root Mount owns the client hello and request-record keys.
    RootMount = 1,
    /// The provider owns the server hello and outcome keys.
    Provider = 2,
}

impl SourceProviderSecurityRoleV1 {
    pub(crate) const fn protocol(self) -> SourceProviderPeerRole {
        match self {
            Self::RootMount => SourceProviderPeerRole::RootMount,
            Self::Provider => SourceProviderPeerRole::Provider,
        }
    }

    const fn decode(value: u8) -> Result<Self, SourceProviderSecurityError> {
        match value {
            1 => Ok(Self::RootMount),
            2 => Ok(Self::Provider),
            _ => Err(SourceProviderSecurityError::format("manifest", "role")),
        }
    }
}

/// Models one exact nonauthorizing `AOSPSEC1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderSecurityManifestV1 {
    role: SourceProviderSecurityRoleV1,
    node_id: [u8; 16],
    security_domain_id: [u8; 16],
    configuration_generation: u64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    proof_capabilities: u8,
    allow_recursive: bool,
    allow_kernel_coupled: bool,
    signers: [SourceProviderSigningKeyV1; SOURCE_PROVIDER_SECURITY_SIGNER_COUNT],
    trust_file_sha256: [u8; 32],
    route_file_sha256: [u8; 32],
}

impl SourceProviderSecurityManifestV1 {
    /// Decodes the exact canonical manifest without granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for any wrong magic, version,
    /// reserved byte, sentinel, closed value, signer order, or collision.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceProviderSecurityError> {
        if bytes.len() != SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES {
            return Err(SourceProviderSecurityError::format("manifest", "length"));
        }
        if &bytes[..8] != MAGIC || read_u16(bytes, 8)? != FORMAT_VERSION {
            return Err(SourceProviderSecurityError::format("manifest", "header"));
        }
        require_zero(bytes, 11, 16, "manifest", "reserved header")?;
        if read_u16(bytes, 48)? != 1 || read_u16(bytes, 50)? != 0 {
            return Err(SourceProviderSecurityError::format("manifest", "protocol"));
        }
        require_zero(bytes, 199, 204, "manifest", "capability reserved")?;
        require_zero(bytes, 748, 752, "manifest", "trailing reserved")?;

        let proof_capabilities = bytes[196];
        if proof_capabilities == 0 || proof_capabilities & !0x0f != 0 {
            return Err(SourceProviderSecurityError::format(
                "manifest",
                "proof capabilities",
            ));
        }
        let signers = [
            decode_signer(&bytes[204..324], SourceProviderKeyUsageV1::RootMountHello)?,
            decode_signer(&bytes[324..444], SourceProviderKeyUsageV1::ProviderHello)?,
            decode_signer(&bytes[444..564], SourceProviderKeyUsageV1::RootMountRecord)?,
            decode_signer(&bytes[564..684], SourceProviderKeyUsageV1::ProviderOutcome)?,
        ];
        validate_signer_partition(&signers)?;

        let manifest = Self {
            role: SourceProviderSecurityRoleV1::decode(bytes[10])?,
            node_id: read_array(bytes, 16)?,
            security_domain_id: read_array(bytes, 32)?,
            configuration_generation: read_u64(bytes, 52)?,
            trust_generation: read_u64(bytes, 60)?,
            trust_digest: ObjectDigest::from_bytes(read_array(bytes, 68)?),
            revocation_generation: read_u64(bytes, 100)?,
            revocation_digest: ObjectDigest::from_bytes(read_array(bytes, 108)?),
            route_id: read_array(bytes, 140)?,
            route_generation: read_u64(bytes, 156)?,
            route_digest: ObjectDigest::from_bytes(read_array(bytes, 164)?),
            proof_capabilities,
            allow_recursive: decode_bool(bytes[197], "recursive")?,
            allow_kernel_coupled: decode_bool(bytes[198], "kernel coupled")?,
            signers,
            trust_file_sha256: read_array(bytes, 684)?,
            route_file_sha256: read_array(bytes, 716)?,
        };
        manifest.validate_sentinels()?;
        Ok(manifest)
    }

    /// Encodes the exact canonical manifest bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES] {
        let mut output = [0; SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES];
        output[..8].copy_from_slice(MAGIC);
        output[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        output[10] = self.role as u8;
        output[16..32].copy_from_slice(&self.node_id);
        output[32..48].copy_from_slice(&self.security_domain_id);
        output[48..50].copy_from_slice(&1u16.to_be_bytes());
        output[50..52].copy_from_slice(&0u16.to_be_bytes());
        output[52..60].copy_from_slice(&self.configuration_generation.to_be_bytes());
        output[60..68].copy_from_slice(&self.trust_generation.to_be_bytes());
        output[68..100].copy_from_slice(self.trust_digest.as_bytes());
        output[100..108].copy_from_slice(&self.revocation_generation.to_be_bytes());
        output[108..140].copy_from_slice(self.revocation_digest.as_bytes());
        output[140..156].copy_from_slice(&self.route_id);
        output[156..164].copy_from_slice(&self.route_generation.to_be_bytes());
        output[164..196].copy_from_slice(self.route_digest.as_bytes());
        output[196] = self.proof_capabilities;
        output[197] = u8::from(self.allow_recursive);
        output[198] = u8::from(self.allow_kernel_coupled);
        for (index, signer) in self.signers.iter().enumerate() {
            let start = SIGNER_OFFSET + index * SIGNER_BYTES;
            encode_signer(signer, &mut output[start..start + SIGNER_BYTES]);
        }
        output[684..716].copy_from_slice(&self.trust_file_sha256);
        output[716..748].copy_from_slice(&self.route_file_sha256);
        output
    }

    /// Returns the protected endpoint role.
    #[must_use]
    pub const fn role(&self) -> SourceProviderSecurityRoleV1 {
        self.role
    }

    /// Returns the protected node identity.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }

    /// Returns the protected security-domain identity.
    #[must_use]
    pub const fn security_domain_id(&self) -> [u8; 16] {
        self.security_domain_id
    }

    /// Returns the atomic protected-configuration generation.
    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// Returns the protected trust generation.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the protected trust digest.
    #[must_use]
    pub const fn trust_digest(&self) -> ObjectDigest {
        self.trust_digest
    }

    /// Returns the protected revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the protected revocation digest.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    /// Returns the protected route ID.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }

    /// Returns the protected route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.route_generation
    }

    /// Returns the protected route digest.
    #[must_use]
    pub const fn route_digest(&self) -> ObjectDigest {
        self.route_digest
    }

    /// Returns the closed proof-class capability mask.
    #[must_use]
    pub const fn proof_capabilities(&self) -> u8 {
        self.proof_capabilities
    }

    /// Reports whether recursive source use is enabled.
    #[must_use]
    pub const fn allow_recursive(&self) -> bool {
        self.allow_recursive
    }

    /// Reports whether kernel-coupled sources are enabled.
    #[must_use]
    pub const fn allow_kernel_coupled(&self) -> bool {
        self.allow_kernel_coupled
    }

    /// Returns the four role-ordered signer references.
    #[must_use]
    pub const fn signers(
        &self,
    ) -> &[SourceProviderSigningKeyV1; SOURCE_PROVIDER_SECURITY_SIGNER_COUNT] {
        &self.signers
    }

    /// Returns the exact protected trust-file SHA-256.
    #[must_use]
    pub const fn trust_file_sha256(&self) -> &[u8; 32] {
        &self.trust_file_sha256
    }

    /// Returns the exact protected route-file SHA-256.
    #[must_use]
    pub const fn route_file_sha256(&self) -> &[u8; 32] {
        &self.route_file_sha256
    }

    fn validate_sentinels(&self) -> Result<(), SourceProviderSecurityError> {
        let invalid = self.node_id == [0; 16]
            || self.security_domain_id == [0; 16]
            || self.configuration_generation == 0
            || self.trust_generation == 0
            || self.trust_digest == ObjectDigest::from_bytes([0; 32])
            || self.revocation_generation == 0
            || self.revocation_digest == ObjectDigest::from_bytes([0; 32])
            || self.route_id == [0; 16]
            || self.route_generation == 0
            || self.route_digest == ObjectDigest::from_bytes([0; 32])
            || self.trust_file_sha256 == [0; 32]
            || self.route_file_sha256 == [0; 32];
        if invalid {
            return Err(SourceProviderSecurityError::format("manifest", "sentinel"));
        }
        Ok(())
    }
}

fn validate_signer_partition(
    signers: &[SourceProviderSigningKeyV1; SOURCE_PROVIDER_SECURITY_SIGNER_COUNT],
) -> Result<(), SourceProviderSecurityError> {
    let root_authority = signers[0].authority_id();
    let provider_authority = signers[1].authority_id();
    let root_matches = signers[2].authority_id() == root_authority
        && signers[2].authority_generation() == signers[0].authority_generation()
        && signers[2].authority_digest() == signers[0].authority_digest();
    let provider_matches = signers[3].authority_id() == provider_authority
        && signers[3].authority_generation() == signers[1].authority_generation()
        && signers[3].authority_digest() == signers[1].authority_digest();
    let all_distinct = (0..SOURCE_PROVIDER_SECURITY_SIGNER_COUNT).all(|left| {
        (left + 1..SOURCE_PROVIDER_SECURITY_SIGNER_COUNT).all(|right| {
            signers[left].key_id() != signers[right].key_id()
                && signers[left].public_key_digest() != signers[right].public_key_digest()
        })
    });
    if root_authority == provider_authority || !root_matches || !provider_matches || !all_distinct {
        return Err(SourceProviderSecurityError::format(
            "manifest",
            "signer partition",
        ));
    }
    Ok(())
}

pub(crate) fn encode_signer(value: &SourceProviderSigningKeyV1, output: &mut [u8]) {
    output[..16].copy_from_slice(&value.authority_id());
    output[16..24].copy_from_slice(&value.authority_generation().to_be_bytes());
    output[24..56].copy_from_slice(value.authority_digest().as_bytes());
    output[56..72].copy_from_slice(&value.key_id());
    output[72..80].copy_from_slice(&value.key_generation().to_be_bytes());
    output[80..112].copy_from_slice(value.public_key_digest().as_bytes());
    output[112] = value.usage() as u8;
    output[113..].fill(0);
}

pub(crate) fn decode_signer(
    bytes: &[u8],
    expected_usage: SourceProviderKeyUsageV1,
) -> Result<SourceProviderSigningKeyV1, SourceProviderSecurityError> {
    if bytes.len() != SIGNER_BYTES || bytes[113..].iter().any(|value| *value != 0) {
        return Err(SourceProviderSecurityError::format("signer", "encoding"));
    }
    let usage = match bytes[112] {
        1 => SourceProviderKeyUsageV1::RootMountHello,
        2 => SourceProviderKeyUsageV1::ProviderHello,
        3 => SourceProviderKeyUsageV1::RootMountRecord,
        4 => SourceProviderKeyUsageV1::ProviderOutcome,
        _ => return Err(SourceProviderSecurityError::format("signer", "usage")),
    };
    if usage != expected_usage {
        return Err(SourceProviderSecurityError::format("signer", "order"));
    }
    SourceProviderSigningKeyV1::new(
        read_array(bytes, 0)?,
        read_u64(bytes, 16)?,
        ObjectDigest::from_bytes(read_array(bytes, 24)?),
        read_array(bytes, 56)?,
        read_u64(bytes, 72)?,
        ObjectDigest::from_bytes(read_array(bytes, 80)?),
        usage,
    )
    .map_err(|_| SourceProviderSecurityError::format("signer", "value"))
}

pub(crate) fn decode_bool(
    value: u8,
    field: &'static str,
) -> Result<bool, SourceProviderSecurityError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SourceProviderSecurityError::format(
            "protected record",
            field,
        )),
    }
}

pub(crate) fn require_zero(
    bytes: &[u8],
    start: usize,
    end: usize,
    object: &'static str,
    field: &'static str,
) -> Result<(), SourceProviderSecurityError> {
    if bytes
        .get(start..end)
        .is_none_or(|reserved| reserved.iter().any(|value| *value != 0))
    {
        return Err(SourceProviderSecurityError::format(object, field));
    }
    Ok(())
}

pub(crate) fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], SourceProviderSecurityError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(SourceProviderSecurityError::format(
            "protected record",
            "truncated field",
        ))
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SourceProviderSecurityError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SourceProviderSecurityError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

pub(crate) fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, SourceProviderSecurityError> {
    Ok(i64::from_be_bytes(read_array(bytes, offset)?))
}
