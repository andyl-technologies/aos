//! Pure workspace-root ownership and mode policy.
//!
//! A newly created workspace has one portable, unshifted root shape. A clone
//! instead preserves the exact portable root metadata authenticated for its
//! source snapshot. This module only validates and canonicalizes that policy;
//! it performs no filesystem observation or mutation.
//!
//! ```text
//! AOSSRP01 | version:u16 | kind:u8 | reserved:u8
//! source-snapshot-guid:u64 | uid:u32 | gid:u32 | mode:u16 | reserved:u16
//! source-metadata-commitment:32
//! ```
//!
//! The source metadata commitment is opaque input here. The future protected
//! resolver must authenticate a canonical source record, recompute
//! `SHA-256("aos.sandbox.storage.snapshot-root-metadata.v1\0" ||
//! source-snapshot-guid:u64be || uid:u32be || gid:u32be || mode:u16be)`, and
//! require those decoded fields to equal the fields passed to
//! [`WorkspaceRootPolicyV1::clone_preserve`]. This pure constructor rejects
//! sentinels and binds both values; it does not establish that cryptographic
//! linkage on the resolver's behalf.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSSRP01";
const VERSION: u16 = 1;
const CREATE_INITIALIZE_KIND: u8 = 1;
const CLONE_PRESERVE_KIND: u8 = 2;
const FIXED_CANONICAL_BYTES: usize = 64;
const MAXIMUM_PORTABLE_MODE: u32 = 0o7777;
const PORTABLE_ID_SENTINEL: u32 = u32::MAX;
const SNAPSHOT_ROOT_METADATA_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-root-metadata.v1\0";
const ROOT_POLICY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-root-policy.v1\0";

const CREATE_ROOT_UID: u32 = 0;
const CREATE_ROOT_GID: u32 = 0;
const CREATE_ROOT_MODE: u16 = 0o755;

/// Reports a workspace-root policy that cannot be represented or enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum WorkspaceRootPolicyError {
    /// A portable UID or GID uses the kernel's invalid all-ones sentinel.
    #[error("workspace-root UID and GID must not use the all-ones sentinel")]
    ReservedPortableIdentity,
    /// A mode contains file-type or other bits outside the portable low 12 bits.
    #[error("workspace-root mode must contain only permission and special mode bits")]
    InvalidMode,
    /// A clone source snapshot uses the reserved zero GUID.
    #[error("clone source snapshot GUID must not be zero")]
    InvalidSourceSnapshotGuid,
    /// A clone source metadata commitment uses the reserved zero digest.
    #[error("clone source metadata commitment must not be zero")]
    InvalidSourceMetadataCommitment,
    /// Observed clone attributes differ from the authenticated source attributes.
    #[error("clone root attributes do not match authenticated source metadata")]
    CloneMetadataMismatch,
    /// Canonical bytes have the wrong length, magic, reserved fields, or shape.
    #[error("workspace-root policy encoding is malformed or noncanonical")]
    MalformedEncoding,
    /// Canonical bytes use an unsupported format version.
    #[error("workspace-root policy encoding version is unsupported")]
    UnsupportedEncodingVersion,
}

/// Stores one portable, unshifted workspace-root UID, GID, and mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortableRootAttributesV1 {
    uid: u32,
    gid: u32,
    mode: u16,
}

impl PortableRootAttributesV1 {
    /// Validates portable root attributes without applying an identity map.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceRootPolicyError`] for the all-ones UID/GID sentinel
    /// or mode bits outside the portable permission and special-bit mask.
    pub(crate) fn new(uid: u32, gid: u32, mode: u32) -> Result<Self, WorkspaceRootPolicyError> {
        if uid == PORTABLE_ID_SENTINEL || gid == PORTABLE_ID_SENTINEL {
            return Err(WorkspaceRootPolicyError::ReservedPortableIdentity);
        }
        if mode > MAXIMUM_PORTABLE_MODE {
            return Err(WorkspaceRootPolicyError::InvalidMode);
        }

        Ok(Self {
            uid,
            gid,
            mode: mode as u16,
        })
    }

    /// Returns the exact unshifted portable UID.
    pub(crate) const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the exact unshifted portable GID.
    pub(crate) const fn gid(self) -> u32 {
        self.gid
    }

    /// Returns the exact portable permission and special mode bits.
    pub(crate) const fn mode(self) -> u16 {
        self.mode
    }
}

/// Selects whether a worker may initialize or must preserve root attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceRootPolicyV1 {
    kind: WorkspaceRootPolicyKindV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceRootPolicyKindV1 {
    /// Initializes a fresh dataset root to portable UID 0, GID 0, and mode 0755.
    CreateInitialize,
    /// Preserves metadata authenticated for one exact source snapshot.
    ClonePreserve {
        source_snapshot_guid: u64,
        root_attributes: PortableRootAttributesV1,
        source_metadata_commitment: ObjectDigest,
    },
}

impl WorkspaceRootPolicyV1 {
    /// Constructs the fixed root policy for a newly created dataset.
    pub(crate) const fn create_initialize() -> Self {
        Self {
            kind: WorkspaceRootPolicyKindV1::CreateInitialize,
        }
    }

    /// Binds clone root attributes to one authenticated source snapshot.
    ///
    /// `source_metadata_commitment` is opaque at this boundary. The protected
    /// resolver is responsible for authenticating its canonical source record
    /// under the module-level domain/preimage contract and matching every
    /// decoded field before calling this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceRootPolicyError`] when the source snapshot GUID or
    /// source metadata commitment uses its reserved zero sentinel.
    pub(crate) fn clone_preserve(
        source_snapshot_guid: u64,
        root_attributes: PortableRootAttributesV1,
        source_metadata_commitment: ObjectDigest,
    ) -> Result<Self, WorkspaceRootPolicyError> {
        if source_snapshot_guid == 0 {
            return Err(WorkspaceRootPolicyError::InvalidSourceSnapshotGuid);
        }
        if source_metadata_commitment.as_bytes() == &[0; 32] {
            return Err(WorkspaceRootPolicyError::InvalidSourceMetadataCommitment);
        }

        Ok(Self {
            kind: WorkspaceRootPolicyKindV1::ClonePreserve {
                source_snapshot_guid,
                root_attributes,
                source_metadata_commitment,
            },
        })
    }

    /// Reports whether this is the exact fixed Create initialization policy.
    pub(crate) const fn is_create_initialize(self) -> bool {
        matches!(self.kind, WorkspaceRootPolicyKindV1::CreateInitialize)
    }

    /// Returns the exact portable attributes required at the workspace root.
    pub(crate) const fn root_attributes(self) -> PortableRootAttributesV1 {
        match self.kind {
            WorkspaceRootPolicyKindV1::CreateInitialize => PortableRootAttributesV1 {
                uid: CREATE_ROOT_UID,
                gid: CREATE_ROOT_GID,
                mode: CREATE_ROOT_MODE,
            },
            WorkspaceRootPolicyKindV1::ClonePreserve {
                root_attributes, ..
            } => root_attributes,
        }
    }

    /// Returns the exact source snapshot GUID for clone preservation.
    pub(crate) const fn source_snapshot_guid(self) -> Option<u64> {
        match self.kind {
            WorkspaceRootPolicyKindV1::CreateInitialize => None,
            WorkspaceRootPolicyKindV1::ClonePreserve {
                source_snapshot_guid,
                ..
            } => Some(source_snapshot_guid),
        }
    }

    /// Returns the approved compact source-root metadata commitment.
    pub(crate) const fn source_metadata_commitment(self) -> Option<ObjectDigest> {
        match self.kind {
            WorkspaceRootPolicyKindV1::CreateInitialize => None,
            WorkspaceRootPolicyKindV1::ClonePreserve {
                source_metadata_commitment,
                ..
            } => Some(source_metadata_commitment),
        }
    }

    /// Classifies an observed root without performing filesystem mutation.
    ///
    /// Create policy permits normalization to its fixed portable attributes.
    /// Clone policy permits only exact preservation of authenticated source
    /// attributes, including set-ID bits.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceRootPolicyError::CloneMetadataMismatch`] when a
    /// clone root differs from the authenticated source attributes.
    pub(crate) fn classify_observed_root(
        self,
        observed: PortableRootAttributesV1,
    ) -> Result<WorkspaceRootDispositionV1, WorkspaceRootPolicyError> {
        let required = self.root_attributes();

        match self.kind {
            WorkspaceRootPolicyKindV1::CreateInitialize if observed == required => {
                Ok(WorkspaceRootDispositionV1::AlreadyConforming)
            }
            WorkspaceRootPolicyKindV1::CreateInitialize => {
                Ok(WorkspaceRootDispositionV1::Initialize(required))
            }
            WorkspaceRootPolicyKindV1::ClonePreserve { .. } if observed == required => {
                Ok(WorkspaceRootDispositionV1::PreserveAuthenticated)
            }
            WorkspaceRootPolicyKindV1::ClonePreserve { .. } => {
                Err(WorkspaceRootPolicyError::CloneMetadataMismatch)
            }
        }
    }

    /// Encodes the policy in its fixed-width canonical form.
    pub(crate) fn canonical_bytes(self) -> [u8; FIXED_CANONICAL_BYTES] {
        let mut bytes = [0_u8; FIXED_CANONICAL_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());

        match self.kind {
            WorkspaceRootPolicyKindV1::CreateInitialize => {
                bytes[10] = CREATE_INITIALIZE_KIND;
                encode_attributes(&mut bytes, self.root_attributes());
            }
            WorkspaceRootPolicyKindV1::ClonePreserve {
                source_snapshot_guid,
                root_attributes,
                source_metadata_commitment,
            } => {
                bytes[10] = CLONE_PRESERVE_KIND;
                bytes[12..20].copy_from_slice(&source_snapshot_guid.to_be_bytes());
                encode_attributes(&mut bytes, root_attributes);
                bytes[32..64].copy_from_slice(source_metadata_commitment.as_bytes());
            }
        }

        bytes
    }

    /// Returns a domain-separated digest of the exact policy bytes.
    pub(crate) fn commitment(self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(ROOT_POLICY_DIGEST_DOMAIN);
        hasher.update(self.canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Revalidates the policy through its strict canonical representation.
    pub(crate) fn validate(self) -> Result<(), WorkspaceRootPolicyError> {
        if Self::from_canonical_bytes(&self.canonical_bytes())? == self {
            Ok(())
        } else {
            Err(WorkspaceRootPolicyError::MalformedEncoding)
        }
    }

    #[cfg(test)]
    pub(crate) const fn invalid_clone_for_test(
        source_snapshot_guid: u64,
        root_attributes: PortableRootAttributesV1,
    ) -> Self {
        Self {
            kind: WorkspaceRootPolicyKindV1::ClonePreserve {
                source_snapshot_guid,
                root_attributes,
                source_metadata_commitment: ObjectDigest::from_bytes([0; 32]),
            },
        }
    }

    /// Reconstructs a typed policy from exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceRootPolicyError`] for malformed, noncanonical, or
    /// unsupported bytes and for invalid clone identities or metadata.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WorkspaceRootPolicyError> {
        if bytes.len() != FIXED_CANONICAL_BYTES || &bytes[..8] != MAGIC {
            return Err(WorkspaceRootPolicyError::MalformedEncoding);
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != VERSION {
            return Err(WorkspaceRootPolicyError::UnsupportedEncodingVersion);
        }
        if bytes[11] != 0 || bytes[30..32] != [0, 0] {
            return Err(WorkspaceRootPolicyError::MalformedEncoding);
        }

        let source_snapshot_guid = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| WorkspaceRootPolicyError::MalformedEncoding)?,
        );
        let root_attributes = decode_attributes(bytes)?;
        let source_metadata_commitment = ObjectDigest::from_bytes(
            bytes[32..64]
                .try_into()
                .map_err(|_| WorkspaceRootPolicyError::MalformedEncoding)?,
        );

        let policy = match bytes[10] {
            CREATE_INITIALIZE_KIND
                if source_snapshot_guid == 0
                    && root_attributes
                        == PortableRootAttributesV1 {
                            uid: CREATE_ROOT_UID,
                            gid: CREATE_ROOT_GID,
                            mode: CREATE_ROOT_MODE,
                        }
                    && source_metadata_commitment.as_bytes() == &[0; 32] =>
            {
                Self::create_initialize()
            }
            CREATE_INITIALIZE_KIND => {
                return Err(WorkspaceRootPolicyError::MalformedEncoding);
            }
            CLONE_PRESERVE_KIND => Self::clone_preserve(
                source_snapshot_guid,
                root_attributes,
                source_metadata_commitment,
            )?,
            _ => return Err(WorkspaceRootPolicyError::MalformedEncoding),
        };

        if policy.canonical_bytes() != bytes {
            return Err(WorkspaceRootPolicyError::MalformedEncoding);
        }

        Ok(policy)
    }
}

/// Commits the approved compact source-root metadata preimage for clone policy.
pub(crate) fn snapshot_root_metadata_commitment(
    source_snapshot_guid: u64,
    root_attributes: PortableRootAttributesV1,
) -> Result<ObjectDigest, WorkspaceRootPolicyError> {
    if source_snapshot_guid == 0 {
        return Err(WorkspaceRootPolicyError::InvalidSourceSnapshotGuid);
    }

    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_ROOT_METADATA_DOMAIN);
    hasher.update(source_snapshot_guid.to_be_bytes());
    hasher.update(root_attributes.uid().to_be_bytes());
    hasher.update(root_attributes.gid().to_be_bytes());
    hasher.update(root_attributes.mode().to_be_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Describes the only pure attribute action admitted by a root policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceRootDispositionV1 {
    /// A create root already has the fixed portable attributes.
    AlreadyConforming,
    /// A create root must be normalized to the enclosed portable attributes.
    Initialize(PortableRootAttributesV1),
    /// A clone root exactly preserves its authenticated source attributes.
    PreserveAuthenticated,
}

fn encode_attributes(
    bytes: &mut [u8; FIXED_CANONICAL_BYTES],
    attributes: PortableRootAttributesV1,
) {
    bytes[20..24].copy_from_slice(&attributes.uid().to_be_bytes());
    bytes[24..28].copy_from_slice(&attributes.gid().to_be_bytes());
    bytes[28..30].copy_from_slice(&attributes.mode().to_be_bytes());
}

fn decode_attributes(bytes: &[u8]) -> Result<PortableRootAttributesV1, WorkspaceRootPolicyError> {
    let uid = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| WorkspaceRootPolicyError::MalformedEncoding)?,
    );
    let gid = u32::from_be_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| WorkspaceRootPolicyError::MalformedEncoding)?,
    );
    let mode = u16::from_be_bytes(
        bytes[28..30]
            .try_into()
            .map_err(|_| WorkspaceRootPolicyError::MalformedEncoding)?,
    );

    PortableRootAttributesV1::new(uid, gid, u32::from(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    #[test]
    fn create_policy_is_fixed_and_normalizes_only_to_portable_root() {
        let policy = WorkspaceRootPolicyV1::create_initialize();
        let expected = PortableRootAttributesV1::new(0, 0, 0o755).unwrap();
        let observed = PortableRootAttributesV1::new(65_536, 65_536, 0o2770).unwrap();

        assert_eq!(policy.root_attributes(), expected);
        assert_eq!(
            policy.classify_observed_root(expected),
            Ok(WorkspaceRootDispositionV1::AlreadyConforming)
        );
        assert_eq!(
            policy.classify_observed_root(observed),
            Ok(WorkspaceRootDispositionV1::Initialize(expected))
        );
    }

    #[test]
    fn clone_policy_preserves_root_identities_and_set_id_bits_exactly() {
        let source_attributes = PortableRootAttributesV1::new(501, 20, 0o6750).unwrap();
        let policy =
            WorkspaceRootPolicyV1::clone_preserve(41, source_attributes, digest(7)).unwrap();

        assert_eq!(policy.root_attributes(), source_attributes);
        assert_eq!(policy.root_attributes().mode(), 0o6750);
        assert_eq!(
            policy.classify_observed_root(source_attributes),
            Ok(WorkspaceRootDispositionV1::PreserveAuthenticated)
        );

        let changed_mode = PortableRootAttributesV1::new(501, 20, 0o750).unwrap();
        assert_eq!(
            policy.classify_observed_root(changed_mode),
            Err(WorkspaceRootPolicyError::CloneMetadataMismatch)
        );

        let changed_uid = PortableRootAttributesV1::new(502, 20, 0o6750).unwrap();
        assert_eq!(
            policy.classify_observed_root(changed_uid),
            Err(WorkspaceRootPolicyError::CloneMetadataMismatch)
        );

        let changed_gid = PortableRootAttributesV1::new(501, 21, 0o6750).unwrap();
        assert_eq!(
            policy.classify_observed_root(changed_gid),
            Err(WorkspaceRootPolicyError::CloneMetadataMismatch)
        );
    }

    #[test]
    fn portable_identity_sentinels_and_mode_bounds_are_closed() {
        assert_eq!(
            PortableRootAttributesV1::new(u32::MAX, 0, 0),
            Err(WorkspaceRootPolicyError::ReservedPortableIdentity)
        );
        assert_eq!(
            PortableRootAttributesV1::new(0, u32::MAX, 0),
            Err(WorkspaceRootPolicyError::ReservedPortableIdentity)
        );
        assert!(PortableRootAttributesV1::new(0, 0, 0o7777).is_ok());
        assert_eq!(
            PortableRootAttributesV1::new(0, 0, 0o10000),
            Err(WorkspaceRootPolicyError::InvalidMode)
        );
    }

    #[test]
    fn clone_source_identities_must_be_nonzero() {
        let attributes = PortableRootAttributesV1::new(0, 0, 0o755).unwrap();

        assert_eq!(
            WorkspaceRootPolicyV1::clone_preserve(0, attributes, digest(1)),
            Err(WorkspaceRootPolicyError::InvalidSourceSnapshotGuid)
        );
        assert_eq!(
            WorkspaceRootPolicyV1::clone_preserve(1, attributes, ObjectDigest::from_bytes([0; 32]),),
            Err(WorkspaceRootPolicyError::InvalidSourceMetadataCommitment)
        );
    }

    #[test]
    fn canonical_encoding_is_fixed_width_deterministic_and_round_trips() {
        let attributes = PortableRootAttributesV1::new(501, 20, 0o7755).unwrap();
        let policy =
            WorkspaceRootPolicyV1::clone_preserve(0x0102_0304_0506_0708, attributes, digest(9))
                .unwrap();
        let bytes = policy.canonical_bytes();

        assert_eq!(bytes.len(), FIXED_CANONICAL_BYTES);
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[8..10], &VERSION.to_be_bytes());
        assert_eq!(bytes[10], CLONE_PRESERVE_KIND);
        assert_eq!(&bytes[12..20], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&bytes[20..24], &501_u32.to_be_bytes());
        assert_eq!(&bytes[24..28], &20_u32.to_be_bytes());
        assert_eq!(&bytes[28..30], &0o7755_u16.to_be_bytes());
        assert_eq!(&bytes[32..64], &[9; 32]);
        assert_eq!(
            WorkspaceRootPolicyV1::from_canonical_bytes(&bytes),
            Ok(policy)
        );
        assert_eq!(policy.canonical_bytes(), policy.canonical_bytes());
    }

    #[test]
    fn decoder_rejects_noncanonical_create_and_clone_encodings() {
        let mut create = WorkspaceRootPolicyV1::create_initialize().canonical_bytes();
        create[12..20].copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            WorkspaceRootPolicyV1::from_canonical_bytes(&create),
            Err(WorkspaceRootPolicyError::MalformedEncoding)
        );

        let attributes = PortableRootAttributesV1::new(0, 0, 0o755).unwrap();
        let policy = WorkspaceRootPolicyV1::clone_preserve(1, attributes, digest(1)).unwrap();
        let mut clone = policy.canonical_bytes();
        clone[11] = 1;
        assert_eq!(
            WorkspaceRootPolicyV1::from_canonical_bytes(&clone),
            Err(WorkspaceRootPolicyError::MalformedEncoding)
        );

        let mut future = policy.canonical_bytes();
        future[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            WorkspaceRootPolicyV1::from_canonical_bytes(&future),
            Err(WorkspaceRootPolicyError::UnsupportedEncodingVersion)
        );
    }
}
