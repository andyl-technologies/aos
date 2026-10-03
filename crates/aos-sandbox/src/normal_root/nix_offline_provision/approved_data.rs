//! Canonical offline candidate and independently signed approval DATA.
//!
//! Candidate derivation and static-job comparisons have one owner below Core
//! and Security. No comparator admits delivery, current authority, hierarchy
//! access, a TPM outcome, a floor or a live session.
//!
//! ```text
//! private-v3: AOSNPK03/version3/reserved + 4*(ID16/seed32) + 4*auth32 (336)
//! public-v3: AOSNPC03/version3 + job16/node16/commit32 + 4*(ID16/public32) (268)
//! static-v3: header80 + public268 + manifest920 + independent signature64
//! effect-v4: header80 + five digest32 + independent signature64 (304)
//! ```

use aos_sandbox_broker_session_protocol::{BrokerSessionKeyUsageV1, BrokerSessionProtocolV1};
use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestErrorV1, BrokerSessionManifestV1,
};
use ed25519_dalek::{Signature, SignatureError, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Names the original offline job metadata DATA, not an admitted file owner.
pub type NixOfflineJobIdentityDataV5 = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

/// Observes the sole offline job identity recipe without admitting custody.
///
/// Directory entry/link/time changes are intentionally excluded because the
/// serialized purpose owner creates entries. File links, extents and times
/// remain exact; the genuine caller owns names, modes, bounds and OFD custody.
///
/// # Errors
/// Returns the actual metadata error. No descriptor is moved or duplicated.
pub fn inspect_nix_offline_job_identity_v5(
    file: &std::fs::File,
) -> std::io::Result<NixOfflineJobIdentityDataV5> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    let (links, length, modified, modified_ns, changed, changed_ns) = if metadata.is_dir() {
        (0, 0, 0, 0, 0, 0)
    } else {
        (
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        links,
        length,
        modified,
        modified_ns,
        changed,
        changed_ns,
    ))
}

/// Observes the fixed offline job label and ACL absence as nonauthorizing DATA.
///
/// # Errors
/// Returns the actual native xattr error. `Ok(false)` reports a label mismatch
/// or an ACL, never an alternate policy or permission to continue an effect.
pub fn nix_offline_job_has_original_label_v5(file: &std::fs::File) -> std::io::Result<bool> {
    let mut context = [0; 256];
    let length = rustix::fs::fgetxattr(file, "security.selinux", &mut context[..])?;
    let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
    if actual != b"system_u:object_r:aos_nix_offline_prepare_state_t" {
        return Ok(false);
    }
    let mut bytes = [0; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(file, name, &mut bytes[..]) {
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Ok(false),
        }
    }
    Ok(true)
}

const CANDIDATE_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.offline-candidates.v3\0";
const APPROVAL_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.approved-job-inspection.v3\0";
const SIGNED_PREFIX_BYTES: usize = 1268;
const PREIMAGE_BYTES: usize = 1317;
const EFFECT_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.approved-effect.v4\0";
const CONTROLLER_PURPOSE: [u8; 16] = [
    1, 0, 0, 0, 0x01, 0x80, 0xa0, 0x58, 0x81, 0x00, 0xa0, 0x58, 0, 0, 0, 0,
];
const OWNER_PURPOSE: [u8; 16] = [
    2, 0, 0, 0, 0x01, 0x80, 0xa0, 0x59, 0x81, 0x00, 0xa0, 0x59, 0, 0, 0, 0,
];

const _: () = assert!(APPROVAL_DOMAIN.len() + SIGNED_PREFIX_BYTES == PREIMAGE_BYTES);

/// Reports a canonical offline DATA comparison failure, not owning authority.
#[derive(Debug, thiserror::Error)]
pub enum NixOfflineApprovedDataErrorV4 {
    /// A bounded shape, coordinate, separation or byte comparison differs.
    #[error("offline approval DATA differs")]
    Rejected,
    /// The original candidate derivation rejected its bounded input.
    #[error("offline candidate DATA differs")]
    Candidate,
    /// The sole canonical session manifest engine rejected the input.
    #[error("offline approval manifest differs")]
    Manifest(#[from] BrokerSessionManifestErrorV1),
    /// The independent public key or exact signature is invalid.
    #[error("offline approval signature differs")]
    Signature(#[from] SignatureError),
}

type Error = NixOfflineApprovedDataErrorV4;

/// Derives the exact V3 public candidate bytes into the caller's existing buffer.
///
/// Secret copies are zeroizing; returned DATA is not an admitted signer.
///
/// # Errors
/// Rejects widths, versions, zero identifiers/secrets and candidate key reuse.
pub fn derive_nix_offline_public_candidates_v3(
    private: &[u8],
    job: &[u8],
    node: &[u8; 16],
    approval: &[u8; 48],
    public: &mut [u8],
) -> Result<(), Error> {
    if private.len() != 336 || job.len() != 16 || public.len() != 268
        || private[..8] != *b"AOSNPK03"
        || private[8..10] != 3_u16.to_le_bytes()
        || private[10..16] != [0; 6]
        || job.iter().all(|byte| *byte == 0)
    {
        return Err(Error::Rejected);
    }
    public.fill(0);
    public[..8].copy_from_slice(b"AOSNPC03");
    public[8..10].copy_from_slice(&3_u16.to_le_bytes());
    public[12..28].copy_from_slice(job);
    public[28..44].copy_from_slice(node);
    let mut digest = Sha256::new();
    digest.update(CANDIDATE_DOMAIN);
    digest.update(private);
    public[44..76].copy_from_slice(&digest.finalize());

    for index in 0..4 {
        let record = &private[16 + index * 48..16 + (index + 1) * 48];
        let seed = Zeroizing::new(<[u8; 32]>::try_from(&record[16..]).map_err(|_| Error::Rejected)?);
        if record[..16].iter().all(|byte| *byte == 0)
            || seed.iter().all(|byte| *byte == 0)
            || record[..16] == approval[..16]
        {
            return Err(Error::Rejected);
        }
        let key = SigningKey::from_bytes(&seed);
        let derived = key.verifying_key().to_bytes();
        if derived == approval[16..] {
            return Err(Error::Rejected);
        }
        let offset = 76 + index * 48;
        public[offset..offset + 16].copy_from_slice(&record[..16]);
        public[offset + 16..offset + 48].copy_from_slice(&derived);
        for earlier in 0..index {
            let earlier_offset = 76 + earlier * 48;
            if public[earlier_offset..earlier_offset + 16] == record[..16]
                || public[earlier_offset + 16..earlier_offset + 48] == derived
            {
                return Err(Error::Rejected);
            }
        }
    }
    let secret = |index: usize| -> &[u8] {
        if index < 4 {
            &private[32 + index * 48..64 + index * 48]
        } else {
            &private[208 + (index - 4) * 32..240 + (index - 4) * 32]
        }
    };
    for index in 0..8 {
        if secret(index).iter().all(|byte| *byte == 0)
            || (0..index).any(|earlier| secret(earlier) == secret(index))
        {
            return Err(Error::Rejected);
        }
    }
    Ok(())
}

/// Compares the exact static-job header without constructing an approval owner.
///
/// # Errors
/// Rejects noncanonical width, version, installation, purpose or approval ID.
pub fn require_nix_offline_static_header_v3(approved: &[u8], approval: &[u8; 48]) -> Result<(), Error> {
    if approved.len() != 1332
        || approved[..8] != *b"AOSNAJ03"
        || approved[8..10] != 3_u16.to_be_bytes()
        || approved[10..12] != 1_u16.to_be_bytes()
        || approved[12..16] != [0; 4]
        || approved[16..32] != approval[..16]
        || approved[32..40] != 1_u64.to_be_bytes()
        || approved[40..48] != [0; 8]
        || approved[48..64] != CONTROLLER_PURPOSE
        || approved[64..80] != OWNER_PURPOSE
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

/// Fills the canonical static-job signature preimage in an existing buffer.
///
/// # Errors
/// Rejects any width other than the exact approved-job and preimage widths.
pub fn fill_nix_offline_static_preimage_v3(approved: &[u8], preimage: &mut [u8]) -> Result<(), Error> {
    if approved.len() != 1332 || preimage.len() != PREIMAGE_BYTES {
        return Err(Error::Rejected);
    }
    preimage[..APPROVAL_DOMAIN.len()].copy_from_slice(APPROVAL_DOMAIN);
    preimage[APPROVAL_DOMAIN.len()..].copy_from_slice(&approved[..SIGNED_PREFIX_BYTES]);
    Ok(())
}

/// Verifies canonical candidate, manifest and independent static-job DATA.
///
/// The caller owns protected originals, admission and both workspaces. Success
/// is a static comparison, never a live effect permit.
///
/// # Errors
/// Preserves header, candidate, manifest role/revocation and signature ordering.
pub fn require_nix_offline_static_approval_v3(
    private: &[u8], public: &[u8], approved: &[u8], node: &[u8; 16],
    approval: &[u8; 48], derived: &mut [u8], preimage: &mut [u8],
) -> Result<(), Error> {
    require_nix_offline_static_header_v3(approved, approval)?;
    if public.len() != 268
        || public[..8] != *b"AOSNPC03"
        || public[8..10] != 3_u16.to_le_bytes()
        || public[10..12] != [0; 2]
        || public[28..44] != *node
        || public != &approved[80..348]
    {
        return Err(Error::Rejected);
    }
    derive_nix_offline_public_candidates_v3(private, &public[12..28], node, approval, derived)
        .map_err(|_| Error::Candidate)?;
    if derived != public {
        return Err(Error::Rejected);
    }

    let manifest = BrokerSessionManifestV1::decode(&approved[348..1268])?;
    if manifest.encode().as_slice() != &approved[348..1268]
        || manifest.protocol() != BrokerSessionProtocolV1::Nix
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.protocol_version() != (1, 0)
        || manifest.node_id() != *node
    {
        return Err(Error::Rejected);
    }
    manifest.require_all_active()?;
    let expected_roles = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let pins = manifest.key_pins();
    for (index, (pin, role)) in pins.iter().zip(expected_roles).enumerate() {
        let offset = 76 + index * 48;
        let signer = pin.signer();
        if signer.key_id().as_slice() != &public[offset..offset + 16]
            || pin.public_key().as_slice() != &public[offset + 16..offset + 48]
            || signer.usage() != role
            || signer.key_generation() != 1
            || pin.minimum_key_generation() != 1
            || pin.minimum_authority_generation() != signer.authority_generation()
        {
            return Err(Error::Rejected);
        }
    }
    for (left, right) in [(0, 2), (1, 3)] {
        let left = pins[left].signer();
        let right = pins[right].signer();
        if left.authority_id() != right.authority_id()
            || left.authority_generation() != right.authority_generation()
            || left.authority_digest() != right.authority_digest()
        {
            return Err(Error::Rejected);
        }
    }
    if pins[0].signer().authority_id() == pins[1].signer().authority_id() {
        return Err(Error::Rejected);
    }

    fill_nix_offline_static_preimage_v3(approved, preimage)?;
    let key_bytes = <[u8; 32]>::try_from(&approval[16..]).map_err(|_| Error::Rejected)?;
    let signature_bytes = <[u8; 64]>::try_from(&approved[1268..]).map_err(|_| Error::Rejected)?;
    VerifyingKey::from_bytes(&key_bytes)?.verify_strict(
        preimage,
        &Signature::from_bytes(&signature_bytes),
    )?;
    Ok(())
}

/// Selects one versioned offline signature purpose as DATA, not authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixOfflineEffectApprovalKindV4 {
    /// Initial pair provisioning, with a zero prior-history digest.
    Initialize,
    /// The one recovery, bound to the complete prior-history digest.
    Recover,
}

/// Verifies the independently signed 304-byte effect or recovery DATA record.
///
/// Expected coordinates must come from the protected owner's originals. This
/// comparator neither constructs that owner nor authorizes a hardware action.
///
/// # Errors
/// Rejects width, version, coordinates, digest pins, workspace or signature.
pub fn require_nix_offline_effect_approval_v4(
    bytes: &[u8], approval: &[u8; 48], job: &[u8; 16], node: &[u8; 16],
    digests: &[[u8; 32]; 5], kind: NixOfflineEffectApprovalKindV4, preimage: &mut [u8],
) -> Result<(), Error> {
    let action = match kind {
        NixOfflineEffectApprovalKindV4::Initialize => 1_u8,
        NixOfflineEffectApprovalKindV4::Recover => 2_u8,
    };
    if bytes.len() != 304 || preimage.len() != EFFECT_DOMAIN.len() + 240
        || bytes[..8] != *b"AOSNAE04"
        || bytes[8..10] != 4_u16.to_be_bytes()
        || bytes[10] != action || bytes[11] != 1
        || bytes[12..16] != [0; 4]
        || bytes[16..32] != approval[..16]
        || bytes[32..48] != *job || bytes[48..64] != *node
        || bytes[64..72] != 1_u64.to_be_bytes() || bytes[72..80] != [0; 8]
        || (kind == NixOfflineEffectApprovalKindV4::Initialize && digests[4] != [0; 32])
        || (kind == NixOfflineEffectApprovalKindV4::Recover && digests[4] == [0; 32])
    {
        return Err(Error::Rejected);
    }
    for (index, digest) in digests.iter().enumerate() {
        if bytes[80 + index * 32..112 + index * 32] != *digest {
            return Err(Error::Rejected);
        }
    }

    preimage[..EFFECT_DOMAIN.len()].copy_from_slice(EFFECT_DOMAIN);
    preimage[EFFECT_DOMAIN.len()..].copy_from_slice(&bytes[..240]);
    let key = <[u8; 32]>::try_from(&approval[16..]).map_err(|_| Error::Rejected)?;
    let signature = <[u8; 64]>::try_from(&bytes[240..]).map_err(|_| Error::Rejected)?;
    VerifyingKey::from_bytes(&key)?.verify_strict(preimage, &Signature::from_bytes(&signature))?;
    Ok(())
}
