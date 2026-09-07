//! Protected node-local broker-authority configuration.
//!
//! The loader opens a real root-owned directory without following a final
//! symlink, then opens every fixed-name child relative to that descriptor. Each
//! child must be a singly-linked, root-owned, non-executable regular file with
//! no group or other permissions. Reads are bounded and use the already-checked
//! descriptors, so path replacement cannot substitute a different inode after
//! validation.
//!
//! The directory contains these files:
//!
//! ```text
//! broker-plan-policy.cbor          canonical TrustPolicy (<= 64 KiB)
//! broker-plan-public-key           raw Ed25519 public key (32 bytes)
//! broker-revocation-scope          raw nonzero RevocationScopeId (16 bytes)
//! ownership-lease-policy.cbor      canonical TrustPolicy (<= 64 KiB)
//! ownership-lease-public-key       raw Ed25519 public key (32 bytes)
//! node-id                          raw nonzero NodeId (16 bytes)
//! journal-mac-key                  key ID (16 bytes) || secret (32 bytes)
//! ```
//!
//! A policy may carry multiple rotation generations. The configured public
//! key must identify exactly one policy entry by its SHA-256 fingerprint;
//! ambiguous reuse of one physical key across policy generations fails closed.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerPlanTrustAnchor, DecodeLimits, MediaType, NodeId, ObjectDigest,
    OwnershipLeaseTrustAnchor, PortableMediaType, RevocationScopeId, descriptor_for_bytes,
};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{BrokerAuthority, BrokerDomain};

const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const PLAN_POLICY_FILE: &str = "broker-plan-policy.cbor";
const PLAN_PUBLIC_KEY_FILE: &str = "broker-plan-public-key";
const PLAN_REVOCATION_SCOPE_FILE: &str = "broker-revocation-scope";
const LEASE_POLICY_FILE: &str = "ownership-lease-policy.cbor";
const LEASE_PUBLIC_KEY_FILE: &str = "ownership-lease-public-key";
const NODE_ID_FILE: &str = "node-id";
const JOURNAL_MAC_KEY_FILE: &str = "journal-mac-key";

/// Reports rejection of protected broker-authority configuration.
#[derive(Debug, thiserror::Error)]
pub enum BrokerAuthorityConfigError {
    /// A protected filesystem operation failed.
    #[error("cannot read protected broker-authority {object}: {source}")]
    Filesystem {
        /// Stable public name for the object being read.
        object: &'static str,
        /// Underlying operating-system error.
        source: std::io::Error,
    },
    /// A protected object violates its fixed schema or security invariants.
    #[error("protected broker-authority {0} is invalid")]
    Invalid(&'static str),
}

impl BrokerAuthority {
    /// Loads authority exclusively from a protected root-owned directory.
    ///
    /// The method never accepts key material, policy bytes, node identity, or
    /// revocation state from a request. Callers should provision the directory
    /// atomically before starting the broker and restart the broker to rotate
    /// an anchor.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAuthorityConfigError`] when the directory or any fixed
    /// child is absent, is not a protected real object, exceeds its exact byte
    /// bound, or does not construct internally consistent trust anchors.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
        domain: BrokerDomain,
    ) -> Result<Self, BrokerAuthorityConfigError> {
        let directory = open(
            path.as_ref(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("directory", source))?;
        validate_directory(&directory)?;

        let plan_policy = read_protected(&directory, PLAN_POLICY_FILE, MAXIMUM_POLICY_BYTES)?;
        let plan_public_key = read_exact::<32>(&directory, PLAN_PUBLIC_KEY_FILE)?;
        let revocation_scope = read_exact::<16>(&directory, PLAN_REVOCATION_SCOPE_FILE)?;
        let lease_policy = read_protected(&directory, LEASE_POLICY_FILE, MAXIMUM_POLICY_BYTES)?;
        let lease_public_key = read_exact::<32>(&directory, LEASE_PUBLIC_KEY_FILE)?;
        let node = read_exact::<16>(&directory, NODE_ID_FILE)?;
        let journal_key = Zeroizing::new(read_exact::<48>(&directory, JOURNAL_MAC_KEY_FILE)?);

        let plan_signer = select_policy_key(
            &plan_policy,
            &plan_public_key,
            SignaturePurpose::BrokerAuthorization,
            KeyUsage::BrokerAuthorization,
        )?;
        let lease_authority = select_policy_key(
            &lease_policy,
            &lease_public_key,
            SignaturePurpose::OwnershipLease,
            KeyUsage::OwnershipLease,
        )?;
        let plan_policy_model = decode_trust_policy(&plan_policy, policy_limits())
            .map_err(|_| BrokerAuthorityConfigError::Invalid(PLAN_POLICY_FILE))?;
        let lease_policy_model = decode_trust_policy(&lease_policy, policy_limits())
            .map_err(|_| BrokerAuthorityConfigError::Invalid(LEASE_POLICY_FILE))?;
        let policy_media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| BrokerAuthorityConfigError::Invalid("trust-policy media type"))?;
        let plan_descriptor = descriptor_for_bytes(policy_media_type.clone(), &plan_policy);
        let lease_descriptor = descriptor_for_bytes(policy_media_type, &lease_policy);

        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_policy,
            plan_descriptor,
            plan_policy_model.trust_scope(),
            plan_signer,
            plan_public_key,
            RevocationScopeId::from_bytes(revocation_scope),
            policy_limits(),
        )
        .map_err(|_| BrokerAuthorityConfigError::Invalid("broker plan trust anchor"))?;
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy,
            lease_descriptor,
            lease_policy_model.trust_scope(),
            lease_authority,
            lease_public_key,
            policy_limits(),
        )
        .map_err(|_| BrokerAuthorityConfigError::Invalid("ownership lease trust anchor"))?;
        let (journal_key_id, journal_secret) = journal_key.split_at(16);
        Self::new(
            domain,
            plan_anchor,
            lease_anchor,
            NodeId::from_bytes(node),
            journal_key_id
                .try_into()
                .map_err(|_| BrokerAuthorityConfigError::Invalid(JOURNAL_MAC_KEY_FILE))?,
            journal_secret
                .try_into()
                .map_err(|_| BrokerAuthorityConfigError::Invalid(JOURNAL_MAC_KEY_FILE))?,
        )
        .map_err(|_| BrokerAuthorityConfigError::Invalid("broker authority"))
    }
}

fn validate_directory(directory: &OwnedFd) -> Result<(), BrokerAuthorityConfigError> {
    let metadata = fstat(directory).map_err(|source| filesystem("directory", source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || !protected_directory_permissions(metadata.st_mode)
    {
        return Err(BrokerAuthorityConfigError::Invalid("directory"));
    }
    Ok(())
}

fn read_exact<const N: usize>(
    directory: &OwnedFd,
    name: &'static str,
) -> Result<[u8; N], BrokerAuthorityConfigError> {
    let bytes = Zeroizing::new(read_protected(directory, name, N)?);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| BrokerAuthorityConfigError::Invalid(name))
}

fn read_protected(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, BrokerAuthorityConfigError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| filesystem(name, source))?;
    let metadata = fstat(&fd).map_err(|source| filesystem(name, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || !protected_file_permissions(metadata.st_mode)
    {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    let declared_size =
        usize::try_from(metadata.st_size).map_err(|_| BrokerAuthorityConfigError::Invalid(name))?;
    if declared_size == 0 || declared_size > maximum_bytes {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }

    let mut bytes = Vec::with_capacity(declared_size);
    std::fs::File::from(fd)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| BrokerAuthorityConfigError::Filesystem {
            object: name,
            source,
        })?;
    if bytes.len() != declared_size || bytes.len() > maximum_bytes {
        return Err(BrokerAuthorityConfigError::Invalid(name));
    }
    Ok(bytes)
}

fn select_policy_key(
    policy_bytes: &[u8],
    public_key: &[u8; 32],
    purpose: SignaturePurpose,
    usage: KeyUsage,
) -> Result<KeyReference, BrokerAuthorityConfigError> {
    let policy = decode_trust_policy(policy_bytes, policy_limits())
        .map_err(|_| BrokerAuthorityConfigError::Invalid("trust policy"))?;
    if policy.purpose() != purpose {
        return Err(BrokerAuthorityConfigError::Invalid("trust policy purpose"));
    }
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    let mut matches = policy
        .allowed_keys()
        .iter()
        .filter(|key| key.usage() == usage && key.public_key_sha256() == fingerprint);
    let selected = matches
        .next()
        .cloned()
        .ok_or(BrokerAuthorityConfigError::Invalid("configured public key"))?;
    if matches.next().is_some() {
        return Err(BrokerAuthorityConfigError::Invalid(
            "ambiguous configured public key",
        ));
    }
    Ok(selected)
}

const fn protected_directory_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o500 | 0o700)
}

const fn protected_file_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o400 | 0o600)
}

const fn policy_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_POLICY_BYTES,
        maximum_collection_items: 2_048,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: MAXIMUM_POLICY_BYTES,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

fn filesystem(object: &'static str, source: rustix::io::Errno) -> BrokerAuthorityConfigError {
    BrokerAuthorityConfigError::Filesystem {
        object,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::TrustScopeId;
    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{StableKeyId, TrustPolicy};

    use super::*;

    fn key(name: &str, generation: u64, public_key: &[u8; 32]) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
            KeyUsage::BrokerAuthorization,
        )
    }

    fn policy(keys: Vec<KeyReference>) -> Vec<u8> {
        encode_trust_policy(
            &TrustPolicy::new(
                TrustScopeId::from_bytes([1; 16]),
                SignaturePurpose::BrokerAuthorization,
                keys,
                Vec::new(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn public_key_selects_one_generation_from_rotation_policy() {
        let first_public_key = [1; 32];
        let selected_public_key = [2; 32];
        let selected = key("second", 7, &selected_public_key);
        let bytes = policy(vec![key("first", 6, &first_public_key), selected.clone()]);

        assert_eq!(
            select_policy_key(
                &bytes,
                &selected_public_key,
                SignaturePurpose::BrokerAuthorization,
                KeyUsage::BrokerAuthorization,
            )
            .unwrap(),
            selected
        );
    }

    #[test]
    fn physical_key_reuse_across_generations_is_ambiguous() {
        let public_key = [3; 32];
        let bytes = policy(vec![
            key("first", 6, &public_key),
            key("second", 7, &public_key),
        ]);

        assert!(
            select_policy_key(
                &bytes,
                &public_key,
                SignaturePurpose::BrokerAuthorization,
                KeyUsage::BrokerAuthorization,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_modes_reject_special_and_shared_permissions() {
        assert!(protected_directory_permissions(0o040700));
        assert!(protected_directory_permissions(0o040500));
        assert!(!protected_directory_permissions(0o041700));
        assert!(!protected_directory_permissions(0o042700));
        assert!(!protected_directory_permissions(0o040750));

        assert!(protected_file_permissions(0o100400));
        assert!(protected_file_permissions(0o100600));
        assert!(!protected_file_permissions(0o104400));
        assert!(!protected_file_permissions(0o102600));
        assert!(!protected_file_permissions(0o100640));
        assert!(!protected_file_permissions(0o100700));
    }
}
