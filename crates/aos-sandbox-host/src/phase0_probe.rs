//! Signed, boot-local evidence from the fixed shifted-userns probe service.
//!
//! The AOSHPB02 record attests that the exact packaged inspector observed a
//! hardened fixed shifted target through pidfs. It does not attest the
//! nspawn payload filter or authorize Host Launch.
//!
//! ```text
//! AOSHPB02 || boot_id[16] || nspawn_sha256[32] || hostd_sha256[32]
//! || inspector_sha256[32] || selinux_policy_sha256[32] || target_pid:u32be
//! || host_uid_start:u32be || host_gid_start:u32be || mapping_count:u32be
//! || cgroup_id:u64be || (namespace_device:u64be || namespace_inode:u64be)*4
//! || Ed25519_signature[64]
//! ```

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use aos_sandbox_linux::pidfd::NamespaceIdentity;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use sha2::{Digest as _, Sha256};

use crate::{HostError, Result};

const MAGIC: &[u8; 8] = b"AOSHPB02";
const MESSAGE_BYTES: usize = 240;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.host-phase0-probe.v2\0";
const MAXIMUM_PROBE_BINARY_BYTES: u64 = 256 * 1024 * 1024;
/// Exact signed AOSHPB02 record length.
pub const PHASE0_PROBE_RECORD_BYTES: usize = MESSAGE_BYTES + 64;

/// Measures the exact protected packaged Host daemon selected by a fixed unit.
///
/// # Errors
///
/// Rejects a foreign path, mutable/non-executable file, oversized bytes, or
/// any change while the file is read.
pub fn verified_packaged_hostd_digest(path: &Path) -> Result<[u8; 32]> {
    verified_packaged_probe_binary_digest(path, "/bin/aos-sandbox-hostd")
}

/// Measures the exact protected phase-0 inspector selected by the fixed unit.
///
/// # Errors
///
/// Rejects a foreign path, mutable/non-executable file, oversized bytes, or
/// any change while the file is read.
pub fn verified_packaged_inspector_digest(path: &Path) -> Result<[u8; 32]> {
    verified_packaged_probe_binary_digest(path, "/bin/aos-sandbox-host-phase0-probe")
}

fn verified_packaged_probe_binary_digest(path: &Path, expected_suffix: &str) -> Result<[u8; 32]> {
    let path_text = path
        .to_str()
        .ok_or_else(|| HostError::State("packaged Host probe path is not UTF-8".to_owned()))?;
    if !path_text.starts_with("/nix/store/") || !path_text.ends_with(expected_suffix) {
        return Err(HostError::State(
            "Host probe is not the fixed packaged executable".to_owned(),
        ));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(format!("cannot open packaged Host probe: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| HostError::State(format!("cannot stat packaged Host probe: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_mode & 0o111 == 0
        || before.st_size <= 0
        || u64::try_from(before.st_size).unwrap_or(u64::MAX) > MAXIMUM_PROBE_BINARY_BYTES
    {
        return Err(HostError::State(
            "packaged Host probe has invalid protected metadata".to_owned(),
        ));
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let amount = file
            .read(&mut buffer)
            .map_err(|error| HostError::State(format!("cannot read Host probe: {error}")))?;
        if amount == 0 {
            break;
        }
        total = total
            .checked_add(amount as u64)
            .ok_or_else(|| HostError::State("Host probe is oversized".to_owned()))?;
        if total > MAXIMUM_PROBE_BINARY_BYTES {
            return Err(HostError::State("Host probe is oversized".to_owned()));
        }
        digest.update(&buffer[..amount]);
    }
    let after = fstat(&file)
        .map_err(|error| HostError::State(format!("cannot restat packaged Host probe: {error}")))?;
    if total != before.st_size as u64
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mode != before.st_mode
        || after.st_uid != before.st_uid
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(HostError::State(
            "packaged Host probe changed during measurement".to_owned(),
        ));
    }
    Ok(digest.finalize().into())
}

/// Carries kernel identities observed by the privileged shifted-target inspector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Phase0ProbeObservationV2 {
    /// Boot in which the target and inspector ran.
    pub boot_id: [u8; 16],
    /// Exact packaged nspawn bytes selected by the Host deployment.
    pub nspawn_sha256: [u8; 32],
    /// Exact packaged Host daemon bytes served by this deployment.
    pub hostd_sha256: [u8; 32],
    /// Exact packaged inspector bytes selected by the fixed phase-0 unit.
    pub inspector_sha256: [u8; 32],
    /// Exact deployed and live enforcing SELinux policy bytes.
    pub selinux_policy_sha256: [u8; 32],
    /// PID 1-reported fixed target main process.
    pub target_pid: u32,
    /// First outer UID in the target's shifted user namespace.
    pub host_uid_start: u32,
    /// First outer GID in the target's shifted user namespace.
    pub host_gid_start: u32,
    /// Length of the target's sole UID/GID mapping.
    pub mapping_count: u32,
    /// Kernel cgroup ID pinned beneath the fixed systemd unit.
    pub cgroup_id: u64,
    /// Type-checked target user namespace.
    pub user: NamespaceIdentity,
    /// Type-checked target mount namespace.
    pub mount: NamespaceIdentity,
    /// Type-checked target network namespace.
    pub network: NamespaceIdentity,
    /// Type-checked target PID namespace.
    pub pid: NamespaceIdentity,
}

/// Signs and verifies one fixed phase-0 probe observation.
pub struct SignedPhase0ProbeRecordV2 {
    observation: Phase0ProbeObservationV2,
    signature: [u8; 64],
}

impl SignedPhase0ProbeRecordV2 {
    /// Signs a structurally valid observation with the dedicated probe key.
    ///
    /// # Errors
    ///
    /// Rejects zero or non-shifted kernel identities and an absent package hash.
    pub fn sign(observation: Phase0ProbeObservationV2, key: &SigningKey) -> Result<Self> {
        validate_observation(&observation)?;
        let message = encode_message(&observation);
        Ok(Self {
            observation,
            signature: key.sign(&message).to_bytes(),
        })
    }

    /// Decodes and authenticates exact record bytes against an independent key.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, signature, boot, package, or kernel fields.
    pub fn verify(
        bytes: &[u8],
        key: &VerifyingKey,
        boot_id: [u8; 16],
        nspawn_sha256: [u8; 32],
        hostd_sha256: [u8; 32],
        inspector_sha256: [u8; 32],
        selinux_policy_sha256: [u8; 32],
    ) -> Result<Self> {
        let bytes: &[u8; PHASE0_PROBE_RECORD_BYTES] = bytes.try_into().map_err(|_| {
            HostError::State("shifted phase-0 probe record has wrong length".to_owned())
        })?;
        let message: [u8; MESSAGE_BYTES] = bytes[..MESSAGE_BYTES].try_into().map_err(|_| {
            HostError::State("shifted phase-0 probe message is malformed".to_owned())
        })?;
        if &message[..8] != MAGIC {
            return Err(HostError::State(
                "shifted phase-0 probe record has wrong version".to_owned(),
            ));
        }
        let signature_bytes: [u8; 64] = bytes[MESSAGE_BYTES..].try_into().map_err(|_| {
            HostError::State("shifted phase-0 probe signature is malformed".to_owned())
        })?;
        key.verify_strict(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| {
                HostError::State("shifted phase-0 probe signature is invalid".to_owned())
            })?;

        let observation = decode_message(&message)?;
        validate_observation(&observation)?;
        if observation.boot_id != boot_id
            || observation.nspawn_sha256 != nspawn_sha256
            || observation.hostd_sha256 != hostd_sha256
            || observation.inspector_sha256 != inspector_sha256
            || observation.selinux_policy_sha256 != selinux_policy_sha256
        {
            return Err(HostError::State(
                "shifted phase-0 probe is stale or targets another package".to_owned(),
            ));
        }
        Ok(Self {
            observation,
            signature: signature_bytes,
        })
    }

    /// Encodes the canonical fixed record.
    #[must_use]
    pub fn encode(&self) -> [u8; PHASE0_PROBE_RECORD_BYTES] {
        let mut bytes = [0; PHASE0_PROBE_RECORD_BYTES];
        bytes[..MESSAGE_BYTES].copy_from_slice(&encode_message(&self.observation));
        bytes[MESSAGE_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    /// Returns the attested kernel observation without granting launch authority.
    #[must_use]
    pub const fn observation(&self) -> &Phase0ProbeObservationV2 {
        &self.observation
    }

    /// Returns the domain-separated digest claimed by phase-0 readiness.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

fn validate_observation(value: &Phase0ProbeObservationV2) -> Result<()> {
    if value.boot_id == [0; 16]
        || value.nspawn_sha256 == [0; 32]
        || value.hostd_sha256 == [0; 32]
        || value.inspector_sha256 == [0; 32]
        || value.selinux_policy_sha256 == [0; 32]
        || value.target_pid <= 1
        || value.host_uid_start == 0
        || value.host_gid_start == 0
        || value.mapping_count < 65_536
        || value
            .host_uid_start
            .checked_add(value.mapping_count - 1)
            .is_none()
        || value
            .host_gid_start
            .checked_add(value.mapping_count - 1)
            .is_none()
        || value.cgroup_id == 0
        || [value.user, value.mount, value.network, value.pid]
            .iter()
            .any(|identity| identity.device == 0 || identity.inode == 0)
    {
        return Err(HostError::State(
            "shifted phase-0 probe observation is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn encode_message(value: &Phase0ProbeObservationV2) -> [u8; MESSAGE_BYTES] {
    let mut bytes = [0; MESSAGE_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&value.boot_id);
    bytes[24..56].copy_from_slice(&value.nspawn_sha256);
    bytes[56..88].copy_from_slice(&value.hostd_sha256);
    bytes[88..120].copy_from_slice(&value.inspector_sha256);
    bytes[120..152].copy_from_slice(&value.selinux_policy_sha256);
    bytes[152..156].copy_from_slice(&value.target_pid.to_be_bytes());
    bytes[156..160].copy_from_slice(&value.host_uid_start.to_be_bytes());
    bytes[160..164].copy_from_slice(&value.host_gid_start.to_be_bytes());
    bytes[164..168].copy_from_slice(&value.mapping_count.to_be_bytes());
    bytes[168..176].copy_from_slice(&value.cgroup_id.to_be_bytes());
    for (index, identity) in [value.user, value.mount, value.network, value.pid]
        .iter()
        .enumerate()
    {
        let start = 176 + index * 16;
        bytes[start..start + 8].copy_from_slice(&identity.device.to_be_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&identity.inode.to_be_bytes());
    }
    bytes
}

fn decode_message(bytes: &[u8; MESSAGE_BYTES]) -> Result<Phase0ProbeObservationV2> {
    fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N]> {
        bytes
            .get(start..start + N)
            .ok_or_else(|| HostError::State("shifted phase-0 probe is truncated".to_owned()))?
            .try_into()
            .map_err(|_| HostError::State("shifted phase-0 probe field is malformed".to_owned()))
    }
    let namespace = |index: usize| -> Result<NamespaceIdentity> {
        let start = 176 + index * 16;
        Ok(NamespaceIdentity {
            device: u64::from_be_bytes(array(bytes, start)?),
            inode: u64::from_be_bytes(array(bytes, start + 8)?),
        })
    };
    Ok(Phase0ProbeObservationV2 {
        boot_id: array(bytes, 8)?,
        nspawn_sha256: array(bytes, 24)?,
        hostd_sha256: array(bytes, 56)?,
        inspector_sha256: array(bytes, 88)?,
        selinux_policy_sha256: array(bytes, 120)?,
        target_pid: u32::from_be_bytes(array(bytes, 152)?),
        host_uid_start: u32::from_be_bytes(array(bytes, 156)?),
        host_gid_start: u32::from_be_bytes(array(bytes, 160)?),
        mapping_count: u32::from_be_bytes(array(bytes, 164)?),
        cgroup_id: u64::from_be_bytes(array(bytes, 168)?),
        user: namespace(0)?,
        mount: namespace(1)?,
        network: namespace(2)?,
        pid: namespace(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> Phase0ProbeObservationV2 {
        Phase0ProbeObservationV2 {
            boot_id: [1; 16],
            nspawn_sha256: [2; 32],
            hostd_sha256: [3; 32],
            inspector_sha256: [5; 32],
            selinux_policy_sha256: [4; 32],
            target_pid: 42,
            host_uid_start: 524_288,
            host_gid_start: 524_288,
            mapping_count: 65_536,
            cgroup_id: 43,
            user: NamespaceIdentity {
                device: 1,
                inode: 2,
            },
            mount: NamespaceIdentity {
                device: 1,
                inode: 3,
            },
            network: NamespaceIdentity {
                device: 1,
                inode: 4,
            },
            pid: NamespaceIdentity {
                device: 1,
                inode: 5,
            },
        }
    }

    #[test]
    fn signed_probe_is_exactly_bound_to_boot_package_and_key() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let record = SignedPhase0ProbeRecordV2::sign(observation(), &key).unwrap();
        let bytes = record.encode();
        assert_eq!(bytes.len(), PHASE0_PROBE_RECORD_BYTES);
        assert_eq!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [1; 16],
                [2; 32],
                [3; 32],
                [5; 32],
                [4; 32]
            )
            .unwrap()
            .observation(),
            &observation()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [9; 16],
                [2; 32],
                [3; 32],
                [5; 32],
                [4; 32]
            )
            .is_err()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [1; 16],
                [9; 32],
                [3; 32],
                [5; 32],
                [4; 32]
            )
            .is_err()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [1; 16],
                [2; 32],
                [9; 32],
                [5; 32],
                [4; 32]
            )
            .is_err()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [1; 16],
                [2; 32],
                [3; 32],
                [9; 32],
                [4; 32]
            )
            .is_err()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &key.verifying_key(),
                [1; 16],
                [2; 32],
                [3; 32],
                [5; 32],
                [9; 32]
            )
            .is_err()
        );
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &bytes,
                &SigningKey::from_bytes(&[8; 32]).verifying_key(),
                [1; 16],
                [2; 32],
                [3; 32],
                [5; 32],
                [4; 32]
            )
            .is_err()
        );
        let mut changed = bytes;
        changed[90] ^= 1;
        assert!(
            SignedPhase0ProbeRecordV2::verify(
                &changed,
                &key.verifying_key(),
                [1; 16],
                [2; 32],
                [3; 32],
                [5; 32],
                [4; 32]
            )
            .is_err()
        );
    }
}
