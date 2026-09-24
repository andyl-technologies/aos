//! Broker-held, signed Network inspector deployment inventory.
//!
//! The broker loads this optional, role-separated credential pair during
//! startup. It verifies the signature and generation, pins every declared
//! physical file, and binds its own running executable to the broker entry.
//! The `manager_query_helper` member names the broker-side PID 1 helper; the
//! inspector-self query helper remains a separate V1-pinned executable.
//! The signer must independently establish that the list includes the full
//! `PT_INTERP` and `DT_NEEDED` graph. A signed list alone does not prove that
//! completeness or replace a fresh, broker-owned PID 1 unit observation.
//!
//! ```text
//! inspector-deployment-verifier-v2: AOSNIK02 | generation:u64 |
//!     Ed25519 public key:32 | SHA-256(role-domain || preceding 48 bytes)
//! inspector-deployment-contract-v2: canonical JSON DeploymentPayload |
//!     Ed25519 signature:64 over signature-domain || JSON bytes
//! inspector-launch-policy-v3: canonical JSON LaunchPolicyPayloadV3 |
//!     Ed25519 signature:64 under a separate domain, bound to the exact V2
//!     signed-contract digest and generation
//! ```

use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const KEY_NAME: &str = "inspector-deployment-verifier-v2";
const CONTRACT_NAME: &str = "inspector-deployment-contract-v2";
const KEY_MAGIC: &[u8; 8] = b"AOSNIK02";
const KEY_DOMAIN: &[u8] = b"aos.network.inspector.deployment-verifier.v2\0";
const SIGNATURE_DOMAIN: &[u8] = b"aos.network.inspector.deployment-contract.v2\0";
const SERVICE_TEMPLATE: &str = "aos-sandbox-network-namespace-inspector@.service";
const SOCKET_UNIT: &str = "aos-sandbox-network-namespace-inspector.socket";
const MAXIMUM_CONTRACT_BYTES: u64 = 64 * 1024;
const MAXIMUM_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_TOTAL_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MEMBERS: usize = 128;

mod launch_policy;
pub use launch_policy::ProtectedServiceLaunchV3;

use launch_policy::ProtectedLaunchPolicyV3;

/// Reports a rejected broker-held inspector deployment inventory.
#[derive(Debug, Error)]
pub enum InspectorDeploymentErrorV2 {
    /// A bounded filesystem operation failed.
    #[error("inspector deployment {operation} failed: {source}")]
    Io {
        /// Names the failing operation.
        operation: &'static str,
        /// Preserves the operating-system error.
        #[source]
        source: io::Error,
    },
    /// The credential, signature, manifest, or retained file failed admission.
    #[error("inspector deployment contract is invalid")]
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MemberRole {
    Broker,
    Inspector,
    LifecycleWorker,
    ManagerQueryHelper,
    Interpreter,
    Library,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MemberExpectation {
    role: MemberRole,
    path: String,
    length: u64,
    mode: u32,
    sha256: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentPayload {
    generation: u64,
    inspector_service_template: String,
    inspector_socket_unit: String,
    inspector_v1_contract_digest: [u8; 32],
    members: Vec<MemberExpectation>,
}

#[derive(Debug)]
struct RetainedMember {
    expectation: MemberExpectation,
    descriptor: File,
    device: u64,
    inode: u64,
}

/// Retains the broker's authenticated inspector deployment inventory.
///
/// This is a startup prerequisite when V2 credentials are installed, not a
/// positive Network Apply or inspection authority. The runtime must also bind
/// a fresh PID 1 `MainPID`/invocation/unit observation to the response pidfd,
/// and independently verify the live worker unit before using an inspector
/// response in place of either direct namespace-currentness check.
#[derive(Debug)]
pub struct ProtectedInspectorDeploymentV2 {
    members: Vec<RetainedMember>,
    launch_policy: Option<ProtectedLaunchPolicyV3>,
}

impl ProtectedInspectorDeploymentV2 {
    /// Loads and pins the exact credential pair if both files are installed.
    ///
    /// # Errors
    ///
    /// Rejects a half-installed pair, unsafe credential metadata, invalid
    /// signature or generation, malformed inventory, or any mismatched member.
    pub fn load_optional(directory: &Path) -> Result<Option<Self>, InspectorDeploymentErrorV2> {
        let key_path = directory.join(KEY_NAME);
        let contract_path = directory.join(CONTRACT_NAME);
        let launch_path = directory.join(launch_policy::CREDENTIAL_NAME);
        let key_present = credential_present(&key_path)?;
        let contract_present = credential_present(&contract_path)?;
        let launch_present = credential_present(&launch_path)?;
        if !key_present && !contract_present {
            if launch_present {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            return Ok(None);
        }
        if !key_present || !contract_present {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }

        let key_bytes = read_credential(&key_path, 80)?;
        let contract_bytes = read_credential(&contract_path, MAXIMUM_CONTRACT_BYTES)?;
        let (generation, key) = decode_verifier(&key_bytes)?;
        let payload = verify_payload(&contract_bytes, generation, &key)?;
        let mut members = Vec::with_capacity(payload.members.len());
        let mut total_bytes = 0_u64;
        for expectation in &payload.members {
            total_bytes = total_bytes
                .checked_add(expectation.length)
                .filter(|bytes| *bytes <= MAXIMUM_TOTAL_MEMBER_BYTES)
                .ok_or(InspectorDeploymentErrorV2::Invalid)?;
            members.push(RetainedMember::open(expectation.clone())?);
        }
        let broker = members
            .iter()
            .find(|member| member.expectation.role == MemberRole::Broker)
            .ok_or(InspectorDeploymentErrorV2::Invalid)?;
        let current = std::fs::metadata("/proc/self/exe")
            .map_err(|source| io_error("inspect broker executable", source))?;
        if current.dev() != broker.device || current.ino() != broker.inode {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }

        let launch_policy = if launch_present {
            Some(ProtectedLaunchPolicyV3::load(
                &launch_path,
                generation,
                &key,
                &contract_bytes,
                &members,
            )?)
        } else {
            None
        };
        let deployment = Self {
            members,
            launch_policy,
        };
        deployment.revalidate()?;
        Ok(Some(deployment))
    }

    /// Revalidates every pinned physical path against the signed inventory.
    ///
    /// # Errors
    ///
    /// Rejects any changed pathname, inode, owner, mode, length, or content.
    pub fn revalidate(&self) -> Result<(), InspectorDeploymentErrorV2> {
        for member in &self.members {
            member.revalidate()?;
        }
        if let Some(policy) = &self.launch_policy {
            policy.revalidate()?;
        }
        Ok(())
    }

    /// Duplicates the pinned broker-side PID 1 query helper executable.
    ///
    /// # Errors
    ///
    /// Rejects changed deployment files or a failed descriptor duplication.
    pub fn broker_query_helper(&self) -> Result<(String, OwnedFd), InspectorDeploymentErrorV2> {
        self.revalidate()?;
        let member = self
            .members
            .iter()
            .find(|member| member.expectation.role == MemberRole::ManagerQueryHelper)
            .ok_or(InspectorDeploymentErrorV2::Invalid)?;
        let descriptor = member
            .descriptor
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| io_error("duplicate broker query helper", source))?;
        Ok((member.expectation.path.clone(), descriptor))
    }

    /// Returns the signed executable path for one queried service role.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete retained inventory.
    pub fn service_executable(&self, inspector: bool) -> Result<&str, InspectorDeploymentErrorV2> {
        let role = if inspector {
            MemberRole::Inspector
        } else {
            MemberRole::LifecycleWorker
        };
        self.members
            .iter()
            .find(|member| member.expectation.role == role)
            .map(|member| member.expectation.path.as_str())
            .ok_or(InspectorDeploymentErrorV2::Invalid)
    }

    /// Returns one signed, fragment-pinned V3 service launch policy.
    ///
    /// V2-only deployments cannot satisfy broker-owned PID 1 queries. The
    /// signed V3 credential must name both exact argv vectors and unit
    /// fragments, bound to this deployment's signed V2 contract.
    ///
    /// # Errors
    ///
    /// Rejects a missing policy or any changed physical or observed fragment
    /// path, inode, mode, length, or content.
    pub fn service_launch(
        &self,
        inspector: bool,
    ) -> Result<ProtectedServiceLaunchV3<'_>, InspectorDeploymentErrorV2> {
        self.revalidate()?;
        let policy = self
            .launch_policy
            .as_ref()
            .ok_or(InspectorDeploymentErrorV2::Invalid)?;
        Ok(policy.service(inspector))
    }
}

fn credential_present(path: &Path) -> Result<bool, InspectorDeploymentErrorV2> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect credential name", source)),
    }
}

impl RetainedMember {
    fn open(expectation: MemberExpectation) -> Result<Self, InspectorDeploymentErrorV2> {
        require_canonical_path(Path::new(&expectation.path))?;
        let descriptor = open_nofollow(Path::new(&expectation.path))?;
        let metadata = descriptor
            .metadata()
            .map_err(|source| io_error("inspect member", source))?;
        verify_member(&descriptor, &metadata, &expectation)?;
        Ok(Self {
            expectation,
            descriptor,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> Result<(), InspectorDeploymentErrorV2> {
        require_canonical_path(Path::new(&self.expectation.path))?;
        let pinned = self
            .descriptor
            .metadata()
            .map_err(|source| io_error("reinspect pinned member", source))?;
        let reopened = open_nofollow(Path::new(&self.expectation.path))?;
        let current = reopened
            .metadata()
            .map_err(|source| io_error("reinspect member path", source))?;
        if pinned.dev() != self.device
            || pinned.ino() != self.inode
            || current.dev() != self.device
            || current.ino() != self.inode
        {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        verify_member(&self.descriptor, &pinned, &self.expectation)?;
        verify_member(&reopened, &current, &self.expectation)
    }
}

fn require_canonical_path(path: &Path) -> Result<(), InspectorDeploymentErrorV2> {
    let resolved =
        std::fs::canonicalize(path).map_err(|source| io_error("resolve member path", source))?;
    if resolved != path {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn verify_payload(
    bytes: &[u8],
    generation: u64,
    key: &VerifyingKey,
) -> Result<DeploymentPayload, InspectorDeploymentErrorV2> {
    let split = bytes
        .len()
        .checked_sub(64)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let (serialized, signature) = bytes.split_at(split);
    let payload: DeploymentPayload =
        serde_json::from_slice(serialized).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    if serde_json::to_vec(&payload).map_err(|_| InspectorDeploymentErrorV2::Invalid)? != serialized
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let signature =
        Signature::from_slice(signature).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + serialized.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(serialized);
    key.verify_strict(&message, &signature)
        .map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    validate_payload(&payload, generation)?;
    Ok(payload)
}

fn validate_payload(
    payload: &DeploymentPayload,
    generation: u64,
) -> Result<(), InspectorDeploymentErrorV2> {
    if payload.generation != generation
        || payload.inspector_service_template != SERVICE_TEMPLATE
        || payload.inspector_socket_unit != SOCKET_UNIT
        || payload.inspector_v1_contract_digest == [0; 32]
        || !(6..=MAXIMUM_MEMBERS).contains(&payload.members.len())
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }

    let mut paths = BTreeSet::new();
    let mut roles = [0_u8; 6];
    for member in &payload.members {
        if !canonical_store_file(&member.path)
            || member.length < 4
            || member.length > MAXIMUM_MEMBER_BYTES
            || member.sha256 == [0; 32]
            || member.mode & !0o7777 != 0
            || member.mode & 0o222 != 0
            || !paths.insert(&member.path)
        {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        let slot = match member.role {
            MemberRole::Broker => Some(0),
            MemberRole::Inspector => Some(1),
            MemberRole::LifecycleWorker => Some(2),
            MemberRole::ManagerQueryHelper => Some(3),
            MemberRole::Interpreter => Some(4),
            MemberRole::Library => Some(5),
        };
        if let Some(index) = slot {
            roles[index] += 1;
        }
    }
    if roles[..4] != [1; 4] || roles[4] == 0 || roles[5] == 0 {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn canonical_store_file(path: &str) -> bool {
    if !path.starts_with("/nix/store/") || path.contains("//") || path.ends_with('/') {
        return false;
    }
    let mut components = path["/nix/store/".len()..].split('/');
    let Some(store_name) = components.next() else {
        return false;
    };
    let store_name = store_name.as_bytes();
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if store_name.len() < 34
        || store_name[32] != b'-'
        || !store_name[..32]
            .iter()
            .all(|byte| NIX_BASE32.contains(byte))
        || !store_name[33..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(byte))
    {
        return false;
    }
    let mut has_member = false;
    for component in components {
        if component.is_empty() || component == "." || component == ".." {
            return false;
        }
        has_member = true;
    }
    has_member
}

fn decode_verifier(bytes: &[u8]) -> Result<(u64, VerifyingKey), InspectorDeploymentErrorV2> {
    if bytes.len() != 80 || &bytes[..8] != KEY_MAGIC {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let expected = Sha256::new()
        .chain_update(KEY_DOMAIN)
        .chain_update(&bytes[..48])
        .finalize();
    if bytes[48..] != expected[..] {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let generation = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| InspectorDeploymentErrorV2::Invalid)?,
    );
    let key_bytes = bytes[16..48]
        .try_into()
        .map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    if generation == 0 {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok((generation, key))
}

fn read_credential(path: &Path, maximum: u64) -> Result<Vec<u8>, InspectorDeploymentErrorV2> {
    let descriptor = open_nofollow(path)?;
    let metadata = descriptor
        .metadata()
        .map_err(|source| io_error("inspect credential", source))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() > maximum
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    read_exact_at(&descriptor, metadata.len())
}

fn verify_member(
    descriptor: &File,
    metadata: &std::fs::Metadata,
    expectation: &MemberExpectation,
) -> Result<(), InspectorDeploymentErrorV2> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != expectation.mode
        || metadata.len() != expectation.length
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    if read_exact_at(descriptor, 4)? != b"\x7fELF" {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    if hash_member(descriptor, expectation.length)?[..] != expectation.sha256 {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let after = descriptor
        .metadata()
        .map_err(|source| io_error("reinspect hashed member", source))?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || after.mode() != metadata.mode()
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn hash_member(descriptor: &File, length: u64) -> Result<[u8; 32], InspectorDeploymentErrorV2> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < length {
        let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
            .map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
        let received = descriptor
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|source| io_error("hash pinned member", source))?;
        if received == 0 {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        digest.update(&buffer[..received]);
        offset += received as u64;
    }
    Ok(digest.finalize().into())
}

fn read_exact_at(descriptor: &File, length: u64) -> Result<Vec<u8>, InspectorDeploymentErrorV2> {
    let capacity = usize::try_from(length).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    let mut bytes = vec![0_u8; capacity];
    let mut offset = 0;
    while offset < capacity {
        let received = descriptor
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|source| io_error("read pinned file", source))?;
        if received == 0 {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        offset += received;
    }
    Ok(bytes)
}

fn open_nofollow(path: &Path) -> Result<File, InspectorDeploymentErrorV2> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io_error("open protected file", source.into()))?;
    Ok(File::from(descriptor))
}

fn io_error(operation: &'static str, source: io::Error) -> InspectorDeploymentErrorV2 {
    InspectorDeploymentErrorV2::Io { operation, source }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn member(role: MemberRole, suffix: &str) -> MemberExpectation {
        MemberExpectation {
            role,
            path: format!("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-test/bin/{suffix}"),
            length: 4,
            mode: 0o555,
            sha256: [7; 32],
        }
    }

    fn payload() -> DeploymentPayload {
        DeploymentPayload {
            generation: 9,
            inspector_service_template: SERVICE_TEMPLATE.to_owned(),
            inspector_socket_unit: SOCKET_UNIT.to_owned(),
            inspector_v1_contract_digest: [8; 32],
            members: vec![
                member(MemberRole::Broker, "broker"),
                member(MemberRole::Inspector, "inspector"),
                member(MemberRole::LifecycleWorker, "worker"),
                member(MemberRole::ManagerQueryHelper, "query"),
                member(MemberRole::Interpreter, "loader"),
                member(MemberRole::Library, "library"),
            ],
        }
    }

    fn sign(payload: &DeploymentPayload, signer: &SigningKey) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(payload).unwrap();
        let mut message = Vec::from(SIGNATURE_DOMAIN);
        message.extend_from_slice(&bytes);
        bytes.extend_from_slice(&signer.sign(&message).to_bytes());
        bytes
    }

    #[test]
    fn role_key_rejects_wrong_generation_and_framing() {
        let signer = SigningKey::from_bytes(&[17; 32]);
        let mut bytes = Vec::from(KEY_MAGIC.as_slice());
        bytes.extend_from_slice(&9_u64.to_be_bytes());
        bytes.extend_from_slice(signer.verifying_key().as_bytes());
        let checksum = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);

        assert_eq!(decode_verifier(&bytes).unwrap().0, 9);
        bytes[0] ^= 1;
        assert!(decode_verifier(&bytes).is_err());
        bytes[0] ^= 1;
        bytes[15] = 0;
        let checksum = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(&bytes[..48])
            .finalize();
        bytes[48..].copy_from_slice(&checksum);
        assert!(decode_verifier(&bytes).is_err());
    }

    #[test]
    fn signed_inventory_rejects_substitution_and_noncanonical_json() {
        let signer = SigningKey::from_bytes(&[19; 32]);
        let bytes = sign(&payload(), &signer);
        assert!(verify_payload(&bytes, 9, &signer.verifying_key()).is_ok());
        assert!(verify_payload(&bytes, 10, &signer.verifying_key()).is_err());

        let mut tampered = bytes.clone();
        tampered[25] ^= 1;
        assert!(verify_payload(&tampered, 9, &signer.verifying_key()).is_err());

        let mut noncanonical = serde_json::to_vec_pretty(&payload()).unwrap();
        let mut message = Vec::from(SIGNATURE_DOMAIN);
        message.extend_from_slice(&noncanonical);
        noncanonical.extend_from_slice(&signer.sign(&message).to_bytes());
        assert!(verify_payload(&noncanonical, 9, &signer.verifying_key()).is_err());
    }

    #[test]
    fn inventory_requires_exact_executable_roles_and_unit_names() {
        let mut candidate = payload();
        validate_payload(&candidate, 9).unwrap();

        candidate.members[3].role = MemberRole::Library;
        assert!(validate_payload(&candidate, 9).is_err());
        candidate = payload();
        candidate.members[5].path = candidate.members[4].path.clone();
        assert!(validate_payload(&candidate, 9).is_err());
        candidate = payload();
        candidate.inspector_service_template = "other@.service".to_owned();
        assert!(validate_payload(&candidate, 9).is_err());
    }

    #[test]
    fn inventory_rejects_path_aliases_and_mutable_members() {
        let mut candidate = payload();
        candidate.members[0].path.push_str("/../broker");
        assert!(validate_payload(&candidate, 9).is_err());
        candidate = payload();
        candidate.members[0].path.push_str("/./broker");
        assert!(validate_payload(&candidate, 9).is_err());
        candidate = payload();
        candidate.members[0].mode = 0o755;
        assert!(validate_payload(&candidate, 9).is_err());
    }

    #[test]
    fn optional_credentials_fail_closed_on_half_installed_pair() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            ProtectedInspectorDeploymentV2::load_optional(directory.path())
                .unwrap()
                .is_none()
        );

        std::fs::write(directory.path().join(launch_policy::CREDENTIAL_NAME), []).unwrap();
        assert!(ProtectedInspectorDeploymentV2::load_optional(directory.path()).is_err());
        std::fs::remove_file(directory.path().join(launch_policy::CREDENTIAL_NAME)).unwrap();

        std::fs::write(directory.path().join(KEY_NAME), []).unwrap();
        assert!(ProtectedInspectorDeploymentV2::load_optional(directory.path()).is_err());

        let dangling = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing-key", dangling.path().join(KEY_NAME)).unwrap();
        std::os::unix::fs::symlink("missing-contract", dangling.path().join(CONTRACT_NAME))
            .unwrap();
        assert!(ProtectedInspectorDeploymentV2::load_optional(dangling.path()).is_err());
    }

    #[test]
    fn v2_only_inventory_cannot_authorize_a_service_query() {
        let deployment = ProtectedInspectorDeploymentV2 {
            members: Vec::new(),
            launch_policy: None,
        };

        assert!(deployment.service_launch(true).is_err());
        assert!(deployment.service_launch(false).is_err());
    }

    #[test]
    fn member_path_rejects_symlinked_component() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let alias = directory.path().join("alias");
        std::fs::write(&target, b"member").unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        assert!(require_canonical_path(&target).is_ok());
        assert!(require_canonical_path(&alias).is_err());
    }
}
