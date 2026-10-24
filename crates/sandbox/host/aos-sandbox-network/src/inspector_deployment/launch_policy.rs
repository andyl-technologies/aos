//! Versioned, signer-bound Network service argv and unit-fragment custody.
//!
//! The V3 credential is optional at broker startup but mandatory for a broker
//! PID 1 query. It is signed by the V2 role key under a distinct domain and
//! commits to the exact signed V2 contract bytes. Both service fragments are
//! pinned as physical read-only files; the signed `FragmentPath` reported by
//! PID 1 must resolve to the same physical file.
//!
//! ```text
//! inspector-launch-policy-v3 = canonical JSON {
//!   "version": 3, "generation": u64,
//!   "deployment_contract_sha256": [u8; 32],
//!   "inspector": ServiceLaunchV3,
//!   "lifecycle_worker": ServiceLaunchV3
//! } || Ed25519(signature-domain || JSON bytes)
//! ServiceLaunchV3 = {
//!   "unit_template": string, "fragment_path": string,
//!   "physical_fragment": { "path": string, "length": u64,
//!                          "mode": u32, "sha256": [u8; 32] },
//!   "arguments": [string]
//! }
//! ```

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    InspectorDeploymentErrorV2, MemberRole, RetainedMember, canonical_store_file, hash_member,
    io_error, open_nofollow, read_credential, require_canonical_path,
};

pub(super) const CREDENTIAL_NAME: &str = "inspector-launch-policy-v3";
const SIGNATURE_DOMAIN: &[u8] = b"aos.network.inspector.launch-policy.v3\0";
const INSPECTOR_TEMPLATE: &str = "aos-sandbox-network-namespace-inspector@.service";
const WORKER_TEMPLATE: &str = "aos-sandbox-network-lifecycle-worker@.service";
const MAXIMUM_POLICY_BYTES: u64 = 16 * 1024;
const MAXIMUM_FRAGMENT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_PATH_BYTES: usize = 512;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchPolicyPayloadV3 {
    version: u8,
    generation: u64,
    deployment_contract_sha256: [u8; 32],
    inspector: ServiceLaunchV3,
    lifecycle_worker: ServiceLaunchV3,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceLaunchV3 {
    unit_template: String,
    fragment_path: String,
    physical_fragment: FragmentExpectationV3,
    arguments: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FragmentExpectationV3 {
    path: String,
    length: u64,
    mode: u32,
    sha256: [u8; 32],
}

#[derive(Debug)]
struct RetainedFragmentV3 {
    expectation: FragmentExpectationV3,
    observed_path: String,
    descriptor: File,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct RetainedServiceLaunchV3 {
    unit_template: String,
    arguments: Vec<String>,
    fragment: RetainedFragmentV3,
}

/// Retains a signed launch policy and both exact unit fragments.
#[derive(Debug)]
pub(super) struct ProtectedLaunchPolicyV3 {
    inspector: RetainedServiceLaunchV3,
    lifecycle_worker: RetainedServiceLaunchV3,
}

/// Borrows one revalidated, signed service launch expectation.
#[derive(Clone, Copy, Debug)]
pub struct ProtectedServiceLaunchV3<'a> {
    unit_template: &'a str,
    fragment_path: &'a str,
    arguments: &'a [String],
}

impl ProtectedServiceLaunchV3<'_> {
    /// Returns the exact signed systemd service template.
    #[must_use]
    pub const fn unit_template(&self) -> &str {
        self.unit_template
    }

    /// Returns the exact signed PID 1 `FragmentPath` value.
    #[must_use]
    pub const fn fragment_path(&self) -> &str {
        self.fragment_path
    }

    /// Returns the complete signed `ExecStart` argument vector.
    #[must_use]
    pub const fn arguments(&self) -> &[String] {
        self.arguments
    }
}

impl ProtectedLaunchPolicyV3 {
    pub(super) fn load(
        path: &Path,
        generation: u64,
        key: &VerifyingKey,
        deployment_contract: &[u8],
        members: &[RetainedMember],
    ) -> Result<Self, InspectorDeploymentErrorV2> {
        let inspector_executable = member_path(members, MemberRole::Inspector)?;
        let worker_executable = member_path(members, MemberRole::LifecycleWorker)?;
        let bytes = read_credential(path, MAXIMUM_POLICY_BYTES)?;
        let payload = verify_policy(
            &bytes,
            generation,
            key,
            deployment_contract,
            inspector_executable,
            worker_executable,
        )?;

        let policy = Self {
            inspector: RetainedServiceLaunchV3::open(payload.inspector)?,
            lifecycle_worker: RetainedServiceLaunchV3::open(payload.lifecycle_worker)?,
        };
        policy.revalidate()?;
        Ok(policy)
    }

    pub(super) fn revalidate(&self) -> Result<(), InspectorDeploymentErrorV2> {
        self.inspector.fragment.revalidate()?;
        self.lifecycle_worker.fragment.revalidate()
    }

    pub(super) fn service(&self, inspector: bool) -> ProtectedServiceLaunchV3<'_> {
        let launch = if inspector {
            &self.inspector
        } else {
            &self.lifecycle_worker
        };
        ProtectedServiceLaunchV3 {
            unit_template: &launch.unit_template,
            fragment_path: &launch.fragment.observed_path,
            arguments: &launch.arguments,
        }
    }
}

impl RetainedServiceLaunchV3 {
    fn open(expectation: ServiceLaunchV3) -> Result<Self, InspectorDeploymentErrorV2> {
        let fragment =
            RetainedFragmentV3::open(expectation.physical_fragment, expectation.fragment_path)?;
        Ok(Self {
            unit_template: expectation.unit_template,
            arguments: expectation.arguments,
            fragment,
        })
    }
}

impl RetainedFragmentV3 {
    fn open(
        expectation: FragmentExpectationV3,
        observed_path: String,
    ) -> Result<Self, InspectorDeploymentErrorV2> {
        let physical_path = Path::new(&expectation.path);
        require_canonical_path(physical_path)?;
        verify_observed_alias(&observed_path, physical_path)?;
        let descriptor = open_nofollow(physical_path)?;
        let metadata = descriptor
            .metadata()
            .map_err(|source| io_error("inspect unit fragment", source))?;
        verify_fragment(&descriptor, &metadata, &expectation)?;
        Ok(Self {
            expectation,
            observed_path,
            descriptor,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> Result<(), InspectorDeploymentErrorV2> {
        let physical_path = Path::new(&self.expectation.path);
        require_canonical_path(physical_path)?;
        verify_observed_alias(&self.observed_path, physical_path)?;
        let pinned = self
            .descriptor
            .metadata()
            .map_err(|source| io_error("reinspect pinned unit fragment", source))?;
        let reopened = open_nofollow(physical_path)?;
        let current = reopened
            .metadata()
            .map_err(|source| io_error("reinspect unit fragment path", source))?;
        if pinned.dev() != self.device
            || pinned.ino() != self.inode
            || current.dev() != self.device
            || current.ino() != self.inode
        {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        verify_fragment(&self.descriptor, &pinned, &self.expectation)?;
        verify_fragment(&reopened, &current, &self.expectation)
    }
}

fn member_path(
    members: &[RetainedMember],
    role: MemberRole,
) -> Result<&str, InspectorDeploymentErrorV2> {
    members
        .iter()
        .find(|member| member.expectation.role == role)
        .map(|member| member.expectation.path.as_str())
        .ok_or(InspectorDeploymentErrorV2::Invalid)
}

fn verify_policy(
    bytes: &[u8],
    generation: u64,
    key: &VerifyingKey,
    deployment_contract: &[u8],
    inspector_executable: &str,
    worker_executable: &str,
) -> Result<LaunchPolicyPayloadV3, InspectorDeploymentErrorV2> {
    let split = bytes
        .len()
        .checked_sub(64)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let (serialized, signature) = bytes.split_at(split);
    let policy: LaunchPolicyPayloadV3 =
        serde_json::from_slice(serialized).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    if serde_json::to_vec(&policy).map_err(|_| InspectorDeploymentErrorV2::Invalid)? != serialized {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let signature =
        Signature::from_slice(signature).map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + serialized.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(serialized);
    key.verify_strict(&message, &signature)
        .map_err(|_| InspectorDeploymentErrorV2::Invalid)?;
    validate_policy(
        &policy,
        generation,
        deployment_contract,
        inspector_executable,
        worker_executable,
    )?;
    Ok(policy)
}

fn validate_policy(
    policy: &LaunchPolicyPayloadV3,
    generation: u64,
    deployment_contract: &[u8],
    inspector_executable: &str,
    worker_executable: &str,
) -> Result<(), InspectorDeploymentErrorV2> {
    let digest: [u8; 32] = Sha256::digest(deployment_contract).into();
    if policy.version != 3
        || policy.generation != generation
        || policy.deployment_contract_sha256 != digest
        || policy.inspector.physical_fragment.path == policy.lifecycle_worker.physical_fragment.path
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    validate_service(
        &policy.inspector,
        INSPECTOR_TEMPLATE,
        inspector_executable,
        1,
    )?;
    validate_service(
        &policy.lifecycle_worker,
        WORKER_TEMPLATE,
        worker_executable,
        8,
    )
}

fn validate_service(
    service: &ServiceLaunchV3,
    template: &str,
    executable: &str,
    argument_count: usize,
) -> Result<(), InspectorDeploymentErrorV2> {
    if service.unit_template != template
        || !normalized_absolute_path(&service.fragment_path)
        || !canonical_store_file(&service.physical_fragment.path)
        || Path::new(&service.fragment_path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(template)
        || Path::new(&service.physical_fragment.path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(template)
        || service.physical_fragment.length == 0
        || service.physical_fragment.length > MAXIMUM_FRAGMENT_BYTES
        || service.physical_fragment.mode == 0
        || service.physical_fragment.mode & !0o7777 != 0
        || service.physical_fragment.mode & (0o222 | 0o111 | 0o7000) != 0
        || service.physical_fragment.sha256 == [0; 32]
        || service.arguments.len() != argument_count
        || service.arguments.first().map(String::as_str) != Some(executable)
        || service
            .arguments
            .iter()
            .any(|argument| !normalized_absolute_path(argument))
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn normalized_absolute_path(path: &str) -> bool {
    path.len() > 1
        && path.len() <= MAXIMUM_PATH_BYTES
        && !path.as_bytes().contains(&0)
        && Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path[1..]
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

fn verify_observed_alias(
    observed: &str,
    physical: &Path,
) -> Result<(), InspectorDeploymentErrorV2> {
    let resolved = std::fs::canonicalize(observed)
        .map_err(|source| io_error("resolve systemd unit fragment", source))?;
    if resolved != physical {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn verify_fragment(
    descriptor: &File,
    metadata: &std::fs::Metadata,
    expectation: &FragmentExpectationV3,
) -> Result<(), InspectorDeploymentErrorV2> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != expectation.mode
        || metadata.len() != expectation.length
        || hash_member(descriptor, expectation.length)? != expectation.sha256
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let after = descriptor
        .metadata()
        .map_err(|source| io_error("reinspect hashed unit fragment", source))?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || after.mode() != metadata.mode()
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const STORE: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-test";

    fn service(template: &str, executable: &str, arguments: Vec<String>) -> ServiceLaunchV3 {
        ServiceLaunchV3 {
            unit_template: template.to_owned(),
            fragment_path: format!("{STORE}/{template}"),
            physical_fragment: FragmentExpectationV3 {
                path: format!("{STORE}/{template}"),
                length: 13,
                mode: 0o444,
                sha256: [5; 32],
            },
            arguments: std::iter::once(executable.to_owned())
                .chain(arguments)
                .collect(),
        }
    }

    fn payload(contract: &[u8]) -> LaunchPolicyPayloadV3 {
        let inspector_executable = format!("{STORE}/bin/inspector");
        let worker_executable = format!("{STORE}/bin/worker");
        LaunchPolicyPayloadV3 {
            version: 3,
            generation: 9,
            deployment_contract_sha256: Sha256::digest(contract).into(),
            inspector: service(INSPECTOR_TEMPLATE, &inspector_executable, vec![]),
            lifecycle_worker: service(
                WORKER_TEMPLATE,
                &worker_executable,
                vec!["/var/lib/aos".to_owned(); 7],
            ),
        }
    }

    fn sign(policy: &LaunchPolicyPayloadV3, signer: &SigningKey) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(policy).unwrap();
        let mut message = Vec::from(SIGNATURE_DOMAIN);
        message.extend_from_slice(&bytes);
        bytes.extend_from_slice(&signer.sign(&message).to_bytes());
        bytes
    }

    #[test]
    fn signed_policy_binds_generation_contract_and_both_launches() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let contract = b"signed V2 contract";
        let policy = payload(contract);
        let bytes = sign(&policy, &signer);
        let inspector_executable = format!("{STORE}/bin/inspector");
        let worker_executable = format!("{STORE}/bin/worker");

        assert!(
            verify_policy(
                &bytes,
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_ok()
        );
        assert!(
            verify_policy(
                &bytes,
                10,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );
        assert!(
            verify_policy(
                &bytes,
                9,
                &signer.verifying_key(),
                b"other contract",
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );

        let mut wrong_argv = payload(contract);
        wrong_argv.lifecycle_worker.arguments[1] = "relative".to_owned();
        assert!(
            verify_policy(
                &sign(&wrong_argv, &signer),
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );
        let mut wrong_fragment = payload(contract);
        wrong_fragment.inspector.physical_fragment.path = format!("{STORE}/other.service");
        assert!(
            verify_policy(
                &sign(&wrong_fragment, &signer),
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );
        let mut wrong_executable = payload(contract);
        wrong_executable.inspector.arguments[0] = worker_executable.clone();
        assert!(
            verify_policy(
                &sign(&wrong_executable, &signer),
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );
    }

    #[test]
    fn signature_domain_and_canonical_json_are_strict() {
        let signer = SigningKey::from_bytes(&[12; 32]);
        let contract = b"signed V2 contract";
        let policy = payload(contract);
        let mut pretty = serde_json::to_vec_pretty(&policy).unwrap();
        let signature = signer.sign(&[SIGNATURE_DOMAIN, pretty.as_slice()].concat());
        pretty.extend_from_slice(&signature.to_bytes());
        let inspector_executable = format!("{STORE}/bin/inspector");
        let worker_executable = format!("{STORE}/bin/worker");
        assert!(
            verify_policy(
                &pretty,
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );

        let mut wrong_domain = serde_json::to_vec(&policy).unwrap();
        let signature =
            signer.sign(&[b"wrong-domain\0".as_slice(), wrong_domain.as_slice()].concat());
        wrong_domain.extend_from_slice(&signature.to_bytes());
        assert!(
            verify_policy(
                &wrong_domain,
                9,
                &signer.verifying_key(),
                contract,
                &inspector_executable,
                &worker_executable
            )
            .is_err()
        );
    }

    #[test]
    fn observed_fragment_alias_must_resolve_to_pinned_physical_file() {
        let directory = tempfile::tempdir().unwrap();
        let physical = directory.path().join("pinned.service");
        let replacement = directory.path().join("replacement.service");
        let alias = directory.path().join("observed.service");
        std::fs::write(&physical, b"pinned").unwrap();
        std::fs::write(&replacement, b"replacement").unwrap();
        std::os::unix::fs::symlink(&physical, &alias).unwrap();

        assert!(verify_observed_alias(alias.to_str().unwrap(), &physical).is_ok());
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        assert!(verify_observed_alias(alias.to_str().unwrap(), &physical).is_err());
    }
}
