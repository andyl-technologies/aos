//! Real-filesystem qualification fixture for the protected inspector store.
//!
//! The fixture is compiled only with `kernel-tests`. It feeds synthetic
//! validated-Ready fields through the broker-side policy constructor, then
//! exercises the store through caller-opened directory descriptors. It does
//! not prove actual peer or Ready authentication, deployment placement, or MAC
//! authority.

use std::error::Error;
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::immutable_file::FsVerityPublicationRoot;
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use serde_json::{Value, json};

use super::*;
use crate::namespace_inspector::{
    BrokerLifecycleWorkerInspectionContextV1, InspectorProcessIdentityV1,
    KernelAuthenticatedInspectorPeerV1, KernelAuthenticatedSystemdManagerV1,
    PendingLifecycleWorkerInspectionV1, ProvisionedNetworkNamespaceInspectorV1,
    ValidatedLifecycleWorkerLeaderV1,
};

/// Lists the exact assertions made by the protected-store ext4 fixture.
pub const PROTECTED_STORE_EXT4_CASES: &[&str] = &[
    "genuine-five-fd-topology",
    "mismatched-expected-view-rejected",
    "aliased-physical-role-rejected",
    "expected-publish-exact-readback",
    "all-roots-reopened-for-expected-lookup",
    "exact-absence-after-reopen",
    "spent-first-claim",
    "all-roots-reopened-for-exact-replay",
    "spent-attempt-mismatch-rejected",
    "wrong-expected-record-role-rejected",
    "wrong-spent-record-role-rejected",
    "ambiguous-cross-mount-publish-rejected",
];

const SUCCESS_MARKER: &str = "AOS_NAMESPACE_INSPECTOR_PROTECTED_STORE_EXT4_OK";

struct StorePaths {
    expected_staging: PathBuf,
    expected_final: PathBuf,
    spent_staging: PathBuf,
    spent_final: PathBuf,
}

impl StorePaths {
    fn below(root: &Path) -> Self {
        Self {
            expected_staging: root.join("expected-staging"),
            expected_final: root.join("expected-final"),
            spent_staging: root.join("spent-staging"),
            spent_final: root.join("spent-final"),
        }
    }

    fn provision(&self) -> Result<ProvisionedInspectorProtectedStores, Box<dyn Error>> {
        provision_with_paths(
            &self.expected_staging,
            &self.expected_final,
            &self.expected_final,
            &self.spent_staging,
            &self.spent_final,
        )
    }
}

/// Exercises the protected inspector store on caller-prepared ext4 directories.
///
/// `root` must contain mode-0700 `expected-staging`, `expected-final`,
/// `spent-staging`, `spent-final`, and `ambiguous-spent-staging` directories.
/// `ambiguous_spent_final` must be a separate bind mount of another mode-0700
/// directory on the same ext4 filesystem. No digest or record bytes are
/// accepted from the caller.
///
/// # Errors
///
/// Returns an error when root admission, fs-verity materialization, publication,
/// root-reopen lookup, replay classification, wrong-role rejection, or the
/// cross-mount ambiguous-publication assertion fails.
pub fn run_namespace_inspector_protected_store_ext4_fixture(
    root: &Path,
    ambiguous_spent_final: &Path,
) -> Result<Value, Box<dyn Error>> {
    let paths = StorePaths::below(root);

    assert_topology_rejections(&paths)?;

    let stores = paths.provision()?;
    let (broker, inspector) = stores.into_roles();
    let expected = expected_attempt(0x11)?;
    let published = broker.publish(&expected).map_err(owned_error)?;
    require(
        published == expected,
        "expected publication readback changed canonical policy",
    )?;

    // Destroy every retained root before reconstructing the store from paths.
    drop(broker);
    drop(inspector);

    let restarted = paths.provision()?;
    let (restarted_broker, restarted_inspector) = restarted.into_roles();
    let looked_up = restarted_inspector
        .expected()
        .lookup(&expected.nonce)
        .map_err(owned_error)?;
    require(
        looked_up.as_ref() == Some(&expected),
        "reconstructed store did not recover exact expected policy",
    )?;
    require(
        restarted_inspector
            .expected()
            .lookup(&[0x12; 32])
            .map_err(owned_error)?
            .is_none(),
        "missing expected policy was not exact absence",
    )?;
    require(
        restarted_inspector
            .spent()
            .claim_once(&expected)
            .map_err(owned_error)?,
        "first spent claim was not created",
    )?;

    drop(restarted_broker);
    drop(restarted_inspector);

    let replay_restart = paths.provision()?;
    let (replay_broker, replay_inspector) = replay_restart.into_roles();
    require(
        replay_inspector
            .expected()
            .lookup(&expected.nonce)
            .map_err(owned_error)?
            .as_ref()
            == Some(&expected),
        "second fresh root set did not recover exact expected policy",
    )?;
    require(
        !replay_inspector
            .spent()
            .claim_once(&expected)
            .map_err(owned_error)?,
        "exact spent replay was not classified as replay",
    )?;

    let mismatch_original = expected_attempt(0x21)?;
    require(
        replay_inspector
            .spent()
            .claim_once(&mismatch_original)
            .map_err(owned_error)?,
        "mismatch control claim was not created",
    )?;
    let mut mismatched_attempt = mismatch_original.clone();
    mismatched_attempt.boot_id = [0x22; 16];
    mismatched_attempt.policy_digest = mismatched_attempt.compute_digest().map_err(owned_error)?;
    require(
        matches!(
            replay_inspector.spent().claim_once(&mismatched_attempt),
            Err(InspectorSpentClaimError::ExistingMismatch { .. })
        ),
        "spent record accepted the same nonce with different bound policy",
    )?;

    let wrong_expected = expected_attempt(0x31)?;
    publish_wrong_role_record(
        &paths.expected_staging,
        &paths.expected_final,
        RecordRole::Expected,
        wrong_expected.nonce,
        &encode_spent_record(SpentRecord::from_expected(&wrong_expected)).map_err(owned_error)?,
    )?;
    require(
        replay_inspector
            .expected()
            .lookup(&wrong_expected.nonce)
            .is_err(),
        "expected lookup accepted a sealed spent-role record",
    )?;

    let wrong_spent = expected_attempt(0x32)?;
    publish_wrong_role_record(
        &paths.spent_staging,
        &paths.spent_final,
        RecordRole::Spent,
        wrong_spent.nonce,
        &encode_expected_record(&wrong_spent).map_err(owned_error)?,
    )?;
    require(
        matches!(
            replay_inspector.spent().claim_once(&wrong_spent),
            Err(InspectorSpentClaimError::ExistingUnreadable { .. })
        ),
        "spent claim accepted a sealed expected-role record",
    )?;

    drop(replay_broker);
    drop(replay_inspector);

    assert_ambiguous_publication_rejected(&paths, root, ambiguous_spent_final)?;

    Ok(json!({
        "schema_version": "aos.sandbox.namespace-inspector-protected-store-ext4-proof/v1",
        "success_marker": SUCCESS_MARKER,
        "policy_source": "internally-derived-synthetic-validated-ready-fixture",
        "reopen_boundary": "all-store-values-dropped-and-roots-reopened",
        "cases": PROTECTED_STORE_EXT4_CASES,
    }))
}

fn assert_topology_rejections(paths: &StorePaths) -> Result<(), Box<dyn Error>> {
    let admitted = paths.provision()?;
    drop(admitted);

    let mismatched_expected = provision_with_paths(
        &paths.expected_staging,
        &paths.expected_final,
        &paths.spent_final,
        &paths.spent_staging,
        &paths.spent_final,
    );
    require(
        matches!(
            mismatched_expected,
            Err(ref error) if error.to_string().contains("expected-final directory views do not match")
        ),
        "different expected-final directory views passed admission",
    )?;

    let aliased_role = provision_with_paths(
        &paths.expected_final,
        &paths.expected_final,
        &paths.expected_final,
        &paths.spent_staging,
        &paths.spent_final,
    );
    require(
        matches!(
            aliased_role,
            Err(ref error) if error.to_string().contains("roles alias one directory")
        ),
        "aliased physical store roles passed admission",
    )
}

fn assert_ambiguous_publication_rejected(
    paths: &StorePaths,
    root: &Path,
    ambiguous_spent_final: &Path,
) -> Result<(), Box<dyn Error>> {
    let stores = provision_with_paths(
        &paths.expected_staging,
        &paths.expected_final,
        &paths.expected_final,
        &root.join("ambiguous-spent-staging"),
        ambiguous_spent_final,
    )?;
    let (broker, inspector) = stores.into_roles();
    let expected = expected_attempt(0x41)?;
    let result = inspector.spent().claim_once(&expected);
    let failed_closed = match &result {
        Err(InspectorSpentClaimError::Publish(
            InspectorProtectedStorePublishError::Publication(
                NoReplacePublicationError::RenameOutcomeAmbiguous { source, artifact },
            ),
        )) => {
            let exact_exdev = matches!(
                source,
                aos_sandbox_linux::Error::Syscall { operation, source }
                    if *operation == "renameat2"
                        && source.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error())
            );
            let private_path = root
                .join("ambiguous-spent-staging")
                .join(artifact.private_name().as_os_str());
            let final_path = ambiguous_spent_final.join(artifact.final_name().as_os_str());
            let observed_private = inspector
                .spent()
                .staging
                .0
                .open_named_sealed(
                    artifact.private_name(),
                    u64::try_from(SPENT_RECORD_BYTES).map_err(owned_error)?,
                )
                .map_err(owned_error)?
                .ok_or_else(|| owned_error("ambiguous private name disappeared"))?;
            let descriptor_before = rustix::fs::fstat(artifact.as_fd()).map_err(owned_error)?;
            let private_metadata = std::fs::metadata(private_path)?;
            let descriptor_after = rustix::fs::fstat(artifact.as_fd()).map_err(owned_error)?;
            let retained_private_unchanged = descriptor_before.st_dev == descriptor_after.st_dev
                && descriptor_before.st_ino == descriptor_after.st_ino
                && descriptor_before.st_size == descriptor_after.st_size
                && descriptor_before.st_nlink == descriptor_after.st_nlink
                && private_metadata.dev() == descriptor_before.st_dev
                && private_metadata.ino() == descriptor_before.st_ino
                && private_metadata.len() == artifact.bytes()
                && u64::try_from(descriptor_before.st_size) == Ok(artifact.bytes())
                && descriptor_before.st_nlink == 1
                && observed_private.device() == descriptor_before.st_dev
                && observed_private.inode() == descriptor_before.st_ino
                && observed_private.bytes() == artifact.bytes()
                && observed_private.observed_verity_digest() == artifact.verity_digest();
            let destination_absent = matches!(
                std::fs::symlink_metadata(final_path),
                Err(ref error)
                    if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error())
            );

            exact_exdev && retained_private_unchanged && destination_absent
        }
        _ => false,
    };

    drop(result);

    drop(broker);
    drop(inspector);

    require(
        failed_closed,
        "cross-mount rename did not remain an ambiguous publication error",
    )
}

fn provision_with_paths(
    expected_staging: &Path,
    broker_expected_final: &Path,
    inspector_expected_final: &Path,
    spent_staging: &Path,
    spent_final: &Path,
) -> Result<ProvisionedInspectorProtectedStores, Box<dyn Error>> {
    ProvisionedInspectorProtectedStores::from_owned(
        open_directory(expected_staging)?,
        open_directory(broker_expected_final)?,
        open_directory(inspector_expected_final)?,
        open_directory(spent_staging)?,
        open_directory(spent_final)?,
    )
    .map_err(owned_error)
}

fn publish_wrong_role_record(
    staging_path: &Path,
    final_path: &Path,
    name_role: RecordRole,
    nonce: [u8; 32],
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let staging =
        FsVerityPublicationRoot::from_owned(open_directory(staging_path)?).map_err(owned_error)?;
    let final_root =
        FsVerityPublicationRoot::from_owned(open_directory(final_path)?).map_err(owned_error)?;
    let names = record_names(name_role, nonce).map_err(owned_error)?;
    let credential = sealed_source("aosni-wrong-role-fixture", bytes).map_err(owned_error)?;
    let mut verifier = ExactRecordVerifier::new(bytes);
    let sealed = staging
        .materialize_and_seal_exact_mode(
            credential
                .as_fd()
                .try_clone_to_owned()
                .map_err(owned_error)?,
            names.private,
            u64::try_from(bytes.len()).map_err(owned_error)?,
            &mut verifier,
        )
        .map_err(owned_error)?;
    sealed
        .publish_noreplace_into(&final_root, names.final_name)
        .map_err(owned_error)?;
    Ok(())
}

fn expected_attempt(seed: u8) -> Result<ExpectedInspectorAttemptV1, Box<dyn Error>> {
    let process = InspectorProcessIdentityV1 {
        pid: 300,
        thread_group_id: 300,
        parent_pid: 299,
        cgroup_id: 5_100,
    };
    let deployment = ProvisionedNetworkNamespaceInspectorV1 {
        boot_id: [0x07; 16],
        broker: peer(100),
        inspector: peer(200),
        systemd_manager: KernelAuthenticatedSystemdManagerV1 {
            pid: 1,
            thread_group_id: 1,
            parent_pid: 0,
            cgroup_id: 17,
            uid: 0,
            gid: 0,
        },
        launch_contract_digest: ObjectDigest::from_bytes([0x06; 32]),
    };
    let pending = PendingLifecycleWorkerInspectionV1::from_validated_ready(
        ValidatedLifecycleWorkerLeaderV1 {
            process,
            cgroup: "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@0-984321-543_876-0.service".to_owned(),
            request_id: [seed.wrapping_add(1); 16],
            effect_digest: ObjectDigest::from_bytes([seed.wrapping_add(2); 32]),
            dispatch_digest: ObjectDigest::from_bytes([seed.wrapping_add(3); 32]),
        },
        BrokerLifecycleWorkerInspectionContextV1 {
            forbidden_host: namespace(u64::from(seed) + 1),
            forbidden_target: namespace(u64::from(seed) + 2),
        },
        &deployment,
        [seed; 32],
        deployment.boot_id,
        10,
        20,
    )
    .map_err(owned_error)?;
    Ok(pending.expected)
}

fn peer(seed: u32) -> KernelAuthenticatedInspectorPeerV1 {
    KernelAuthenticatedInspectorPeerV1 {
        process: InspectorProcessIdentityV1 {
            pid: seed,
            thread_group_id: seed,
            parent_pid: seed - 1,
            cgroup_id: u64::from(seed) * 17,
        },
        uid: 0,
        gid: 0,
    }
}

fn namespace(seed: u64) -> NamespaceIdentity {
    NamespaceIdentity {
        device: seed,
        inode: seed * 100,
    }
}

fn open_directory(path: &Path) -> Result<OwnedFd, Box<dyn Error>> {
    Ok(File::open(path)?.into())
}

fn owned_error(error: impl Display) -> Box<dyn Error> {
    Box::new(io::Error::other(error.to_string()))
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(Box::new(io::Error::other(message)))
    }
}
