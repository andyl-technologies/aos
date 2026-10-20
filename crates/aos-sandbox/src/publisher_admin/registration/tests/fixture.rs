//! Shares actual protected policy and native cgroup setup for registration tests.
//!
//! The existing protected-directory test helper bypasses ancestor-policy setup
//! only; journal ownership, exclusive locking, record validation and durable
//! writes remain real. Cgroups are opened read-only and never created or changed.

#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures intentionally panic."
)]

use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_core::format::encode_policy;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, CacheDomainId, DecodeLimits, IncarnationId, ObjectDigest,
    PrincipalId, ProjectId, RawClockProvenance, ResourceId, SandboxId,
};
use aos_sandbox_linux::cgroup::CgroupV2Root;

use aos_sandbox_core::{Grant, GrantId, Operation, OperationSet, ResourceKind, RevocationScopeId};
use aos_sandbox_protocol::local_holder_session::LocalSessionScope;

use super::*;
use crate::publisher_admin::policy::{
    PublisherControllerHeadV1, PublisherResourceBindingV1,
    PublisherRevocationHeadV1,
};
use aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1;
use crate::{JournalLimits, RecordNamespace};

const PROVENANCE: [u8; 16] = [0x22; 16];
const CONTROLLER: [u8; 16] = [0x66; 16];

pub(crate) struct FixtureConfig {
    pub(crate) revocation_scope: RevocationScopeId,
    pub(crate) clock_provenance: [u8; 16],
    pub(crate) policy_limits: PublisherPolicyLimits,
}

pub(crate) struct Fixture {
    pub(crate) journal: Journal,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) scope: LocalSessionScope,
    pub(crate) config: FixtureConfig,
    pub(crate) policy: PreparedPublisherPolicyRevisionV1,
}

pub(crate) fn open_journal(directory: &Path) -> Journal {
    let uid = fs::metadata(directory)
        .expect("test directory metadata")
        .uid();
    Journal::open_protected_at_uid(directory, "issuance.journal", JournalLimits::default(), uid)
        .expect("protected test journal")
        .0
}

pub(crate) fn fixture(install_policy: bool, allow_publish: bool) -> Fixture {
    let directory = tempfile::tempdir().expect("test directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut journal = open_journal(directory.path());
    let scope = LocalSessionScope {
        holder: PrincipalId::from_bytes([1; 16]),
        project: ProjectId::from_bytes([2; 16]),
        sandbox: SandboxId::from_bytes([3; 16]),
        incarnation: IncarnationId::from_bytes([4; 16]),
        epoch: AssignmentEpoch::new(7),
        cache_resource: ResourceId::from_bytes([5; 16]),
    };
    let config = FixtureConfig {
        revocation_scope: RevocationScopeId::from_bytes([6; 16]),
        clock_provenance: PROVENANCE,
        policy_limits: PublisherPolicyLimits::default(),
    };
    let domain = CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([7; 16]));
    let grants = if allow_publish {
        vec![
            Grant::new(
                GrantId::from_bytes([8; 16]),
                ResourceKind::CachePublish,
                OperationSet::one(Operation::Publish),
                Selector::Resource {
                    resource: scope.cache_resource,
                },
                false,
            )
            .expect("policy grant"),
        ]
    } else {
        Vec::new()
    };
    let policy = Policy::new(
        Vec::new(),
        Vec::new(),
        grants,
        Vec::new(),
        ResourceProfile::new(Vec::new()).expect("resource profile"),
        Vec::new(),
        domain,
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .expect("policy");
    let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        scope.project,
        1,
        100,
        200,
        &encode_policy(&policy),
        DecodeLimits::default(),
    )
    .expect("prepared policy");
    {
        let mut store =
            PublisherPolicyStore::load(&mut journal, config.policy_limits).expect("policy store");
        store
            .install_resource_from_trusted_controller(
                [0x11; 16],
                &PublisherResourceBindingV1::new(
                    scope.cache_resource,
                    scope.project,
                    domain,
                    ObjectDigest::from_bytes([9; 32]),
                )
                .expect("resource binding"),
            )
            .expect("install resource");
        if install_policy {
            store
                .publish_policy_from_trusted_controller([0x12; 16], None, &policy)
                .expect("install policy");
        }
        store
            .advance_controller_from_trusted_controller(
                [0x13; 16],
                None,
                PublisherControllerHeadV1 {
                    principal: PrincipalId::from_bytes(CONTROLLER),
                    generation: 1,
                },
            )
            .expect("controller head");
        store
            .advance_revocation_from_trusted_controller(
                [0x14; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope: config.revocation_scope,
                    generation: 1,
                },
            )
            .expect("revocation head");
    }
    Fixture {
        journal,
        directory,
        scope,
        config,
        policy,
    }
}

pub(crate) fn anchor() -> RetainedCgroupAnchor {
    let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").expect("cgroup root").into())
        .expect("typed cgroup root");
    let membership = fs::read_to_string("/proc/self/cgroup").expect("own cgroup");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .expect("unified hierarchy");
    root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
        .expect("own cgroup anchor")
}

pub(crate) fn sample(wall: i64, boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(PROVENANCE).expect("test provenance"),
        KernelBootId::current().expect("host boot").into_bytes(),
        wall,
        boottime,
    )
    .expect("paired sample")
}
