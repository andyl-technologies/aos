//! Shared signed project authorization fixtures for verifier and retention tests.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

use aos_sandbox_core::format::encode_policy;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
};
use aos_sandbox_core::{CacheDomainId, DecodeLimits, ProjectId};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::{Journal, JournalLimits, RecordNamespace};

use super::project_authorization_source_v2::{
    HEAD_DOMAIN, PACKET_BYTES, PinnedPublisherProjectAuthorizationIssuerV2, REVISION_DOMAIN,
    commitment, encode_project_authorization_issuer_credential_v2,
};
use super::{
    PreparedPublisherPolicyRevisionV1, PublisherPolicyStore, policy_current_key,
    policy_revision_key,
};

pub(super) struct TestDirectory(PathBuf);

impl TestDirectory {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aos-project-authorization-v2-{}-{}",
            std::process::id(),
            ProjectId::new()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    pub(super) fn open(&self) -> Journal {
        self.open_with_limits(JournalLimits::default())
    }

    pub(super) fn open_with_limits(&self, limits: JournalLimits) -> Journal {
        let uid = fs::metadata(&self.0).unwrap().uid();
        Journal::open_protected_at_uid(&self.0, "controller.journal", limits, uid)
            .unwrap()
            .0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn policy(
    project: ProjectId,
    generation: u64,
    not_before: i64,
) -> PreparedPublisherPolicyRevisionV1 {
    let policy = Policy::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        ResourceProfile::new(Vec::new()).unwrap(),
        Vec::new(),
        CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*project.as_bytes()),
        ),
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .unwrap();
    PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        project,
        generation,
        not_before,
        1_000,
        &encode_policy(&policy),
        DecodeLimits::default(),
    )
    .unwrap()
}

pub(super) fn packet(
    store: &PublisherPolicyStore<'_>,
    project: ProjectId,
    signer: &SigningKey,
    signer_generation: u64,
    request_id: [u8; 16],
    epoch: u64,
) -> [u8; PACKET_BYTES] {
    let current = store.current_policy(project).unwrap().unwrap();
    let head = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_current_key(project),
        )
        .unwrap();
    let revision = store
        .journal
        .get(
            RecordNamespace::PublisherPolicy,
            &policy_revision_key(project, current.generation()),
        )
        .unwrap();

    let mut bytes = [0; PACKET_BYTES];
    bytes[..8].copy_from_slice(b"AOSPSC02");
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    bytes[12..20].copy_from_slice(&signer_generation.to_be_bytes());
    bytes[20..36].copy_from_slice(project.as_bytes());
    bytes[36..44].copy_from_slice(&current.generation().to_be_bytes());
    bytes[44..76].copy_from_slice(commitment(HEAD_DOMAIN, head).as_bytes());
    bytes[76..108].copy_from_slice(commitment(REVISION_DOMAIN, revision).as_bytes());
    bytes[108..124].copy_from_slice(&request_id);
    bytes[124..132].copy_from_slice(&epoch.to_be_bytes());
    for (index, ceiling) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
        let offset = 132 + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&ceiling.to_be_bytes());
    }
    resign(&mut bytes, signer);
    bytes
}

pub(super) fn resign(bytes: &mut [u8; PACKET_BYTES], signer: &SigningKey) {
    let mut preimage =
        b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0"
            .to_vec();
    preimage.extend_from_slice(&bytes[..160]);
    bytes[160..].copy_from_slice(&signer.sign(&preimage).to_bytes());
}

pub(super) fn pin(
    signer: &SigningKey,
    generation: u64,
) -> PinnedPublisherProjectAuthorizationIssuerV2 {
    let credential =
        encode_project_authorization_issuer_credential_v2(generation, &signer.verifying_key())
            .unwrap();
    PinnedPublisherProjectAuthorizationIssuerV2::decode(&credential).unwrap()
}
