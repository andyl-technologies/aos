//! Signed deployment source for the initial project publisher-policy head.
//!
//! The root-provisioned credentials are a 272-byte signed `AOSPSC01` packet,
//! exact canonical policy CBOR, and a dedicated Ed25519 verification key. The
//! signature covers the domain-separated first 176 packet bytes. Its object
//! descriptor digest commits the separately loaded CBOR, while the controller
//! journal preserves exact generation-one heads across service restarts.
//!
//! ```text
//! AOSPSC01 | publisher-principal[16] | node[16] | project[16] | resource[16]
//!          | isolation-policy[32]
//!          | controller[16] | controller-generation:u64be
//!          | revocation-scope[16] | revocation-generation:u64be
//!          | policy-generation:u64be | not-before:i64be | expires:i64be
//!          | canonical-policy-object-digest[32] | ed25519-signature[64]
//! ```

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherPolicyLimits,
    PublisherResourceBindingV1, PublisherRevocationHeadV1,
};
use aos_sandbox::publisher_sessions::PublisherSessionScope;
use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{
    DecodeLimits, NodeId, ObjectDigest, Operation, PrincipalId, ProjectId, ResourceId,
    ResourceKind, RevocationScopeId, Selector,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use super::ProductionController;
use crate::controller_ownership::sample_ownership_clock;

const PACKET_NAME: &str = "publisher-policy-source-v1";
const POLICY_NAME: &str = "publisher-policy-v1.cbor";
const KEY_NAME: &str = "publisher-policy-source-public-key-v1";
const MAGIC: &[u8; 8] = b"AOSPSC01";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source-transaction.v1\0";
const PACKET_BYTES: usize = 272;
const SIGNED_BYTES: usize = 208;
const MAXIMUM_POLICY_BYTES: usize = 4 * 1024 * 1024;

/// Reports missing, substituted, or stale publisher-policy deployment authority.
#[derive(Debug, thiserror::Error)]
pub(super) enum PublisherPolicySourceErrorV1 {
    /// A required protected systemd credential is absent or unsafe.
    #[error("publisher policy source credential is invalid")]
    Credential,
    /// The source signature, scope, policy, or validity is invalid.
    #[error("signed publisher policy source is invalid")]
    Source,
    /// A retained policy head differs from the exact signed initial source.
    #[error("publisher policy source conflicts with protected current state")]
    Conflict,
    /// Protected journal replay or durability failed.
    #[error("publisher policy source installation failed: {0}")]
    Store(#[from] aos_sandbox::publisher_policy::PublisherPolicyError),
}

struct SignedSourceV1 {
    packet: [u8; PACKET_BYTES],
    policy: PreparedPublisherPolicyRevisionV1,
    resource: PublisherResourceBindingV1,
    controller: PublisherControllerHeadV1,
    revocation: PublisherRevocationHeadV1,
}

/// Installs or exact-replays one signed initial source before serving requests.
pub(super) fn install_from_process_credentials(
    controller: &mut ProductionController,
    scope: PublisherSessionScope,
) -> Result<(), PublisherPolicySourceErrorV1> {
    let packet = read_credential(PACKET_NAME, PACKET_BYTES, PACKET_BYTES)?;
    let policy = read_credential(POLICY_NAME, 1, MAXIMUM_POLICY_BYTES)?;
    let key = read_credential(KEY_NAME, 32, 32)?;
    let packet: [u8; PACKET_BYTES] = packet
        .try_into()
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let now = sample_ownership_clock()
        .map_err(|_| PublisherPolicySourceErrorV1::Source)?
        .wall_seconds();
    let source = SignedSourceV1::verify(packet, &policy, key, scope, now)?;
    source.install(controller)
}

impl SignedSourceV1 {
    fn verify(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
    ) -> Result<Self, PublisherPolicySourceErrorV1> {
        if &packet[..8] != MAGIC {
            return Err(PublisherPolicySourceErrorV1::Source);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key).map_err(|_| PublisherPolicySourceErrorV1::Source)?;
        let signature = Signature::from_slice(&packet[SIGNED_BYTES..])
            .map_err(|_| PublisherPolicySourceErrorV1::Source)?;
        let mut statement = Vec::with_capacity(SIGNING_DOMAIN.len() + SIGNED_BYTES);
        statement.extend_from_slice(SIGNING_DOMAIN);
        statement.extend_from_slice(&packet[..SIGNED_BYTES]);
        verifying_key
            .verify(&statement, &signature)
            .map_err(|_| PublisherPolicySourceErrorV1::Source)?;

        let publisher_principal = PrincipalId::from_bytes(read_array(&packet, 8)?);
        let node = NodeId::from_bytes(read_array(&packet, 24)?);
        let project = ProjectId::from_bytes(read_array(&packet, 40)?);
        let resource_id = ResourceId::from_bytes(read_array(&packet, 56)?);
        let isolation = ObjectDigest::from_bytes(read_array(&packet, 72)?);
        let controller_principal = PrincipalId::from_bytes(read_array(&packet, 104)?);
        let controller_generation = read_u64(&packet, 120)?;
        let revocation_scope = RevocationScopeId::from_bytes(read_array(&packet, 128)?);
        let revocation_generation = read_u64(&packet, 144)?;
        let policy_generation = read_u64(&packet, 152)?;
        let not_before = read_i64(&packet, 160)?;
        let expires_at = read_i64(&packet, 168)?;
        let expected_digest: [u8; 32] = read_array(&packet, 176)?;
        if publisher_principal != scope.principal
            || node != scope.node
            || project != scope.project
            || resource_id != scope.cache_resource
            || controller_principal.as_bytes() == &[0; 16]
            || revocation_scope.as_bytes() == &[0; 16]
            || controller_generation != 1
            || revocation_generation != 1
            || policy_generation != 1
            || now < not_before
            || now >= expires_at
        {
            return Err(PublisherPolicySourceErrorV1::Source);
        }
        let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            project,
            policy_generation,
            not_before,
            expires_at,
            canonical_policy,
            DecodeLimits::default(),
        )
        .map_err(|_| PublisherPolicySourceErrorV1::Source)?;
        if policy.descriptor().digest().as_bytes() != &expected_digest
            || policy.policy().cache_domain().kind() != CacheDomainKind::Project
            || !policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
            || policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && !matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
        {
            return Err(PublisherPolicySourceErrorV1::Source);
        }
        let resource = PublisherResourceBindingV1::new(
            resource_id,
            project,
            policy.policy().cache_domain(),
            isolation,
        )
        .map_err(|_| PublisherPolicySourceErrorV1::Source)?;
        Ok(Self {
            packet,
            policy,
            resource,
            controller: PublisherControllerHeadV1 {
                principal: controller_principal,
                generation: controller_generation,
            },
            revocation: PublisherRevocationHeadV1 {
                scope: revocation_scope,
                generation: revocation_generation,
            },
        })
    }

    fn install(
        self,
        controller: &mut ProductionController,
    ) -> Result<(), PublisherPolicySourceErrorV1> {
        let mut store = controller.publisher_policies(PublisherPolicyLimits::default())?;
        match store.resource_binding(self.resource.resource())? {
            Some(current) if current == self.resource => {}
            Some(_) => return Err(PublisherPolicySourceErrorV1::Conflict),
            None => {
                store.install_resource_from_trusted_controller(
                    self.transaction_id(b"resource"),
                    &self.resource,
                )?;
            }
        }
        match store.controller_head()? {
            Some(current) if current == self.controller => {}
            Some(_) => return Err(PublisherPolicySourceErrorV1::Conflict),
            None => {
                store.advance_controller_from_trusted_controller(
                    self.transaction_id(b"controller"),
                    None,
                    self.controller,
                )?;
            }
        }
        match store.revocation_head(self.revocation.scope)? {
            Some(current) if current == self.revocation => {}
            Some(_) => return Err(PublisherPolicySourceErrorV1::Conflict),
            None => {
                store.advance_revocation_from_trusted_controller(
                    self.transaction_id(b"revocation"),
                    None,
                    self.revocation,
                )?;
            }
        }
        match store.current_policy(self.policy.project())? {
            Some(current) if current == self.policy => Ok(()),
            Some(_) => Err(PublisherPolicySourceErrorV1::Conflict),
            None => {
                store.publish_policy_from_trusted_controller(
                    self.transaction_id(b"policy"),
                    None,
                    &self.policy,
                )?;
                Ok(())
            }
        }
    }

    fn transaction_id(&self, kind: &[u8]) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(kind)
            .chain_update(self.packet)
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }
}

fn read_array<const N: usize>(
    packet: &[u8],
    offset: usize,
) -> Result<[u8; N], PublisherPolicySourceErrorV1> {
    packet
        .get(offset..offset + N)
        .ok_or(PublisherPolicySourceErrorV1::Source)?
        .try_into()
        .map_err(|_| PublisherPolicySourceErrorV1::Source)
}

fn read_u64(packet: &[u8], offset: usize) -> Result<u64, PublisherPolicySourceErrorV1> {
    Ok(u64::from_be_bytes(read_array(packet, offset)?))
}

fn read_i64(packet: &[u8], offset: usize) -> Result<i64, PublisherPolicySourceErrorV1> {
    Ok(i64::from_be_bytes(read_array(packet, offset)?))
}

fn read_credential(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, PublisherPolicySourceErrorV1> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(PublisherPolicySourceErrorV1::Credential)?;
    let directory = Path::new(&directory);
    if !directory.is_absolute() {
        return Err(PublisherPolicySourceErrorV1::Credential);
    }
    let descriptor = open(
        &directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let process_uid = rustix::process::geteuid().as_raw();
    let length =
        usize::try_from(metadata.len()).map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    if !metadata.is_file()
        || !(minimum..=maximum).contains(&length)
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != process_uid)
        || metadata.mode() & 0o077 != 0
    {
        return Err(PublisherPolicySourceErrorV1::Credential);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    if file
        .read(&mut [0_u8; 1])
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?
        != 0
    {
        return Err(PublisherPolicySourceErrorV1::Credential);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::format::encode_policy;
    use aos_sandbox_core::model::{
        CacheDomain, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
    };
    use aos_sandbox_core::{CacheDomainId, Grant, GrantId, OperationSet};
    use ed25519_dalek::{Signer as _, SigningKey};

    fn source_fixture() -> ([u8; PACKET_BYTES], Vec<u8>, [u8; 32], PublisherSessionScope) {
        let scope = PublisherSessionScope {
            principal: PrincipalId::from_bytes([9; 16]),
            node: NodeId::from_bytes([8; 16]),
            project: ProjectId::from_bytes([1; 16]),
            cache_resource: ResourceId::from_bytes([2; 16]),
        };
        let grant = Grant::new(
            GrantId::from_bytes([4; 16]),
            ResourceKind::CachePublish,
            OperationSet::one(Operation::Publish),
            Selector::Resource {
                resource: scope.cache_resource,
            },
            false,
        )
        .expect("publisher grant");
        let policy = Policy::new(
            Vec::new(),
            Vec::new(),
            vec![grant],
            Vec::new(),
            ResourceProfile::new(Vec::new()).expect("resource profile"),
            Vec::new(),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
            RevocationPolicy::new(RevocationMode::DenyNew, 0),
            None,
            Vec::new(),
        )
        .expect("publisher policy");
        let policy = encode_policy(&policy);
        let prepared = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            scope.project,
            1,
            100,
            200,
            &policy,
            DecodeLimits::default(),
        )
        .expect("valid policy");
        let signer = SigningKey::from_bytes(&[17; 32]);
        let mut packet = [0; PACKET_BYTES];
        packet[..8].copy_from_slice(MAGIC);
        packet[8..24].copy_from_slice(scope.principal.as_bytes());
        packet[24..40].copy_from_slice(scope.node.as_bytes());
        packet[40..56].copy_from_slice(scope.project.as_bytes());
        packet[56..72].copy_from_slice(scope.cache_resource.as_bytes());
        packet[72..104].fill(5);
        packet[104..120].fill(6);
        packet[120..128].copy_from_slice(&1_u64.to_be_bytes());
        packet[128..144].fill(7);
        packet[144..152].copy_from_slice(&1_u64.to_be_bytes());
        packet[152..160].copy_from_slice(&1_u64.to_be_bytes());
        packet[160..168].copy_from_slice(&100_i64.to_be_bytes());
        packet[168..176].copy_from_slice(&200_i64.to_be_bytes());
        packet[176..208].copy_from_slice(prepared.descriptor().digest().as_bytes());
        let mut statement = SIGNING_DOMAIN.to_vec();
        statement.extend_from_slice(&packet[..SIGNED_BYTES]);
        packet[SIGNED_BYTES..].copy_from_slice(&signer.sign(&statement).to_bytes());
        (packet, policy, signer.verifying_key().to_bytes(), scope)
    }

    #[test]
    fn signed_source_binds_canonical_policy_scope_and_initial_heads() {
        let (packet, policy, key, scope) = source_fixture();
        let verified =
            SignedSourceV1::verify(packet, &policy, key, scope, 150).expect("valid signed source");
        assert_eq!(verified.resource.project(), scope.project);
        assert_eq!(verified.resource.resource(), scope.cache_resource);
        assert_eq!(verified.controller.generation, 1);
        assert_eq!(verified.revocation.generation, 1);
        assert_ne!(
            verified.transaction_id(b"resource"),
            verified.transaction_id(b"policy")
        );

        let mut changed_policy = policy.clone();
        changed_policy[0] ^= 1;
        assert!(SignedSourceV1::verify(packet, &changed_policy, key, scope, 150).is_err());
        let wrong_scope = PublisherSessionScope {
            project: ProjectId::from_bytes([10; 16]),
            ..scope
        };
        assert!(SignedSourceV1::verify(packet, &policy, key, wrong_scope, 150).is_err());
        let wrong_principal = PublisherSessionScope {
            principal: PrincipalId::from_bytes([10; 16]),
            ..scope
        };
        assert!(SignedSourceV1::verify(packet, &policy, key, wrong_principal, 150).is_err());
        let wrong_node = PublisherSessionScope {
            node: NodeId::from_bytes([10; 16]),
            ..scope
        };
        assert!(SignedSourceV1::verify(packet, &policy, key, wrong_node, 150).is_err());
        assert!(SignedSourceV1::verify(packet, &policy, key, scope, 200).is_err());

        let mut changed_packet = packet;
        changed_packet[72] ^= 1;
        assert!(SignedSourceV1::verify(changed_packet, &policy, key, scope, 150).is_err());
    }
}
