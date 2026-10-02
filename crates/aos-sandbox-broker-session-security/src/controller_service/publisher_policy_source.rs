//! Signed deployment source for the initial project publisher-policy head.
//!
//! The root-provisioned credentials are a 272-byte signed `AOSPSC01` packet,
//! exact canonical policy CBOR, and a dedicated Ed25519 verification key. The
//! signature covers the domain-separated first 208 packet bytes. Its object
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

use aos_sandbox::publisher_policy::{
    GitUploadBootstrapAppendV1, GitUploadBootstrapErrorV1, PublisherPolicyError,
    PublisherPolicyLimits, VerifiedPublisherPolicySourceV1,
};
use aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1;
use aos_sandbox::publisher_sessions::PublisherSessionScope;
use aos_sandbox_core::{GitUploadCapacityV1, RawPairedClockSample};
use aos_sandbox::ownership_resume::OwnershipClockObservationError;
use super::ProductionController;
use super::publisher_credential::read_required_credential;
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

struct SignedSourceV1(VerifiedPublisherPolicySourceV1);

/// Installs or exact-replays one signed initial source before serving requests.
pub(super) fn install_from_process_credentials(
    controller: &mut ProductionController,
    scope: PublisherSessionScope,
) -> Result<(), PublisherPolicySourceErrorV1> {
    let packet = read_required_credential(PACKET_NAME, PACKET_BYTES, PACKET_BYTES)
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let policy = read_required_credential(POLICY_NAME, 1, MAXIMUM_POLICY_BYTES)
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
    let key = read_required_credential(KEY_NAME, 32, 32)
        .map_err(|_| PublisherPolicySourceErrorV1::Credential)?;
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
    if source.0.policy().policy().effective_grants().iter()
        .any(|grant| grant.resource_kind() == aos_sandbox_core::ResourceKind::GitObjectDatabase)
    {
        // The ordinary loader has no original capacity input or bootstrap cut.
        return Err(PublisherPolicySourceErrorV1::Source);
    }
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
        VerifiedPublisherPolicySourceV1::verify_ordinary(packet, canonical_policy, key, scope, now)
            .map(Self)
            .map_err(|_| PublisherPolicySourceErrorV1::Source)
    }

    fn install(
        self,
        controller: &mut ProductionController,
    ) -> Result<(), PublisherPolicySourceErrorV1> {
        let mut store = controller.publisher_policies(PublisherPolicyLimits::default())?;
        self.0.install_initial_policy(&mut store).map_err(|error| match error {
            GitUploadBootstrapErrorV1::Conflict => PublisherPolicySourceErrorV1::Conflict,
            GitUploadBootstrapErrorV1::Store(cause) => PublisherPolicySourceErrorV1::Store(cause),
            _ => PublisherPolicySourceErrorV1::Source,
        })
    }

    fn transaction_id(&self, kind: &[u8]) -> [u8; 16] {
        self.0.transaction_id(kind)
    }
}


// A fixed SAME-worker destination. Every returned verification/append outcome
// is parked here before another readback, clock sample or protected crossing.
pub(super) struct PublisherPolicyBootstrapAttemptV1 {
    credentials: PublisherPolicyBootstrapCredentialCustodyV1,
    source: Option<Result<VerifiedPublisherPolicySourceV1, GitUploadBootstrapErrorV1>>,
    capacity: Option<Result<GitUploadCapacityV1, GitUploadBootstrapErrorV1>>,
    installs: [Option<Result<(), GitUploadBootstrapErrorV1>>; 4],
    append: Option<Result<GitUploadBootstrapAppendV1, GitUploadBootstrapErrorV1>>,
    original_clock: Option<RawPairedClockSample>,
    first_failure: Option<BootstrapCauseV1>,
    postcheck_debt: Option<BootstrapCauseV1>,
    started: bool,
}

#[derive(Debug, thiserror::Error)]
enum BootstrapCauseV1 {
    #[error("original fixed credential custody failed")]
    Lower,
    #[error("original signed policy verification failed")]
    Source,
    #[error("original capacity verification failed")]
    Capacity,
    #[error("original initial policy install failed")]
    Install(usize),
    #[error("original bootstrap preparation failed")]
    AppendPreparation,
    #[error("original bootstrap protected crossing failed")]
    Append,
    #[error("original protected policy store failed")]
    Store(#[source] PublisherPolicyError),
    #[error("original bootstrap current readback failed")]
    Current(#[source] GitUploadBootstrapErrorV1),
    #[error("original paired clock observation failed")]
    Clock(#[source] OwnershipClockObservationError),
    #[error("original bootstrap phase, clock or interval is invalid")]
    Rejected,
}

impl PublisherPolicyBootstrapAttemptV1 {
    pub(super) fn new() -> Self {
        Self {
            credentials: PublisherPolicyBootstrapCredentialCustodyV1::new(),
            source: None,
            capacity: None,
            installs: std::array::from_fn(|_| None),
            append: None,
            original_clock: None,
            first_failure: None,
            postcheck_debt: None,
            started: false,
        }
    }

    pub(super) fn install_bootstrap_once(
        &mut self,
        controller: &mut ProductionController,
        scope: PublisherSessionScope,
    ) -> Result<(), ()> {
        if self.started {
            if self.first_failure.is_none() && self.postcheck_debt.is_none() {
                self.first_failure = Some(BootstrapCauseV1::Rejected);
            }
            self.credentials.fence();
            return Err(());
        }
        // Prearm before any capture, decode, clock or Journal effect.
        self.started = true;
        let result = self.install_inner(controller, scope);
        if let Err(cause) = result {
            self.first_failure.get_or_insert(cause);
        }

        // A returned Err is parked before bookends, including their own Err.
        // Do not retry a failed partial lower batch or replace its originals.
        if self.credentials.ready().is_some() {
            if let Err(cause) = self.check_originals_and_time() {
                self.postcheck_debt.get_or_insert(cause);
            }
        }
        if self.first_failure.is_some() || self.postcheck_debt.is_some() {
            self.credentials.fence();
            return Err(());
        }
        Ok(())
    }

    fn install_inner(
        &mut self,
        controller: &mut ProductionController,
        scope: PublisherSessionScope,
    ) -> Result<(), BootstrapCauseV1> {
        self.credentials.capture().map_err(|_| BootstrapCauseV1::Lower)?;
        let now = self.check_originals_and_time()?;
        let [packet, policy, key, _] = self.credentials.ready()
            .ok_or(BootstrapCauseV1::Rejected)?;
        let packet = packet.try_into().map_err(|_| BootstrapCauseV1::Rejected)?;
        let key = key.try_into().map_err(|_| BootstrapCauseV1::Rejected)?;
        self.source = Some(VerifiedPublisherPolicySourceV1::verify(packet, policy, key, scope, now));
        if matches!(self.source.as_ref(), Some(Err(_))) {
            return Err(BootstrapCauseV1::Source);
        }

        self.check_originals_and_time()?;
        let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let body = self.credentials.ready().ok_or(BootstrapCauseV1::Rejected)?[3];
        self.capacity = Some(source.verify_git_capacity(body));
        if matches!(self.capacity.as_ref(), Some(Err(_))) {
            return Err(BootstrapCauseV1::Capacity);
        }

        let mut store = controller.publisher_policies(PublisherPolicyLimits::default())
            .map_err(BootstrapCauseV1::Store)?;
        for index in 0..4 {
            self.check_originals_and_time()?;
            let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(BootstrapCauseV1::Rejected)?;
            self.installs[index] = Some(match index {
                0 => source.install_initial_resource(&mut store),
                1 => source.install_initial_controller(&mut store),
                2 => source.install_initial_revocation(&mut store),
                _ => source.install_initial_policy_head(&mut store),
            });
            if matches!(self.installs[index].as_ref(), Some(Err(_))) {
                return Err(BootstrapCauseV1::Install(index));
            }
            self.check_originals_and_time()?;
        }

        self.check_originals_and_time()?;
        let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let capacity = self.capacity.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let body = self.credentials.ready().ok_or(BootstrapCauseV1::Rejected)?[3];
        self.append = Some(store.prepare_git_upload_bootstrap(source, capacity, body));
        if matches!(self.append.as_ref(), Some(Err(_))) {
            return Err(BootstrapCauseV1::AppendPreparation);
        }

        self.check_originals_and_time()?;
        let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let append = self.append.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        if store.preflight_git_upload_bootstrap(append, source).is_err() {
            return Err(BootstrapCauseV1::Append);
        }

        self.check_originals_and_time()?;
        let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let append = self.append.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        if store.initialize_git_upload_bootstrap(append, source).is_err() {
            return Err(BootstrapCauseV1::Append);
        }

        let now = self.check_originals_and_time()?;
        let source = self.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let capacity = self.capacity.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        let append = self.append.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(BootstrapCauseV1::Rejected)?;
        store.current_git_upload_bootstrap(append, source, capacity, &self.credentials, now)
            .map_err(BootstrapCauseV1::Current)?;
        Ok(())
    }

    fn check_originals_and_time(&mut self) -> Result<i64, BootstrapCauseV1> {
        self.credentials.recheck().map_err(|_| BootstrapCauseV1::Lower)?;
        let sample = sample_ownership_clock().map_err(BootstrapCauseV1::Clock)?;
        if let Some(original) = self.original_clock {
            if sample.host_boot_id() != original.host_boot_id()
                || sample.boottime_nanoseconds() < original.boottime_nanoseconds()
            {
                return Err(BootstrapCauseV1::Rejected);
            }
        } else {
            self.original_clock = Some(sample);
        }
        if let Some(Ok(source)) = &self.source {
            if sample.wall_seconds() < source.policy().not_before()
                || sample.wall_seconds() >= source.policy().expires_at()
            {
                return Err(BootstrapCauseV1::Rejected);
            }
        }
        Ok(sample.wall_seconds())
    }

    /// Checks the complete original bootstrap before lending its project DATA.
    pub(super) fn current_cache_project(
        &mut self,
        controller: &mut ProductionController,
    ) -> Result<aos_sandbox_core::ProjectId, ()> {
        if self.first_failure.is_some() || self.postcheck_debt.is_some() {
            return Err(());
        }
        let returned = (|| {
            let now = self.check_originals_and_time()?;
            let source = self.source.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(BootstrapCauseV1::Rejected)?;
            let capacity = self.capacity.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(BootstrapCauseV1::Rejected)?;
            let append = self.append.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(BootstrapCauseV1::Rejected)?;
            let mut store = controller.publisher_policies(PublisherPolicyLimits::default())
                .map_err(BootstrapCauseV1::Store)?;
            store.current_git_upload_bootstrap(append, source, capacity, &self.credentials, now)
                .map_err(BootstrapCauseV1::Current)?;
            Ok::<_, BootstrapCauseV1>(source.policy().policy().project())
        })();
        match returned {
            Ok(project) => Ok(project),
            Err(cause) => {
                self.first_failure.get_or_insert(cause);
                Err(())
            }
        }
    }

    /// Checks route DATA against the SAME original signed bootstrap and capacity.
    /// The short store borrow ends before the evaluator mutates its Journal.
    pub(super) fn check_git_read_route(
        &mut self,
        controller: &mut ProductionController,
        project: aos_sandbox_core::ProjectId,
        resource: aos_sandbox_core::ResourceId,
    ) -> Result<(), ()> {
        let current = self.current_cache_project(controller)?;
        let capacity = self.capacity.as_ref().and_then(|result| result.as_ref().ok());
        if current != project || capacity.map(|capacity| capacity.resource()) != Some(resource) {
            self.first_failure.get_or_insert(BootstrapCauseV1::Rejected);
            return Err(());
        }
        Ok(())
    }

    // Diagnostics borrow the original cause; no stringification or move-out.
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.first_failure.as_ref().or(self.postcheck_debt.as_ref())?;
        match cause {
            BootstrapCauseV1::Lower => self.credentials.failure()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            BootstrapCauseV1::Source => self.source.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            BootstrapCauseV1::Capacity => self.capacity.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            BootstrapCauseV1::Install(index) => self.installs[*index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            BootstrapCauseV1::AppendPreparation => self.append.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            BootstrapCauseV1::Append => self.append.as_ref()?.as_ref().ok()?.failure(),
            BootstrapCauseV1::Store(error) => Some(error),
            BootstrapCauseV1::Current(error) => Some(error),
            BootstrapCauseV1::Clock(error) => Some(error),
            BootstrapCauseV1::Rejected => Some(cause),
        }
    }
}

#[cfg(test)]
mod tests {

    // These signatures authenticate only test DATA. No Journal, PID1, runtime
    // owner, currentness or admission-positive fixture is constructed.
    #[test]
    fn full_policy_signature_commits_distinct_canonical_capacity_input() {
        use aos_sandbox_core::{
            ExportId, FeatureRef, MediaType, PortableMediaType, ResourceDimension,
            ResourceVector, descriptor_for_bytes, encode_git_upload_capacity_v1,
        };
        let (mut packet, policy, key, scope) = source_fixture();
        let ordinary = aos_sandbox_core::format::decode_policy(&policy, DecodeLimits::default()).unwrap();
        let capacity = GitUploadCapacityV1::new(
            scope.project, ResourceId::from_bytes([10; 16]), ExportId::from_bytes([11; 16]),
            1, ObjectDigest::from_bytes([12; 32]), ObjectDigest::from_bytes([13; 32]),
            ResourceVector::new([100; ResourceDimension::COUNT]),
            ResourceVector::ZERO.with(ResourceDimension::ConcurrentOperations, 1),
            100_000, 100, 1, 1_000_000_000,
            [
                FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 1, 0).unwrap(),
                FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap(),
            ],
        ).unwrap();
        let body = encode_git_upload_capacity_v1(&capacity);
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::GitUploadCapacity.as_str()).unwrap(), &body,
        );
        let mut grants = ordinary.effective_grants().to_vec();
        grants.push(Grant::new(
            GrantId::from_bytes([14; 16]), ResourceKind::GitObjectDatabase,
            OperationSet::one(Operation::ContentRead),
            Selector::Resource { resource: capacity.resource() }, false,
        ).unwrap());
        let features = vec![
            FeatureRef::new("aos.sandbox.git.upload-operation-capacity", 1, 0).unwrap(),
            FeatureRef::new("aos.sandbox.git.whole-odb-read", 1, 0).unwrap(),
        ];
        let policy = Policy::new(
            features, vec![descriptor], grants, Vec::new(), ordinary.limits().clone(),
            Vec::new(), ordinary.cache_domain(), ordinary.revocation(), None, Vec::new(),
        ).unwrap();
        let policy = encode_policy(&policy);
        let prepared = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            scope.project, 1, 100, 200, &policy, DecodeLimits::default(),
        ).unwrap();
        packet[176..208].copy_from_slice(prepared.descriptor().digest().as_bytes());
        let mut statement = SIGNING_DOMAIN.to_vec();
        statement.extend_from_slice(&packet[..SIGNED_BYTES]);
        let signer = SigningKey::from_bytes(&[17; 32]);
        packet[SIGNED_BYTES..].copy_from_slice(&signer.sign(&statement).to_bytes());

        let verified = VerifiedPublisherPolicySourceV1::verify(packet, &policy, key, scope, 150).unwrap();
        assert_eq!(verified.verify_git_capacity(&body).unwrap(), capacity);
        assert_ne!(verified.resource().resource(), capacity.resource());

        let mut changed = body.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(matches!(
            verified.verify_git_capacity(&changed), Err(GitUploadBootstrapErrorV1::Descriptor(_)),
        ));
        assert!(verified.verify_git_capacity(&[0]).is_err());
    }

    #[test]
    fn empty_bootstrap_has_no_originals_or_ready_data() {
        let attempt = PublisherPolicyBootstrapAttemptV1::new();

        assert!(attempt.credentials.ready().is_none());
        assert!(attempt.source.is_none());
        assert!(attempt.capacity.is_none());
        assert!(attempt.append.is_none());
        assert!(!attempt.started);
        assert!(attempt.failure().is_none());
    }

    use super::*;
    use aos_sandbox::publisher_policy::PreparedPublisherPolicyRevisionV1;
    use aos_sandbox_core::{
        DecodeLimits, NodeId, ObjectDigest, Operation, PrincipalId, ProjectId,
        ResourceId, ResourceKind, RevocationScopeId, Selector,
    };
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
        assert_eq!(verified.0.resource().project(), scope.project);
        assert_eq!(verified.0.resource().resource(), scope.cache_resource);
        assert_eq!(verified.0.controller().generation, 1);
        assert_eq!(verified.0.revocation().generation, 1);
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
