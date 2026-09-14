//! Deterministic lowering into the existing closed packet-policy program.
//!
//! The compiler resolves mediated destinations only through the exact immutable
//! project discovery snapshot selected by policy. It converts explicit ingress
//! allocations and discovered service addresses into canonical flow sets,
//! checks every quota before returning, and delegates the final closed profile
//! validation to [`crate::policy::NetworkPolicyProgramV1`].

use std::collections::BTreeMap;

use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_core::{FeatureRef, NetworkEndpointId, ObjectDigest, ServiceId};
use sha2::{Digest as _, Sha256};

use crate::allocation::NetworkNamespacePlanV1;
use crate::policy::{
    NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkPolicyProgramV1,
};

use super::egress::MediatedEgressPolicyV1;
use super::identity::{
    AdvancedNetworkIdentityV1, ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1,
};
use super::ingress::{IngressAllocationSetV1, IngressTranslationPlanV1};
use super::quota::{AdvancedNetworkQuotaV1, NetworkPolicyUsageV1};
use super::service_discovery::ProjectServiceDiscoverySnapshotV1;
use super::{
    AdvancedNetworkPolicyError, MAXIMUM_ADVANCED_NETWORK_ENDPOINTS, MAXIMUM_ADVANCED_NETWORK_FLOWS,
    MAXIMUM_ADVANCED_NETWORK_FLOWS_PER_ENDPOINT, nonzero_digest, strictly_increasing,
};

const POLICY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.advanced-policy.v1\0";
const COMPILED_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.compiled-advanced-policy.v2\0";
const MAXIMUM_POLICY_FEATURES: usize = 32;

/// Names the fixed reviewed artifacts used by the existing packet-program profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkEnforcementArtifactsV1 {
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
}

impl NetworkEnforcementArtifactsV1 {
    /// Constructs one fixed enforcement and optional lease-gate artifact pair.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a zero digest.
    pub fn new(
        enforcement_program_digest: ObjectDigest,
        lease_gate_program_digest: Option<ObjectDigest>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !nonzero_digest(enforcement_program_digest)
            || lease_gate_program_digest.is_some_and(|digest| !nonzero_digest(digest))
        {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        Ok(Self {
            enforcement_program_digest,
            lease_gate_program_digest,
        })
    }

    /// Returns the fixed default-deny enforcement-program digest.
    #[must_use]
    pub const fn enforcement_program_digest(self) -> ObjectDigest {
        self.enforcement_program_digest
    }

    /// Returns the fixed veth lease-gate digest, when required.
    #[must_use]
    pub const fn lease_gate_program_digest(self) -> Option<ObjectDigest> {
        self.lease_gate_program_digest
    }
}

/// Stores one canonical assignment-bound advanced Network policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkPolicyV1 {
    identity: AdvancedNetworkIdentityV1,
    kind: NetworkKind,
    egress: Option<MediatedEgressPolicyV1>,
    ingress: IngressAllocationSetV1,
    quota: AdvancedNetworkQuotaV1,
    hard_features: Vec<FeatureRef>,
    advisory_features: Vec<FeatureRef>,
    digest: ObjectDigest,
}

impl AdvancedNetworkPolicyV1 {
    /// Constructs one bounded canonical advanced policy.
    ///
    /// Isolated policy has neither egress nor ingress. Outbound policy has a
    /// mediated egress object and no ingress. Published policy has ingress and
    /// no egress. Project policy may combine either explicit set. Host network
    /// sharing remains outside this strong-boundary model.
    ///
    /// Hard and advisory feature sets must each be strictly ordered, bounded,
    /// and disjoint. The ingress owner and any discovery expectation must name
    /// the same complete identity and project.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for an incompatible policy kind,
    /// owner or project mismatch, or noncanonical feature sets.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: AdvancedNetworkIdentityV1,
        kind: NetworkKind,
        egress: Option<MediatedEgressPolicyV1>,
        ingress: IngressAllocationSetV1,
        quota: AdvancedNetworkQuotaV1,
        hard_features: Vec<FeatureRef>,
        advisory_features: Vec<FeatureRef>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if ingress.owner() != &identity
            || egress
                .as_ref()
                .is_some_and(|policy| policy.discovery().project() != identity.project())
        {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if hard_features.len() > MAXIMUM_POLICY_FEATURES
            || advisory_features.len() > MAXIMUM_POLICY_FEATURES
            || !strictly_increasing(&hard_features)
            || !strictly_increasing(&advisory_features)
            || hard_features
                .iter()
                .any(|feature| advisory_features.binary_search(feature).is_ok())
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        let has_egress = egress.is_some();
        let has_ingress = !ingress.allocations().is_empty();
        let shape_is_valid = match kind {
            NetworkKind::Isolated => !has_egress && !has_ingress,
            NetworkKind::Project => true,
            NetworkKind::Outbound => has_egress && !has_ingress,
            NetworkKind::Published => !has_egress && has_ingress,
            NetworkKind::Host => false,
        };
        if !shape_is_valid {
            return Err(AdvancedNetworkPolicyError::Unrepresentable);
        }

        let digest = policy_digest(
            &identity,
            kind,
            egress.as_ref(),
            &ingress,
            quota,
            &hard_features,
            &advisory_features,
        );
        Ok(Self {
            identity,
            kind,
            egress,
            ingress,
            quota,
            hard_features,
            advisory_features,
            digest,
        })
    }

    /// Returns the complete assignment and allocation identity.
    #[must_use]
    pub const fn identity(&self) -> &AdvancedNetworkIdentityV1 {
        &self.identity
    }

    /// Returns the closed portable exposure kind.
    #[must_use]
    pub const fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// Returns the mediated egress policy, when selected.
    #[must_use]
    pub const fn egress(&self) -> Option<&MediatedEgressPolicyV1> {
        self.egress.as_ref()
    }

    /// Returns the complete assignment-fenced ingress allocation set.
    #[must_use]
    pub const fn ingress(&self) -> &IngressAllocationSetV1 {
        &self.ingress
    }

    /// Returns the explicit quota governing compilation and replacement overlap.
    #[must_use]
    pub const fn quota(&self) -> AdvancedNetworkQuotaV1 {
        self.quota
    }

    /// Returns required hard features in canonical order.
    #[must_use]
    pub fn hard_features(&self) -> &[FeatureRef] {
        &self.hard_features
    }

    /// Returns advisory features in canonical order.
    #[must_use]
    pub fn advisory_features(&self) -> &[FeatureRef] {
        &self.advisory_features
    }

    /// Returns the commitment to the complete advanced policy.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSAPP01");
        bytes.extend_from_slice(&self.identity.encode_recovery());
        bytes.push(compiler_kind_code(self.kind));
        encode_compiler_blob(
            &mut bytes,
            self.egress
                .as_ref()
                .map(MediatedEgressPolicyV1::encode_recovery)
                .as_deref(),
        );
        let ingress = self.ingress.encode_recovery();
        encode_compiler_blob(&mut bytes, Some(&ingress));
        encode_compiler_quota(&mut bytes, self.quota);
        encode_features(&mut bytes, &self.hard_features);
        encode_features(&mut bytes, &self.advisory_features);
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 2 * 1024 * 1024 || bytes.get(..8) != Some(b"AOSAPP01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = CompilerReader::new(&bytes[8..]);
        let identity = AdvancedNetworkIdentityV1::decode_recovery(reader.take(398)?, authorities)?;
        let kind = decode_compiler_kind(reader.byte()?)?;
        let egress = match reader.blob(16 * 1024)? {
            Some(value) => Some(MediatedEgressPolicyV1::decode_recovery(value)?),
            None => None,
        };
        let ingress = IngressAllocationSetV1::decode_recovery(
            reader
                .blob(1024 * 1024)?
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
            authorities,
        )?;
        let quota = decode_compiler_quota(&mut reader)?;
        let hard = decode_features(&mut reader)?;
        let advisory = decode_features(&mut reader)?;
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::new(identity, kind, egress, ingress, quota, hard, advisory)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

/// Retains one advanced policy and its exact existing packet-program lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledAdvancedNetworkPolicyV1 {
    source: AdvancedNetworkPolicyV1,
    namespace_plan: NetworkNamespacePlanV1,
    discovery_digest: Option<ObjectDigest>,
    discovery_currentness: Option<ProtectedCurrentnessWitnessV1>,
    translation: IngressTranslationPlanV1,
    usage: NetworkPolicyUsageV1,
    program: NetworkPolicyProgramV1,
    digest: ObjectDigest,
}

impl CompiledAdvancedNetworkPolicyV1 {
    /// Returns the complete canonical source policy.
    #[must_use]
    pub const fn source(&self) -> &AdvancedNetworkPolicyV1 {
        &self.source
    }

    /// Returns the exact discovery snapshot used for lowering, when any.
    #[must_use]
    pub const fn discovery_digest(&self) -> Option<ObjectDigest> {
        self.discovery_digest
    }

    /// Returns protected discovery-currentness evidence used for lowering.
    #[must_use]
    pub const fn discovery_currentness(&self) -> Option<ProtectedCurrentnessWitnessV1> {
        self.discovery_currentness
    }

    /// Returns the exact revision-specific namespace-plan commitment.
    #[must_use]
    pub const fn namespace_plan_digest(&self) -> ObjectDigest {
        self.namespace_plan.digest()
    }

    /// Returns the exact existing namespace plan validated during lowering.
    #[must_use]
    pub const fn namespace_plan(&self) -> &NetworkNamespacePlanV1 {
        &self.namespace_plan
    }

    /// Returns the immutable listener translation/DNAT companion plan.
    #[must_use]
    pub const fn translation(&self) -> &IngressTranslationPlanV1 {
        &self.translation
    }

    /// Returns the checked resource usage of the lowered program.
    #[must_use]
    pub const fn usage(&self) -> NetworkPolicyUsageV1 {
        self.usage
    }

    /// Returns the existing closed packet-policy program.
    #[must_use]
    pub const fn program(&self) -> &NetworkPolicyProgramV1 {
        &self.program
    }

    /// Returns the commitment binding source, physical plan, packet program,
    /// artifacts, discovery, and ingress translation together.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSACP01");
        let source = self.source.encode_recovery();
        let namespace = self.namespace_plan.encode_recovery();
        let program = self.program.encode_recovery();
        encode_compiler_blob(&mut bytes, Some(&source));
        encode_compiler_blob(&mut bytes, Some(&namespace));
        match (self.discovery_digest, self.discovery_currentness) {
            (Some(digest), Some(witness)) => {
                bytes.push(1);
                bytes.extend_from_slice(digest.as_bytes());
                bytes.extend_from_slice(&witness.encode_recovery());
            }
            (None, None) => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 233]);
            }
            _ => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 233]);
            }
        }
        encode_compiler_blob(&mut bytes, Some(&program));
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 4 * 1024 * 1024 || bytes.get(..8) != Some(b"AOSACP01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = CompilerReader::new(&bytes[8..]);
        let source = AdvancedNetworkPolicyV1::decode_recovery(
            reader
                .blob(2 * 1024 * 1024)?
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
            authorities,
        )?;
        let namespace = NetworkNamespacePlanV1::decode_recovery(
            reader
                .blob(128 * 1024)?
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
        )
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let discovery_present = reader.boolean()?;
        let discovery_bytes = reader.array::<32>()?;
        let witness_bytes = reader.take(201)?;
        let (discovery_digest, discovery_currentness) = if discovery_present {
            let digest = ObjectDigest::from_bytes(discovery_bytes);
            let witness =
                ProtectedCurrentnessWitnessV1::rebind_recovery(witness_bytes, authorities)?;
            if witness.purpose() != super::identity::ProtectedWitnessPurposeV1::Discovery
                || witness.record_digest() != digest
                || witness.namespace()
                    != super::identity::project_namespace(source.identity.project())
            {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            (Some(digest), Some(witness))
        } else {
            if discovery_bytes != [0; 32] || witness_bytes != [0; 201] {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            (None, None)
        };
        if source.egress.is_some() != discovery_present {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let program = NetworkPolicyProgramV1::decode_recovery(
            reader
                .blob(1024 * 1024)?
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
        )
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        if !reader.finished()
            || !source
                .identity
                .physical()
                .matches_namespace_plan(&namespace)
            || namespace.kind() != source.kind
            || namespace.packet_program_digest() != program.digest()
            || namespace.enforcement_program_digest() != program.enforcement_program_digest()
            || namespace.lease_gate_program_digest() != program.lease_gate_program_digest()
        {
            return Err(AdvancedNetworkPolicyError::PhysicalIdentityMismatch);
        }
        let translation = IngressTranslationPlanV1::compile(&source.ingress, &namespace)?;
        let usage = usage_from_decoded(&source, &program)?;
        source.quota.admit(usage)?;
        let artifacts = NetworkEnforcementArtifactsV1::new(
            program.enforcement_program_digest(),
            program.lease_gate_program_digest(),
        )?;
        let digest = compiled_digest(
            &source,
            &namespace,
            discovery_digest,
            discovery_currentness,
            &translation,
            &program,
            artifacts,
        );
        let value = Self {
            source,
            namespace_plan: namespace,
            discovery_digest,
            discovery_currentness,
            translation,
            usage,
            program,
            digest,
        };
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

/// Deterministically lowers one advanced policy to `NetworkPolicyProgramV1`.
///
/// # Errors
///
/// Returns [`AdvancedNetworkPolicyError`] for missing, stale, or foreign
/// discovery; unresolved mediated destinations; endpoint/flow overflow;
/// quota exhaustion; or a final program shape that the existing closed profile
/// rejects. Semantically identical lowered packet flows collapse canonically.
pub fn compile_advanced_network_policy_v1(
    policy: AdvancedNetworkPolicyV1,
    namespace: &NetworkNamespacePlanV1,
    discovery: Option<&ProjectServiceDiscoverySnapshotV1>,
    artifacts: NetworkEnforcementArtifactsV1,
) -> Result<CompiledAdvancedNetworkPolicyV1, AdvancedNetworkPolicyError> {
    if !policy.identity.physical().matches_namespace_plan(namespace)
        || namespace.kind() != policy.kind
        || namespace.enforcement_program_digest() != artifacts.enforcement_program_digest
        || namespace.lease_gate_program_digest() != artifacts.lease_gate_program_digest
    {
        return Err(AdvancedNetworkPolicyError::PhysicalIdentityMismatch);
    }
    let mut endpoint_flows: BTreeMap<NetworkEndpointId, Vec<NetworkFlowPolicyV1>> = BTreeMap::new();
    let mut service_count = 0_usize;
    let mut previous_service: Option<ServiceId> = None;

    let (discovery_digest, discovery_currentness) = match policy.egress() {
        Some(egress) => {
            let snapshot = discovery.ok_or(AdvancedNetworkPolicyError::StaleServiceDiscovery)?;
            snapshot.verify_current(egress.discovery())?;
            if snapshot.project() != policy.identity.project() {
                return Err(AdvancedNetworkPolicyError::StaleServiceDiscovery);
            }

            for destination in egress.destinations() {
                if previous_service != Some(destination.service_id()) {
                    service_count = service_count
                        .checked_add(1)
                        .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;
                    previous_service = Some(destination.service_id());
                }
                let service = snapshot
                    .service(destination.service_id())
                    .filter(|service| service.endpoint_id() == destination.endpoint_id())
                    .ok_or(AdvancedNetworkPolicyError::StaleServiceDiscovery)?;
                if !service
                    .authority()
                    .discloses(policy.identity.assignment().sandbox())
                {
                    return Err(AdvancedNetworkPolicyError::DisclosureDenied);
                }
                let mut matched = false;
                for address in service
                    .addresses()
                    .iter()
                    .filter(|address| address.protocol() == destination.protocol())
                {
                    matched = true;
                    let flow = NetworkFlowPolicyV1::new(
                        NetworkFlowDirectionV1::Egress,
                        address.protocol(),
                        address.address(),
                        Some(address.ports()),
                    )
                    .map_err(|_| AdvancedNetworkPolicyError::Unrepresentable)?;
                    endpoint_flows
                        .entry(destination.endpoint_id())
                        .or_default()
                        .push(flow);
                }
                if !matched {
                    return Err(AdvancedNetworkPolicyError::StaleServiceDiscovery);
                }
            }
            (Some(snapshot.digest()), Some(snapshot.currentness()))
        }
        None => {
            if discovery.is_some() {
                return Err(AdvancedNetworkPolicyError::StaleServiceDiscovery);
            }
            (None, None)
        }
    };

    for allocation in policy.ingress.allocations() {
        for source in allocation.allowed_sources() {
            let flow = NetworkFlowPolicyV1::new(
                NetworkFlowDirectionV1::Ingress,
                allocation.external().protocol(),
                *source,
                Some(allocation.target_ports()),
            )
            .map_err(|_| AdvancedNetworkPolicyError::Unrepresentable)?;
            endpoint_flows
                .entry(allocation.target_endpoint_id())
                .or_default()
                .push(flow);
        }
    }

    if endpoint_flows.len() > MAXIMUM_ADVANCED_NETWORK_ENDPOINTS {
        return Err(AdvancedNetworkPolicyError::Unrepresentable);
    }
    let mut flow_count = 0_usize;
    let mut endpoints = Vec::with_capacity(endpoint_flows.len());
    for (endpoint_id, mut flows) in endpoint_flows {
        flows.sort_unstable();
        flows.dedup();
        if flows.len() > MAXIMUM_ADVANCED_NETWORK_FLOWS_PER_ENDPOINT {
            return Err(AdvancedNetworkPolicyError::Unrepresentable);
        }
        flow_count = flow_count
            .checked_add(flows.len())
            .filter(|count| *count <= MAXIMUM_ADVANCED_NETWORK_FLOWS)
            .ok_or(AdvancedNetworkPolicyError::Unrepresentable)?;
        endpoints.push(
            NetworkEndpointPolicyV1::new(endpoint_id, flows)
                .map_err(|_| AdvancedNetworkPolicyError::Unrepresentable)?,
        );
    }

    let usage = NetworkPolicyUsageV1::new(
        service_count,
        policy
            .egress
            .as_ref()
            .map_or(0, |egress| egress.destinations().len()),
        policy.ingress.allocations().len(),
        endpoints.len(),
        flow_count,
    )?;
    policy.quota.admit(usage)?;
    let program = NetworkPolicyProgramV1::new(
        policy.kind,
        artifacts.enforcement_program_digest,
        artifacts.lease_gate_program_digest,
        endpoints,
    )
    .map_err(|_| AdvancedNetworkPolicyError::Unrepresentable)?;
    if namespace.packet_program_digest() != program.digest() {
        return Err(AdvancedNetworkPolicyError::PhysicalIdentityMismatch);
    }

    let translation = IngressTranslationPlanV1::compile(&policy.ingress, namespace)?;
    let digest = compiled_digest(
        &policy,
        namespace,
        discovery_digest,
        discovery_currentness,
        &translation,
        &program,
        artifacts,
    );

    Ok(CompiledAdvancedNetworkPolicyV1 {
        source: policy,
        namespace_plan: namespace.clone(),
        discovery_digest,
        discovery_currentness,
        translation,
        usage,
        program,
        digest,
    })
}

fn compiled_digest(
    policy: &AdvancedNetworkPolicyV1,
    namespace: &NetworkNamespacePlanV1,
    discovery: Option<ObjectDigest>,
    discovery_currentness: Option<ProtectedCurrentnessWitnessV1>,
    translation: &IngressTranslationPlanV1,
    program: &NetworkPolicyProgramV1,
    artifacts: NetworkEnforcementArtifactsV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(COMPILED_DIGEST_DOMAIN);
    digest.update(policy.digest().as_bytes());
    digest.update(namespace.digest().as_bytes());
    digest.update(program.digest().as_bytes());
    digest.update(translation.digest().as_bytes());
    digest.update(artifacts.enforcement_program_digest.as_bytes());
    digest.update(
        artifacts
            .lease_gate_program_digest
            .map_or([0; 32], |value| *value.as_bytes()),
    );
    digest.update(discovery.map_or([0; 32], |value| *value.as_bytes()));
    match discovery_currentness {
        Some(witness) => {
            digest.update([1]);
            digest.update(witness.current_head().as_bytes());
        }
        None => digest.update([0; 33]),
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn policy_digest(
    identity: &AdvancedNetworkIdentityV1,
    kind: NetworkKind,
    egress: Option<&MediatedEgressPolicyV1>,
    ingress: &IngressAllocationSetV1,
    quota: AdvancedNetworkQuotaV1,
    hard_features: &[FeatureRef],
    advisory_features: &[FeatureRef],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(POLICY_DIGEST_DOMAIN);
    digest.update(identity.digest().as_bytes());
    digest.update([network_kind_code(kind)]);
    match egress {
        Some(egress) => {
            digest.update([1]);
            digest.update(egress.digest().as_bytes());
        }
        None => digest.update([0]),
    }
    digest.update(ingress.digest().as_bytes());
    digest.update(quota.services().to_be_bytes());
    digest.update(quota.egress_destinations().to_be_bytes());
    digest.update(quota.ingress_allocations().to_be_bytes());
    digest.update(quota.endpoints().to_be_bytes());
    digest.update(quota.flows().to_be_bytes());
    digest_features(&mut digest, hard_features);
    digest_features(&mut digest, advisory_features);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn digest_features(digest: &mut Sha256, features: &[FeatureRef]) {
    digest.update((features.len() as u16).to_be_bytes());
    for feature in features {
        digest.update([feature.namespace().len() as u8]);
        digest.update(feature.namespace().as_bytes());
        digest.update(feature.major().to_be_bytes());
        digest.update(feature.minor().to_be_bytes());
    }
}

const fn network_kind_code(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Isolated => 1,
        NetworkKind::Project => 2,
        NetworkKind::Outbound => 3,
        NetworkKind::Published => 4,
        NetworkKind::Host => 5,
    }
}

struct CompilerReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> CompilerReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AdvancedNetworkPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }
    fn byte(&mut self) -> Result<u8, AdvancedNetworkPolicyError> {
        Ok(self.array::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool, AdvancedNetworkPolicyError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AdvancedNetworkPolicyError::NonCanonical),
        }
    }
    fn u32(&mut self) -> Result<u32, AdvancedNetworkPolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, maximum: usize) -> Result<Option<&'a [u8]>, AdvancedNetworkPolicyError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        if length == 0 {
            return Ok(None);
        }
        if length > maximum {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Some(self.take(length)?))
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
fn encode_compiler_blob(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
    }
}
fn encode_compiler_quota(bytes: &mut Vec<u8>, value: AdvancedNetworkQuotaV1) {
    for item in [
        value.services(),
        value.egress_destinations(),
        value.ingress_allocations(),
        value.endpoints(),
        value.flows(),
    ] {
        bytes.extend_from_slice(&item.to_be_bytes());
    }
}
fn decode_compiler_quota(
    reader: &mut CompilerReader<'_>,
) -> Result<AdvancedNetworkQuotaV1, AdvancedNetworkPolicyError> {
    AdvancedNetworkQuotaV1::new(
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
    )
}
fn encode_features(bytes: &mut Vec<u8>, features: &[FeatureRef]) {
    bytes.push(features.len() as u8);
    for feature in features {
        bytes.push(feature.namespace().len() as u8);
        bytes.extend_from_slice(feature.namespace().as_bytes());
        bytes.extend_from_slice(&feature.major().to_be_bytes());
        bytes.extend_from_slice(&feature.minor().to_be_bytes());
    }
}
fn decode_features(
    reader: &mut CompilerReader<'_>,
) -> Result<Vec<FeatureRef>, AdvancedNetworkPolicyError> {
    let count = usize::from(reader.byte()?);
    if count > MAXIMUM_POLICY_FEATURES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(reader.byte()?);
        let namespace = core::str::from_utf8(reader.take(length)?)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?
            .to_owned();
        let major = reader.u32()?;
        let minor = reader.u32()?;
        values.push(
            FeatureRef::new(namespace, major, minor)
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
    }
    Ok(values)
}
fn compiler_kind_code(value: NetworkKind) -> u8 {
    network_kind_code(value)
}
fn decode_compiler_kind(value: u8) -> Result<NetworkKind, AdvancedNetworkPolicyError> {
    match value {
        1 => Ok(NetworkKind::Isolated),
        2 => Ok(NetworkKind::Project),
        3 => Ok(NetworkKind::Outbound),
        4 => Ok(NetworkKind::Published),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}
fn usage_from_decoded(
    source: &AdvancedNetworkPolicyV1,
    program: &NetworkPolicyProgramV1,
) -> Result<NetworkPolicyUsageV1, AdvancedNetworkPolicyError> {
    let services = source.egress.as_ref().map_or(0, |egress| {
        let mut ids = egress
            .destinations()
            .iter()
            .map(|value| value.service_id())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    });
    let flows = program
        .endpoints()
        .iter()
        .try_fold(0_usize, |total, endpoint| {
            total
                .checked_add(endpoint.flows().len())
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)
        })?;
    NetworkPolicyUsageV1::new(
        services,
        source
            .egress
            .as_ref()
            .map_or(0, |value| value.destinations().len()),
        source.ingress.allocations().len(),
        program.endpoints().len(),
        flows,
    )
}
