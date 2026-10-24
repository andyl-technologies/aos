//! Canonical realization bindings for all owners in a coupled world.

use super::*;

/// Identifies an owner's independent execution and preservation responsibilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutorOwnerRole {
    /// Controls native or modeled state evolution for its participant nodes.
    Execution,
    /// Authoritatively preserves the declared mutable state domains.
    Capture,
}

impl Canonical for ExecutorOwnerRole {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Execution => 0,
            Self::Capture => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Execution),
            1 => Ok(Self::Capture),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "executor-owner-role",
                tag,
            }),
        }
    }
}

/// Binds one execution or capture owner to its complete admitted implementation profile.
///
/// `compatibility` authenticates implementation and patches, execution model,
/// ISA/features, devices, clocks, memory/coherence, transport, fault support,
/// instrumentation, state/protocol schemas, required host compatibility
/// evidence, and all continuation-affecting parameters. A backend name or
/// executable version alone cannot satisfy this binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerImplementationBinding {
    provider: String,
    compatibility: CampaignHash,
    nodes: BTreeSet<String>,
    roles: BTreeSet<ExecutorOwnerRole>,
    guarantee: NodeExecutionGuarantee,
}

impl OwnerImplementationBinding {
    /// Builds a bounded realized-owner binding.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid provider/node identifiers or an empty or
    /// oversized set of logical node views.
    pub fn new(
        provider: String,
        compatibility: CampaignHash,
        nodes: BTreeSet<String>,
        guarantee: NodeExecutionGuarantee,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_roles(
            provider,
            compatibility,
            nodes,
            guarantee,
            BTreeSet::from([ExecutorOwnerRole::Execution]),
        )
    }

    /// Builds a bounded owner with explicit execution and capture responsibilities.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, empty/oversized node views,
    /// or an empty role set. Capture support does not imply execution support.
    pub fn new_with_roles(
        provider: String,
        compatibility: CampaignHash,
        nodes: BTreeSet<String>,
        guarantee: NodeExecutionGuarantee,
        roles: BTreeSet<ExecutorOwnerRole>,
    ) -> Result<Self, CampaignCodecError> {
        validate_identifier(&provider, "executor owner provider identifier is invalid")?;
        if nodes.is_empty() || nodes.len() > MAX_EXECUTOR_OWNER_NODES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "execution owner node set is empty or oversized",
            });
        }
        for node in &nodes {
            validate_identifier(node, "executor owner node identifier is invalid")?;
        }
        if roles.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor owner has no execution or capture role",
            });
        }

        Ok(Self {
            provider,
            compatibility,
            nodes,
            roles,
            guarantee,
        })
    }

    /// Returns the provider's stable implementation family identifier.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the authenticated complete compatibility-profile identity.
    #[must_use]
    pub const fn compatibility(&self) -> CampaignHash {
        self.compatibility
    }

    /// Returns the logical node views governed by this execution owner.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeSet<String> {
        &self.nodes
    }

    /// Returns independently declared execution and preservation roles.
    #[must_use]
    pub const fn roles(&self) -> &BTreeSet<ExecutorOwnerRole> {
        &self.roles
    }

    /// Returns the qualified execution guarantee selected for this realization.
    #[must_use]
    pub const fn guarantee(&self) -> &NodeExecutionGuarantee {
        &self.guarantee
    }
}

impl Canonical for OwnerImplementationBinding {
    fn encode(&self, encoder: &mut Encoder) {
        self.provider.encode(encoder);
        self.compatibility.encode(encoder);
        self.nodes.encode(encoder);
        self.roles.encode(encoder);
        self.guarantee.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let provider = decoder.string_bounded(MAX_IDENTIFIER_BYTES, "owner-provider-bytes")?;
        let compatibility = CampaignHash::decode(decoder)?;
        let nodes = decoder.set_bounded_by(
            MAX_EXECUTOR_OWNER_NODES,
            "execution-owner-node-count",
            |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "owner-node-id-bytes"),
        )?;
        let roles = decoder.set_bounded(2, "executor-owner-role-count")?;
        Self::new_with_roles(
            provider,
            compatibility,
            nodes,
            NodeExecutionGuarantee::decode(decoder)?,
            roles,
        )
    }
}

/// Authenticates the entire coupled world's scenario, configuration, and owners.
///
/// All realized compute and non-compute owners must occur exactly once. The
/// graph identity authenticates causal/ownership edges and ordering policy;
/// the graph admission layer verifies completeness against its realization.
/// This roster conservatively treats every listed owner as coupled. It does
/// not infer isolation from an absent network edge or a later disconnection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorNodeRoster {
    scenario: ScenarioArtifactId,
    configuration: ConfigurationArtifactId,
    graph: CampaignHash,
    owners: BTreeMap<String, OwnerImplementationBinding>,
}

impl ExecutorNodeRoster {
    /// Builds a bounded whole-world implementation roster.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, an empty/oversized roster,
    /// duplicate node ownership, or an encoded roster exceeding 16 MiB.
    pub fn new(
        scenario: ScenarioArtifactId,
        configuration: ConfigurationArtifactId,
        graph: CampaignHash,
        owners: BTreeMap<String, OwnerImplementationBinding>,
    ) -> Result<Self, CampaignCodecError> {
        if owners.is_empty() || owners.len() > MAX_EXECUTOR_NODE_OWNERS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor owner roster is empty or oversized",
            });
        }
        let mut assigned_nodes = BTreeSet::new();
        for (owner, binding) in &owners {
            validate_identifier(owner, "executor owner identifier is invalid")?;
            for role in binding.roles() {
                for node in binding.nodes() {
                    if assigned_nodes.insert((*role, node)) {
                        continue;
                    }
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "logical node has duplicate owners for one responsibility",
                    });
                }
            }
        }

        let roster = Self {
            scenario,
            configuration,
            graph,
            owners,
        };
        codec::ensure_encoded_size(&roster, MAX_ROSTER_BYTES, "executor-node-roster-bytes")?;
        Ok(roster)
    }

    /// Returns the authenticated portable scenario artifact.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioArtifactId {
        self.scenario
    }

    /// Returns the planned configuration artifact, distinct from observed state.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationArtifactId {
        self.configuration
    }

    /// Returns the admitted realized graph and ordering-policy identity.
    #[must_use]
    pub const fn graph(&self) -> CampaignHash {
        self.graph
    }

    /// Returns every execution owner's authenticated implementation binding.
    #[must_use]
    pub const fn owners(&self) -> &BTreeMap<String, OwnerImplementationBinding> {
        &self.owners
    }

    /// Reports whether every coupled owner is repeatable under its admitted model.
    #[must_use]
    pub fn is_repeatable(&self) -> bool {
        self.owners
            .values()
            .all(|binding| matches!(binding.guarantee(), NodeExecutionGuarantee::Repeatable))
    }

    /// Returns the domain-separated complete realization identity.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.executor-node-roster.v1", &self.canonical_bytes())
    }

    /// Returns strict canonical roster bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a bounded canonical roster without converting legacy state.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown versions, malformed/noncanonical bytes,
    /// invalid ownership, or an oversized record.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(bytes, MAX_ROSTER_BYTES, "executor-node-roster-bytes")
    }
}

impl Canonical for ExecutorNodeRoster {
    fn encode(&self, encoder: &mut Encoder) {
        ROSTER_SCHEMA_VERSION.encode(encoder);
        self.scenario.encode(encoder);
        self.configuration.encode(encoder);
        self.graph.encode(encoder);
        self.owners.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(u32::decode(decoder)?, ROSTER_SCHEMA_VERSION)?;
        Self::new(
            ScenarioArtifactId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            decoder.map_bounded_by(
                MAX_EXECUTOR_NODE_OWNERS,
                "executor-node-owner-count",
                |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "execution-owner-id-bytes"),
                OwnerImplementationBinding::decode,
            )?,
        )
    }
}
