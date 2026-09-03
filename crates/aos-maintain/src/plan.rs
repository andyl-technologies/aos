//! Immutable update plans, typed URL materialization, and semantic edit scope.
//!
//! A plan closes one selected update unit against exact inventory, discovery,
//! Git, controller, source-slot, and owner-path identities. Source downloads
//! may fill planned hash mutations later, but cannot expand their paths or
//! semantic field scope.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::PACKAGE_UPDATE_PLAN_V1;
use crate::discovery::{DiscoverySnapshotV1, UnitDiscovery};
use crate::envelope::{ControllerIdentity, GitObjectId, InventoryEnvelopeV1, RepositoryContent};
use crate::identity::{ArtifactSlotId, ComponentId, PlanId, SourceSlotId, UnitId};
use crate::inventory::{
    ArtifactInput, ArtifactMaterializer, ArtifactOutput, ComponentVersion, HashMode,
    ProjectionField, RiskLevel, SourceFetcher, UrlPart, UrlScheme, UrlSegment, UrlTemplate,
    VersionProjection,
};
use crate::workflow::DiscoveryDecision;

/// Names a literal field whose exact old value may be replaced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SemanticMutation {
    /// Normalized repository-relative owner path.
    pub owner: String,
    /// Attribute path relative to the unit's `mkUpstream` argument.
    pub field_path: Vec<String>,
    /// Exact literal value required before mutation.
    pub expected: String,
    /// Exact literal value written by deterministic materialization.
    pub replacement: String,
}

/// Describes one planned source download whose hash is resolved later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceIntent {
    /// Component owning this source.
    pub component: ComponentId,
    /// Source-slot identity within the component.
    pub slot: SourceSlotId,
    /// Exact selected upstream identity bound to the downloaded bytes.
    pub upstream_id: String,
    /// Fetcher and hash semantics frozen from inventory.
    pub fetcher: SourceFetcher,
    /// Hash mode frozen from inventory.
    pub hash_mode: HashMode,
    /// Ordered structurally rendered candidate URLs.
    pub urls: Vec<String>,
    /// Exact old SRI hash required at mutation time.
    pub expected_hash: String,
    /// Complete redirect-host allowlist.
    pub allowed_redirect_hosts: Vec<String>,
}

/// Describes one planned generated fixed-output artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactIntent {
    /// Stable artifact identity within the update unit.
    pub slot: ArtifactSlotId,
    /// Ordered source/artifact dependency edges.
    pub inputs: Vec<ArtifactInput>,
    /// Exact old SRI hash required at mutation time.
    pub expected_hash: String,
    /// Exact current artifact derivation replaced by materialization.
    pub expected_derivation: String,
    /// Closed kind-specific builder parameters.
    pub materializer: ArtifactMaterializer,
    /// Complete generated repository output contract.
    pub outputs: Vec<ArtifactOutput>,
}

/// Classifies one deterministic validation action frozen into a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateKind {
    /// Verifies formatting of the exact owner path.
    Format,
    /// Runs package-aware static validation.
    Lint,
    /// Evaluates the repository and its checks without building the candidate.
    Eval,
    /// Builds an exact package member for one target.
    PackageBuild,
    /// Runs one complete repository test layer.
    RepositoryTest,
}

/// Defines one exact local gate invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateSpec {
    /// Stable identity within its gate plan.
    pub id: String,
    /// Semantic gate class.
    pub kind: GateKind,
    /// Exact argument vector beginning with `aos`.
    pub argv: Vec<String>,
    /// Target platform when the gate is platform-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Freezes a single-unit package update before any worktree mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdatePlanV1 {
    /// Selects the exact closed plan schema.
    pub schema: String,
    /// Deterministic identifier derived from every selection input.
    pub plan_id: PlanId,
    /// Exact unit updated by this initial plan form.
    pub unit_id: UnitId,
    /// Exact clean base commit.
    pub base_commit: GitObjectId,
    /// Exact clean base tree.
    pub base_tree: GitObjectId,
    /// Repository-bound inventory envelope identity.
    pub inventory_envelope_digest: Sha256Digest,
    /// Immutable discovery snapshot identity.
    pub discovery_snapshot_digest: Sha256Digest,
    /// Current package version visible to maintainers.
    pub current_package_version: String,
    /// Projected target package version.
    pub target_package_version: String,
    /// Complete selected component vector, including unchanged components.
    pub component_targets: BTreeMap<ComponentId, ComponentVersion>,
    /// Exact author-owned literal mutations.
    pub semantic_mutations: Vec<SemanticMutation>,
    /// Planned sources whose content hashes are materialized by the controller.
    pub sources: Vec<SourceIntent>,
    /// Planned generated fixed-output artifacts in dependency order.
    #[serde(default)]
    pub artifacts: Vec<ArtifactIntent>,
    /// Fast deterministic checks required after every accepted attempt.
    pub quick_gates: Vec<GateSpec>,
    /// Complete repository checks required for the exact accepted commit.
    pub final_gates: Vec<GateSpec>,
    /// Minimum deterministic risk class from package policy.
    pub risk: RiskLevel,
    /// Controller executable and policy identity frozen by the plan.
    pub controller: ControllerIdentity,
    /// Observational creation time in Unix seconds.
    pub created_at_unix: u64,
    /// Last time this plan may begin execution.
    pub expires_at_unix: u64,
}

impl PackageUpdatePlanV1 {
    /// Validates identity, base, mutation scope, source bounds, and expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, malformed identity,
    /// duplicate semantic field, unsafe owner/URL, empty target vector, or
    /// invalid lifetime.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_UPDATE_PLAN_V1 {
            bail!("unsupported package update plan schema");
        }
        self.base_commit.validate()?;
        self.base_tree.validate()?;
        if self.base_commit.algorithm != self.base_tree.algorithm {
            bail!("plan base commit and tree use different object formats");
        }
        if self.component_targets.is_empty() || self.component_targets.len() > 64 {
            bail!("plan component target vector is empty or oversized");
        }
        if self.current_package_version.is_empty()
            || self.target_package_version.is_empty()
            || self.expires_at_unix <= self.created_at_unix
        {
            bail!("plan version or lifetime is invalid");
        }
        let mut fields = BTreeSet::new();
        for mutation in &self.semantic_mutations {
            validate_owner(&mutation.owner)?;
            if mutation.field_path.is_empty()
                || mutation.field_path.len() > 12
                || mutation.expected == mutation.replacement
                || !fields.insert((&mutation.owner, &mutation.field_path))
            {
                bail!("plan contains invalid or duplicate semantic mutation");
            }
        }
        if self.sources.len() > 128 {
            bail!("plan source set is oversized");
        }
        for source in &self.sources {
            if source.urls.is_empty()
                || source.urls.len() > 16
                || source.upstream_id.is_empty()
                || source.upstream_id.len() > 512
            {
                bail!("plan source URL set is empty or oversized");
            }
            for value in &source.urls {
                let url = Url::parse(value).context("parsing planned source URL")?;
                if url.scheme() != "https"
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    bail!("planned source URL is unsafe");
                }
            }
            for host in &source.allowed_redirect_hosts {
                if host.is_empty()
                    || host.len() > 253
                    || host.starts_with('.')
                    || host.ends_with('.')
                    || !host.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'.')
                    })
                {
                    bail!("planned redirect host is invalid");
                }
            }
        }
        if self.artifacts.len() > 128 {
            bail!("plan artifact set is oversized");
        }
        let mut artifact_ids = BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifact_ids.insert(&artifact.slot)
                || artifact.inputs.is_empty()
                || !artifact.expected_hash.starts_with("sha256-")
                || !artifact.expected_derivation.starts_with("/nix/store/")
                || !artifact.expected_derivation.ends_with(".drv")
            {
                bail!("plan contains an invalid or duplicate artifact intent");
            }
            for input in &artifact.inputs {
                if let ArtifactInput::Artifact {
                    artifact: dependency,
                } = input
                    && !artifact_ids.contains(dependency)
                {
                    bail!("plan artifacts are not ordered by their dependency graph");
                }
            }
        }
        validate_gates(&self.quick_gates, "quick")?;
        validate_gates(&self.final_gates, "final")?;
        let final_ids = self
            .final_gates
            .iter()
            .map(|gate| gate.id.as_str())
            .collect::<BTreeSet<_>>();
        if self
            .quick_gates
            .iter()
            .any(|gate| !final_ids.contains(gate.id.as_str()))
        {
            bail!("final gate plan does not contain every quick gate");
        }
        Ok(())
    }
}

/// Creates one immutable plan from an update-available discovery result.
///
/// # Errors
///
/// Returns an error unless the inventory is bound to a clean base, the
/// snapshot matches that inventory, the selected unit exists, and every
/// component and source can be projected deterministically.
pub fn create_plan(
    envelope: &InventoryEnvelopeV1,
    snapshot: &DiscoverySnapshotV1,
    unit_id: &UnitId,
    created_at_unix: u64,
) -> Result<PackageUpdatePlanV1> {
    envelope.validate()?;
    snapshot.validate()?;
    let inventory_envelope_digest =
        Sha256Digest::of_canonical(crate::MAINTENANCE_INVENTORY_ENVELOPE_V1, envelope)?;
    if snapshot.inventory_envelope_digest != inventory_envelope_digest {
        bail!("discovery snapshot does not match the inventory envelope");
    }
    if created_at_unix < snapshot.evaluated_at_unix
        || created_at_unix >= snapshot.evaluated_at_unix.saturating_add(24 * 60 * 60)
    {
        bail!("discovery snapshot is not fresh enough to plan");
    }
    let (base_commit, base_tree) = match &envelope.content {
        RepositoryContent::Clean { commit, tree } => (commit.clone(), tree.clone()),
        RepositoryContent::Dirty { .. } => bail!("a dirty inventory cannot produce a write plan"),
    };
    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| &unit.unit_id == unit_id)
        .ok_or_else(|| anyhow::anyhow!("update unit is not present in inventory"))?;
    let discovery = snapshot
        .units
        .iter()
        .find(|unit| unit.unit_id == unit_id.as_str())
        .ok_or_else(|| anyhow::anyhow!("update unit is not present in discovery snapshot"))?;
    if discovery.decision != DiscoveryDecision::UpdateAvailable {
        bail!("update unit does not have a selectable candidate");
    }

    let component_targets = component_targets(unit, discovery)?;
    let package = unit
        .package
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("selected unit has no package projection"))?;
    let target_package_version =
        project_package_version(&package.version_projection, &component_targets)?;
    let mut semantic_mutations = Vec::new();
    if package.current_version != target_package_version {
        semantic_mutations.push(SemanticMutation {
            owner: unit.owner.clone(),
            field_path: vec!["package".to_string(), "currentVersion".to_string()],
            expected: package.current_version.clone(),
            replacement: target_package_version.clone(),
        });
    }
    let mut sources = Vec::new();
    for (component_id, component) in &unit.components {
        let target = component_targets
            .get(component_id)
            .ok_or_else(|| anyhow::anyhow!("plan target vector is incomplete"))?;
        if target != &component.current {
            semantic_mutations.push(component_mutation(
                &unit.owner,
                component_id,
                ProjectionField::UpstreamId,
                &component.current.upstream_id,
                &target.upstream_id,
            ));
            semantic_mutations.push(component_mutation(
                &unit.owner,
                component_id,
                ProjectionField::ComparisonVersion,
                &component.current.comparison_version,
                &target.comparison_version,
            ));
        }
        for (slot_id, slot) in &component.sources {
            let urls = slot
                .url_templates
                .iter()
                .map(|template| render_url(template, &component_targets))
                .collect::<Result<Vec<_>>>()?;
            sources.push(SourceIntent {
                component: component_id.clone(),
                slot: slot_id.clone(),
                upstream_id: target.upstream_id.clone(),
                fetcher: slot.fetcher,
                hash_mode: slot.hash_mode,
                urls,
                expected_hash: slot.hash.clone(),
                allowed_redirect_hosts: slot.allowed_redirect_hosts.clone(),
            });
        }
    }
    semantic_mutations.sort_by(|left, right| left.field_path.cmp(&right.field_path));
    sources
        .sort_by(|left, right| (&left.component, &left.slot).cmp(&(&right.component, &right.slot)));
    let artifacts = ordered_artifact_intents(unit)?;
    let discovery_snapshot_digest =
        Sha256Digest::of_canonical(crate::DISCOVERY_SNAPSHOT_V1, snapshot)?;
    let (quick_gates, final_gates) = gate_plans(unit);
    let seed = PlanSeed {
        unit_id,
        base_commit: &base_commit,
        base_tree: &base_tree,
        inventory_envelope_digest,
        discovery_snapshot_digest,
        component_targets: &component_targets,
        quick_gates: &quick_gates,
        final_gates: &final_gates,
    };
    let plan_seed = Sha256Digest::of_canonical("aos.package-update-plan-seed/v1", &seed)?;
    let plan_id = PlanId::parse(format!("plan-{}", &plan_seed.hex()[..24]))?;
    let plan = PackageUpdatePlanV1 {
        schema: PACKAGE_UPDATE_PLAN_V1.to_string(),
        plan_id,
        unit_id: unit_id.clone(),
        base_commit,
        base_tree,
        inventory_envelope_digest,
        discovery_snapshot_digest,
        current_package_version: package.current_version.clone(),
        target_package_version,
        component_targets,
        semantic_mutations,
        sources,
        artifacts,
        quick_gates,
        final_gates,
        risk: unit.policy.risk_floor,
        controller: envelope.controller.clone(),
        created_at_unix,
        expires_at_unix: snapshot.evaluated_at_unix.saturating_add(24 * 60 * 60),
    };
    plan.validate()?;
    Ok(plan)
}

fn ordered_artifact_intents(unit: &crate::inventory::UpdateUnit) -> Result<Vec<ArtifactIntent>> {
    fn visit<'a>(
        id: &'a ArtifactSlotId,
        unit: &'a crate::inventory::UpdateUnit,
        visited: &mut BTreeSet<&'a ArtifactSlotId>,
        output: &mut Vec<ArtifactIntent>,
    ) -> Result<()> {
        if visited.contains(id) {
            return Ok(());
        }
        let artifact = unit
            .artifacts
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("artifact dependency disappeared after validation"))?;
        for input in &artifact.inputs {
            if let ArtifactInput::Artifact {
                artifact: dependency,
            } = input
            {
                visit(dependency, unit, visited, output)?;
            }
        }
        visited.insert(id);
        output.push(ArtifactIntent {
            slot: id.clone(),
            inputs: artifact.inputs.clone(),
            expected_hash: artifact.hash.clone(),
            expected_derivation: artifact.derivation.clone(),
            materializer: artifact.materializer.clone(),
            outputs: artifact.outputs.clone(),
        });
        Ok(())
    }

    let mut visited = BTreeSet::new();
    let mut output = Vec::with_capacity(unit.artifacts.len());
    for id in unit.artifacts.keys() {
        visit(id, unit, &mut visited, &mut output)?;
    }
    Ok(output)
}

fn gate_plans(unit: &crate::inventory::UpdateUnit) -> (Vec<GateSpec>, Vec<GateSpec>) {
    let mut quick = vec![
        GateSpec {
            id: "format-owner".to_string(),
            kind: GateKind::Format,
            argv: vec![
                "aos".to_string(),
                "fmt".to_string(),
                "--check".to_string(),
                unit.owner.clone(),
            ],
            target: None,
        },
        GateSpec {
            id: "checks-eval".to_string(),
            kind: GateKind::Eval,
            argv: vec!["aos".to_string(), "test".to_string(), "eval".to_string()],
            target: None,
        },
    ];
    for member in &unit.members {
        quick.push(GateSpec {
            id: format!("lint-{member}"),
            kind: GateKind::Lint,
            argv: vec!["aos".to_string(), "lint".to_string(), member.to_string()],
            target: None,
        });
        for target in &unit.platforms {
            quick.push(GateSpec {
                id: format!("build-{member}-{target}"),
                kind: GateKind::PackageBuild,
                argv: vec![
                    "aos".to_string(),
                    "build".to_string(),
                    member.to_string(),
                    "--target".to_string(),
                    target.clone(),
                ],
                target: Some(target.clone()),
            });
        }
    }
    quick.sort_by(|left, right| left.id.cmp(&right.id));
    let mut final_gates = quick.clone();
    for layer in ["rust", "build", "vm", "fleet"] {
        final_gates.push(GateSpec {
            id: format!("repository-{layer}"),
            kind: GateKind::RepositoryTest,
            argv: vec!["aos".to_string(), "test".to_string(), layer.to_string()],
            target: None,
        });
    }
    final_gates.sort_by(|left, right| left.id.cmp(&right.id));
    (quick, final_gates)
}

fn validate_gates(gates: &[GateSpec], label: &str) -> Result<()> {
    if gates.is_empty() || gates.len() > 256 {
        bail!("{label} gate plan is empty or oversized");
    }
    let mut ids = BTreeSet::new();
    for gate in gates {
        if gate.id.is_empty()
            || gate.id.len() > 128
            || !ids.insert(gate.id.as_str())
            || gate.argv.len() < 2
            || gate.argv.len() > 16
            || gate.argv.first().map(String::as_str) != Some("aos")
            || gate.argv.iter().any(|value| {
                value.is_empty()
                    || value.len() > 4096
                    || value
                        .bytes()
                        .any(|byte| byte == 0 || byte.is_ascii_control())
            })
        {
            bail!("{label} gate plan contains an invalid gate");
        }
    }
    Ok(())
}

/// Renders a structured source URL with per-segment percent encoding.
///
/// # Errors
///
/// Returns an error when a referenced component is absent or URL construction
/// cannot preserve the fixed HTTPS authority.
pub fn render_url(
    template: &UrlTemplate,
    targets: &BTreeMap<ComponentId, ComponentVersion>,
) -> Result<String> {
    let scheme = match template.scheme {
        UrlScheme::Https => "https",
    };
    let mut url = Url::parse(&format!("{scheme}://{}/", template.authority))?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("source URL cannot accept path segments"))?;
    segments.pop_if_empty();
    for segment in &template.path {
        let value = match segment {
            UrlSegment::Literal { value } => value.clone(),
            UrlSegment::Parts { parts } => {
                let mut value = String::new();
                for part in parts {
                    match part {
                        UrlPart::Literal { value: literal } => value.push_str(literal),
                        UrlPart::ComponentField { component, field } => {
                            let target = targets.get(component).ok_or_else(|| {
                                anyhow::anyhow!("URL references an absent component target")
                            })?;
                            value.push_str(match field {
                                ProjectionField::ComparisonVersion => &target.comparison_version,
                                ProjectionField::UpstreamId => &target.upstream_id,
                            });
                        }
                    }
                }
                value
            }
        };
        segments.push(&value);
    }
    drop(segments);
    Ok(url.to_string())
}

fn component_targets(
    unit: &crate::inventory::UpdateUnit,
    discovery: &UnitDiscovery,
) -> Result<BTreeMap<ComponentId, ComponentVersion>> {
    let discovered = discovery
        .components
        .iter()
        .map(|component| (component.component.as_str(), component))
        .collect::<BTreeMap<_, _>>();
    unit.components
        .iter()
        .map(|(component_id, component)| {
            let selected = discovered
                .get(component_id.as_str())
                .and_then(|result| result.selected.clone())
                .unwrap_or_else(|| component.current.clone());
            Ok((component_id.clone(), selected))
        })
        .collect()
}

fn project_package_version(
    projection: &VersionProjection,
    targets: &BTreeMap<ComponentId, ComponentVersion>,
) -> Result<String> {
    match projection {
        VersionProjection::ComponentField { component, field } => {
            let target = targets
                .get(component)
                .ok_or_else(|| anyhow::anyhow!("package projection references absent component"))?;
            Ok(match field {
                ProjectionField::ComparisonVersion => target.comparison_version.clone(),
                ProjectionField::UpstreamId => target.upstream_id.clone(),
            })
        }
    }
}

fn component_mutation(
    owner: &str,
    component: &ComponentId,
    field: ProjectionField,
    expected: &str,
    replacement: &str,
) -> SemanticMutation {
    let field = match field {
        ProjectionField::ComparisonVersion => "comparisonVersion",
        ProjectionField::UpstreamId => "upstreamId",
    };
    SemanticMutation {
        owner: owner.to_string(),
        field_path: vec![
            "components".to_string(),
            component.to_string(),
            "current".to_string(),
            field.to_string(),
        ],
        expected: expected.to_string(),
        replacement: replacement.to_string(),
    }
}

fn validate_owner(owner: &str) -> Result<()> {
    let path = std::path::Path::new(owner);
    if owner.is_empty()
        || owner.len() > 4096
        || path.is_absolute()
        || !owner.starts_with("pkgs/")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::CurDir
                    | std::path::Component::RootDir
            )
        })
    {
        bail!("plan owner path is unsafe");
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanSeed<'a> {
    unit_id: &'a UnitId,
    base_commit: &'a GitObjectId,
    base_tree: &'a GitObjectId,
    inventory_envelope_digest: Sha256Digest,
    discovery_snapshot_digest: Sha256Digest,
    component_targets: &'a BTreeMap<ComponentId, ComponentVersion>,
    quick_gates: &'a [GateSpec],
    final_gates: &'a [GateSpec],
}

#[cfg(test)]
mod tests {
    use crate::inventory::{ProjectionField, UrlPart, UrlSegment};

    use super::*;

    #[test]
    fn url_rendering_encodes_component_values_inside_one_segment() -> Result<()> {
        let component = ComponentId::parse("main")?;
        let template = UrlTemplate {
            scheme: UrlScheme::Https,
            authority: "downloads.example.org".to_string(),
            path: vec![
                UrlSegment::Literal {
                    value: "releases".to_string(),
                },
                UrlSegment::Parts {
                    parts: vec![
                        UrlPart::Literal {
                            value: "source-".to_string(),
                        },
                        UrlPart::ComponentField {
                            component: component.clone(),
                            field: ProjectionField::UpstreamId,
                        },
                        UrlPart::Literal {
                            value: ".tar.xz".to_string(),
                        },
                    ],
                },
            ],
        };
        let targets = BTreeMap::from([(
            component,
            ComponentVersion {
                upstream_id: "release/1.2.3?mirror=bad".to_string(),
                comparison_version: "1.2.3".to_string(),
            },
        )]);

        assert_eq!(
            render_url(&template, &targets)?,
            "https://downloads.example.org/releases/source-release%2F1.2.3%3Fmirror=bad.tar.xz"
        );
        Ok(())
    }

    #[test]
    fn invalid_plan_owner_paths_fail_closed() {
        assert!(validate_owner("../pkgs/zlib.nix").is_err());
        assert!(validate_owner("modules/zlib.nix").is_err());
        assert!(validate_owner("pkgs/compression/zlib.nix").is_ok());
    }
}
