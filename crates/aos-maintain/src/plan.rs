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
use crate::identity::{ArtifactSlotId, CohortId, ComponentId, PlanId, SourceSlotId, UnitId};
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

/// Freezes one unit's candidate vector and deterministic materialization scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdateUnitPlan {
    /// Exact independently scheduled update-unit identity.
    pub unit_id: UnitId,
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
    /// Explicit package-builder attribute values eligible for repair proposals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_scope: Vec<String>,
}

/// Freezes a one- or multi-unit campaign before any worktree mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdatePlanV1 {
    /// Selects the exact closed plan schema.
    pub schema: String,
    /// Deterministic identifier derived from every selection input.
    pub plan_id: PlanId,
    /// Explicit inventory cohort for a multi-unit campaign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<CohortId>,
    /// Strictly ordered unit transactions in this atomic campaign.
    pub units: Vec<PackageUpdateUnitPlan>,
    /// Exact clean base commit.
    pub base_commit: GitObjectId,
    /// Exact clean base tree.
    pub base_tree: GitObjectId,
    /// Repository-bound inventory envelope identity.
    pub inventory_envelope_digest: Sha256Digest,
    /// Immutable discovery snapshot identity.
    pub discovery_snapshot_digest: Sha256Digest,
    /// Fast deterministic checks required after every accepted attempt.
    pub quick_gates: Vec<GateSpec>,
    /// Complete repository checks required for the exact accepted commit.
    pub final_gates: Vec<GateSpec>,
    /// Highest deterministic risk class across campaign package policy.
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
        if self.units.is_empty()
            || self.units.len() > 32
            || self.expires_at_unix <= self.created_at_unix
            || (self.units.len() == 1 && self.cohort.is_some())
            || (self.units.len() > 1 && self.cohort.is_none())
        {
            bail!("plan version or lifetime is invalid");
        }
        let mut fields = BTreeSet::new();
        let mut unit_ids = BTreeSet::new();
        let mut previous = None;
        for unit in &self.units {
            if !unit_ids.insert(&unit.unit_id)
                || previous.is_some_and(|prior: &UnitId| prior >= &unit.unit_id)
                || unit.component_targets.is_empty()
                || unit.component_targets.len() > 64
                || unit.current_package_version.is_empty()
                || unit.target_package_version.is_empty()
            {
                bail!("plan unit set or version vector is invalid");
            }
            previous = Some(&unit.unit_id);
            validate_unit_plan(unit, &mut fields)?;
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

    /// Returns the only unit in a single-unit campaign.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is an explicit multi-unit campaign.
    pub fn single_unit(&self) -> Result<&PackageUpdateUnitPlan> {
        if self.units.len() != 1 {
            bail!("operation supports only a single-unit campaign");
        }
        self.units
            .first()
            .ok_or_else(|| anyhow::anyhow!("plan has no units"))
    }
}

fn validate_unit_plan(
    unit: &PackageUpdateUnitPlan,
    fields: &mut BTreeSet<(UnitId, String, Vec<String>)>,
) -> Result<()> {
    if unit.repair_scope.len() > 64
        || unit.repair_scope.windows(2).any(|pair| pair[0] >= pair[1])
        || unit.repair_scope.iter().any(|field| {
            field.is_empty()
                || field.len() > 128
                || !field.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte == b'-'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
    {
        bail!("plan contains an invalid repair scope");
    }
    for mutation in &unit.semantic_mutations {
        validate_owner(&mutation.owner)?;
        if mutation.field_path.is_empty()
            || mutation.field_path.len() > 12
            || mutation.expected == mutation.replacement
            || !fields.insert((
                unit.unit_id.clone(),
                mutation.owner.clone(),
                mutation.field_path.clone(),
            ))
        {
            bail!("plan contains invalid or duplicate semantic mutation");
        }
    }
    if unit.sources.len() > 128 {
        bail!("plan source set is oversized");
    }
    for source in &unit.sources {
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
    if unit.artifacts.len() > 128 {
        bail!("plan artifact set is oversized");
    }
    let mut artifact_ids = BTreeSet::new();
    for artifact in &unit.artifacts {
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
    Ok(())
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
    create_campaign_plan(
        envelope,
        snapshot,
        None,
        std::slice::from_ref(unit_id),
        created_at_unix,
    )
}

/// Creates one immutable atomic campaign from explicitly associated units.
///
/// # Errors
///
/// Returns an error unless every selected unit belongs to the named cohort,
/// has a complete selectable candidate, and can be projected deterministically.
pub fn create_campaign_plan(
    envelope: &InventoryEnvelopeV1,
    snapshot: &DiscoverySnapshotV1,
    cohort: Option<&CohortId>,
    unit_ids: &[UnitId],
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
    if unit_ids.is_empty()
        || (unit_ids.len() == 1 && cohort.is_some())
        || (unit_ids.len() > 1 && cohort.is_none())
    {
        bail!("campaign selection does not match its cohort identity");
    }
    let mut selected = unit_ids.to_vec();
    selected.sort();
    if selected.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("campaign contains duplicate update units");
    }
    let mut units = Vec::with_capacity(selected.len());
    let mut risks = Vec::with_capacity(selected.len());
    let mut quick_gates = Vec::new();
    let mut final_gates = Vec::new();
    for unit_id in &selected {
        let unit = envelope
            .inventory
            .units
            .iter()
            .find(|unit| &unit.unit_id == unit_id)
            .ok_or_else(|| anyhow::anyhow!("update unit is not present in inventory"))?;
        if unit.cohort.as_ref() != cohort {
            bail!("selected update unit does not belong to the requested cohort");
        }
        let discovery = snapshot
            .units
            .iter()
            .find(|unit| unit.unit_id == unit_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("update unit is not present in discovery snapshot"))?;
        if discovery.decision != DiscoveryDecision::UpdateAvailable {
            bail!("campaign unit does not have a selectable candidate");
        }
        units.push(create_unit_plan(unit, discovery)?);
        risks.push(unit.policy.risk_floor);
        let (quick, final_plan) = gate_plans(unit);
        quick_gates.extend(quick);
        final_gates.extend(final_plan);
    }
    deduplicate_gates(&mut quick_gates)?;
    deduplicate_gates(&mut final_gates)?;
    let risk = risks
        .into_iter()
        .max_by_key(|risk| risk_rank(*risk))
        .ok_or_else(|| anyhow::anyhow!("campaign has no risk policy"))?;
    let discovery_snapshot_digest =
        Sha256Digest::of_canonical(crate::DISCOVERY_SNAPSHOT_V1, snapshot)?;
    let seed = PlanSeed {
        cohort,
        units: &units,
        base_commit: &base_commit,
        base_tree: &base_tree,
        inventory_envelope_digest,
        discovery_snapshot_digest,
        quick_gates: &quick_gates,
        final_gates: &final_gates,
    };
    let plan_seed = Sha256Digest::of_canonical("aos.package-update-plan-seed/v1", &seed)?;
    let plan_id = PlanId::parse(format!("plan-{}", &plan_seed.hex()[..24]))?;
    let plan = PackageUpdatePlanV1 {
        schema: PACKAGE_UPDATE_PLAN_V1.to_string(),
        plan_id,
        cohort: cohort.cloned(),
        units,
        base_commit,
        base_tree,
        inventory_envelope_digest,
        discovery_snapshot_digest,
        quick_gates,
        final_gates,
        risk,
        controller: envelope.controller.clone(),
        created_at_unix,
        expires_at_unix: snapshot.evaluated_at_unix.saturating_add(24 * 60 * 60),
    };
    plan.validate()?;
    Ok(plan)
}

fn create_unit_plan(
    unit: &crate::inventory::UpdateUnit,
    discovery: &UnitDiscovery,
) -> Result<PackageUpdateUnitPlan> {
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
    Ok(PackageUpdateUnitPlan {
        unit_id: unit.unit_id.clone(),
        current_package_version: package.current_version.clone(),
        target_package_version,
        component_targets,
        semantic_mutations,
        sources,
        artifacts,
        repair_scope: unit.policy.repair_scope.clone(),
    })
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
            id: format!("format-{}", unit.unit_id),
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
    if matches!(
        unit.policy.risk_floor,
        RiskLevel::High | RiskLevel::Critical
    ) {
        for member in &unit.members {
            for target in &unit.platforms {
                final_gates.push(GateSpec {
                    id: format!("repeat-build-{member}-{target}"),
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
    }
    // AOS intentionally chooses the conservative closed policy while package
    // coverage is young: every package root is built on each eligible target.
    // This is a deterministic superset of any affected reverse-dependency
    // closure and prevents an incomplete graph from weakening final evidence.
    for target in &unit.platforms {
        final_gates.push(GateSpec {
            id: format!("repository-build-all-{target}"),
            kind: GateKind::RepositoryTest,
            argv: vec![
                "aos".to_string(),
                "build".to_string(),
                "--all".to_string(),
                "--target".to_string(),
                target.clone(),
            ],
            target: Some(target.clone()),
        });
    }
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

fn deduplicate_gates(gates: &mut Vec<GateSpec>) -> Result<()> {
    gates.sort_by(|left, right| left.id.cmp(&right.id));
    let mut unique: Vec<GateSpec> = Vec::with_capacity(gates.len());
    for gate in gates.drain(..) {
        if let Some(previous) = unique.last()
            && previous.id == gate.id
        {
            if previous != &gate {
                bail!("campaign assigns one gate identity to different commands");
            }
            continue;
        }
        unique.push(gate);
    }
    *gates = unique;
    Ok(())
}

const fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::Low => 0,
        RiskLevel::Normal => 1,
        RiskLevel::High => 2,
        RiskLevel::Critical => 3,
    }
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
    cohort: Option<&'a CohortId>,
    units: &'a [PackageUpdateUnitPlan],
    base_commit: &'a GitObjectId,
    base_tree: &'a GitObjectId,
    inventory_envelope_digest: Sha256Digest,
    discovery_snapshot_digest: Sha256Digest,
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
