//! Portable profiles records and their local schema invariants.

use super::*;

/// Selects one unidirectional lane direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Receives admitted input.
    Input,
    /// Produces admitted output.
    Output,
}

/// Selects a timing contract independently of capture fidelity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingMode {
    /// Uses qualified exact modeled boundaries.
    Exact,
    /// Uses admitted bounded execution windows.
    Quantized,
}

/// Selects how an owner participates in coordinator scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingRole {
    /// Runs under execution grants.
    Active,
    /// Reacts to admitted events.
    EventDriven,
    /// Publishes observations under an autonomous contract.
    Autonomous,
}

/// States execution repeatability within the selected profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repeatability {
    /// Has bound deterministic execution qualification.
    Qualified,
    /// Admits nondeterministic physical execution.
    Nondeterministic,
    /// Makes no qualified repeatability claim.
    Unqualified,
}

/// States the state scope covered by preservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureScope {
    /// Includes every future-affecting modeled state domain.
    CompleteModel,
    /// Includes only the admitted architectural state scope.
    Architectural,
    /// Makes no capture claim.
    None,
}

/// States the continuation guarantee within an admitted scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Continuation {
    /// Preserves exact future-affecting state within the selected scope.
    Exact,
    /// Admits documented continuation differences.
    BestEffort,
    /// Does not support continuation.
    Unsupported,
}

/// Selects one independent operation facet with bound guarantees.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetSelection {
    /// Names the selected operation facet.
    pub id: Id,
    /// Selects its positive interface edition.
    pub version: Version,
    /// Binds the selected operation configuration and schemas.
    pub configuration_ref: ContentRef,
    /// Binds its explicit guarantee evidence and limitations.
    pub guarantees_ref: ContentRef,
    /// Carries identity-bearing facet extensions.
    pub extensions: Extensions,
}

/// Selects timing mode and scheduling independently of guarantee axes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingContract {
    /// Selects the baseline operating schema, version 1.
    pub schema_version: Version,
    /// Selects exact or quantized timing.
    pub mode: OperatingMode,
    /// Selects active, event-driven, or autonomous participation.
    pub scheduling_role: SchedulingRole,
    /// Names the admitted ordering profile, superdense-v1.
    pub ordering_profile: String,
    /// Binds the complete timing, budget, publication, and deadline policy.
    pub policy_ref: ContentRef,
    /// Specifies positive regular-grid resolution, or explicit null for nonuniform boundaries.
    #[serde(deserialize_with = "required_nullable")]
    pub resolution_ps: Option<U64>,
    /// Specifies regular-grid phase, or explicit null with nonuniform resolution.
    #[serde(deserialize_with = "required_nullable")]
    pub phase_ps: Option<U64>,
    /// Lists selected facets by ID and version.
    pub facets: Vec<FacetSelection>,
    /// Carries identity-bearing timing extensions.
    pub extensions: Extensions,
}

/// States independent repeatability and preservation guarantees.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeProfile {
    /// Selects the baseline guarantee schema, version 1.
    pub schema_version: Version,
    /// States qualification or admitted nondeterminism.
    pub repeatability: Repeatability,
    /// States whether capture covers complete modeled or architectural state.
    pub capture_scope: CaptureScope,
    /// States the continuation guarantee within that scope.
    pub continuation: Continuation,
    /// Claims separately qualified restart from durable content.
    pub durable_restart: bool,
    /// Claims separately qualified branch isolation.
    pub isolated_fork: bool,
    /// Claims separately qualified replay conditional on recorded inputs.
    pub conditional_replay: bool,
    /// Binds scope restrictions and future exogenous-input limitations.
    pub limitations_ref: ContentRef,
    /// Carries identity-bearing guarantee extensions.
    pub extensions: Extensions,
}

/// Describes realized capabilities without implying unselected facets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProfile {
    /// Selects the baseline capability schema, version 1.
    pub schema_version: Version,
    /// Lists realized operation facets by ID and version.
    pub facets: Vec<FacetSelection>,
    /// Binds device, queue, DMA, IRQ, reset, and capture support.
    pub devices_ref: ContentRef,
    /// Binds mandatory host restrictions and allowed mode combinations.
    pub requirements_ref: ContentRef,
    /// Carries identity-bearing capability extensions.
    pub extensions: Extensions,
}

impl Validate for FacetSelection {
    fn validate(&self) -> Result<(), ContractError> {
        self.configuration_ref.validate()?;
        self.guarantees_ref.validate()?;
        if self.version == 0 {
            return Err(invalid("version", "zero schema/facet edition is forbidden"));
        }
        Ok(())
    }
}

impl Validate for OperatingContract {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.policy_ref.validate()?;
        validate_sorted(
            &self.facets,
            |value| (value.id.clone(), value.version),
            "facets",
        )?;
        for value in &self.facets {
            value.validate()?;
        }
        if self.ordering_profile != "superdense-v1" {
            return Err(invalid("ordering_profile", "unsupported ordering profile"));
        }
        match (self.resolution_ps, self.phase_ps) {
            (Some(resolution), Some(phase)) => {
                QuantumGrid::new(resolution, phase)?;
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "resolution_ps",
                    "resolution and phase must both be present or both null",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for GuaranteeProfile {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        self.limitations_ref.validate()?;
        Ok(())
    }
}

impl Validate for CapabilityProfile {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid("schema_version", "expected baseline version 1"));
        }
        validate_sorted(
            &self.facets,
            |value| (value.id.clone(), value.version),
            "facets",
        )?;
        for value in &self.facets {
            value.validate()?;
        }
        self.devices_ref.validate()?;
        self.requirements_ref.validate()?;
        Ok(())
    }
}
