//! Portable declarative model schemas with explicit tagged policy variants.
//!
//! All resource quantities are decimal strings and policy tags are snake case:
//!
//! ```json
//! {"kind":"capacity","target_set":"hosts","dimension":"bytes","phase":"final","limit":"4096"}
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Quantity, Rational};

/// A topology partition mapping each named member to its distinct target set.
pub type ScopeFamily = BTreeMap<String, Vec<String>>;

/// Independently named topology partitions over the complete target collection.
pub type ScopeFamilies = BTreeMap<String, ScopeFamily>;

/// A finite declarative assignment problem before structural validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    /// Semantic model version; the current version is one.
    #[serde(with = "decimal_version")]
    pub model_version: u32,
    /// Opaque consumer revisions; these are not freshness or authority proofs.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub observation_basis: BTreeMap<String, String>,
    /// Atomic placement units keyed by their stable identifiers.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub items: BTreeMap<String, Item>,
    /// Placement destinations keyed by their stable identifiers.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub targets: BTreeMap<String, Target>,
    /// Resource dimensions keyed by their stable identifiers.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub dimensions: BTreeMap<String, Dimension>,
    /// Shared finite eligible-target sets keyed by domain identifier.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub domains: BTreeMap<String, Vec<String>>,
    /// Finite item groups keyed by group identifier.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Named target sets, which may overlap.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub target_sets: BTreeMap<String, Vec<String>>,
    /// Scope families mapping member identifiers to disjoint target sets.
    #[serde(deserialize_with = "deserialize_families")]
    pub scope_families: ScopeFamilies,
    /// Complete historical item placements and ordinary resource charges.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub observed: BTreeMap<String, Observation>,
    /// Explicit fragments of ordinary charges and additional concurrent holdings.
    pub holdings: Vec<Holding>,
    /// Named typed requirements and their enforcement policy.
    pub constraints: Vec<Constraint>,
    /// Objective tiers, compared lexicographically in this order.
    pub objectives: Vec<ObjectiveTier>,
}

/// A resource dimension with an explicit integer accounting quantum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dimension {
    /// Human-readable unit name, carrying no implicit conversion semantics.
    pub unit: String,
    /// Positive integer quantity of the declared unit represented by one input unit.
    pub quantum: Quantity,
}

/// An indivisible unit that can occupy one eligible target or be deferred.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    /// Identifier of the item's shared candidate domain.
    pub domain: String,
    /// Whether final assignment may explicitly defer this item.
    pub deferrable: bool,
    /// Target-dependent demand for every declared resource dimension.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub demands: BTreeMap<String, Demand>,
}

/// A sparse target-dependent resource demand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Demand {
    /// Explicit fallback for targets without an override; absence requires coverage.
    pub default: Option<Quantity>,
    /// Demand overrides keyed by target identifier.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub overrides: BTreeMap<String, Quantity>,
}

/// A placement destination and its out-of-model resource consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Declared capacities for consumer helpers; constraints carry their own limits.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub capacities: BTreeMap<String, Capacity>,
    /// Fixed consumption, explicitly defined for every dimension.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub fixed_load: BTreeMap<String, Quantity>,
}

/// A declared finite or explicitly unbounded target capacity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capacity {
    /// A finite capacity in the associated dimension's quantum.
    Finite {
        /// Exact finite ceiling.
        limit: Quantity,
    },
    /// A capacity with no declared finite ceiling.
    Unbounded,
}

/// A complete proposed assignment keyed by item identifier.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    /// Exactly one target or deferred binding for every modeled item.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub bindings: BTreeMap<String, Binding>,
}

/// A final placement decision.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Binding {
    /// Placement on one real target.
    Target {
        /// Destination target identifier.
        target: String,
    },
    /// Explicitly deferred work, consuming no final placement resources.
    Deferred,
}

/// A historical placement, independent of current eligibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedBinding {
    /// Existing ordinary placement on a real target.
    Target {
        /// Historical target identifier.
        target: String,
    },
    /// An item with no ordinary historical placement.
    Unplaced,
}

/// An item's historical ordinary placement and independently submitted charges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Historical binding, which may be ineligible for final placement.
    pub binding: ObservedBinding,
    /// Complete per-dimension historical charges, zero for unplaced items.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub charges: BTreeMap<String, Quantity>,
}

/// A named observed holding with unambiguous accounting treatment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holding {
    /// Stable holding identifier, unique within the problem.
    pub id: String,
    /// Target where this holding consumes resources.
    pub target: String,
    /// Resource dimension of the charge.
    pub dimension: String,
    /// Exact held quantity.
    pub quantity: Quantity,
    /// Whether the holding fragments an ordinary charge or is additional.
    pub kind: HoldingKind,
}

/// The accounting association of a concurrent holding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HoldingKind {
    /// A fragment already included in an item's ordinary historical charge.
    Ordinary {
        /// Item whose observed charge is fragmented.
        item: String,
    },
    /// Extra concurrent occupancy, never folded into ordinary placement demand.
    Additional {
        /// Whether the holding remains charged at the final boundary.
        retained_at_final: bool,
    },
}

/// An exact accounting phase used by capacities and utilization metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingPhase {
    /// Fixed consumption, final placements, and retained additional holdings.
    Final,
    /// Fixed consumption, all extra holdings, and source/destination overlap.
    Overlap,
}

/// A requirement's hard or explicitly repairable enforcement semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Every component must have zero violation.
    Hard,
    /// Numeric component debt may not exceed its observation-derived baseline.
    Repair,
}

/// A named requirement whose meaning can be independently evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraint {
    /// Stable identifier used in reports and repair references.
    pub id: String,
    /// Hard enforcement or explicit componentwise repair.
    pub enforcement: Enforcement,
    /// Typed predicate and its fully specified parameters.
    pub rule: ConstraintRule,
}

/// A typed assignment predicate supported by the reference evaluator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstraintRule {
    /// Further restricts selected items to a declared target set.
    Eligibility {
        /// Items whose candidate domains are intersected with this set.
        items: Vec<String>,
        /// Additional allowed target identifiers.
        targets: Vec<String>,
    },
    /// Requires exact explicitly submitted item bindings.
    FixedPlacement {
        /// Required bindings; these never override eligibility or mandatory admission.
        #[serde(deserialize_with = "deserialize_unique_map")]
        bindings: BTreeMap<String, Binding>,
    },
    /// Bounds one exact target-set resource load.
    Capacity {
        /// Named target-set identifier.
        target_set: String,
        /// Resource dimension identifier.
        dimension: String,
        /// Final or conservative-overlap accounting.
        phase: AccountingPhase,
        /// Explicit resource ceiling.
        limit: Quantity,
    },
    /// Bounds the number of admitted members of an item group.
    Admission {
        /// Item-group identifier.
        group: String,
        /// Inclusive minimum number admitted.
        minimum: Quantity,
        /// Inclusive maximum number admitted.
        maximum: Quantity,
    },
    /// Requires zero or every group member to be admitted.
    AtomicAdmission {
        /// Item-group identifier.
        group: String,
    },
    /// Requires admitted group members to share one topology member.
    CoLocation {
        /// Item-group identifier.
        group: String,
        /// Target-scope family identifier.
        family: String,
    },
    /// Requires distinct occupied topology members and optional per-member ceilings.
    Spread {
        /// Item-group identifier.
        group: String,
        /// Target-scope family identifier.
        family: String,
        /// Inclusive minimum distinct occupied members.
        minimum: Quantity,
        /// Optional ceiling on admitted items within each member.
        maximum_per_member: Option<Quantity>,
        /// Whether the minimum is disabled when no group item is admitted.
        when_admitted: bool,
    },
    /// Bounds explicit transition costs over selected items.
    MovementBudget {
        /// Selected item identifiers.
        items: Vec<String>,
        /// Costs and transition categories, with nonnegative compatible units.
        costs: MovementCosts,
        /// Nonnegative exact cost ceiling.
        limit: Rational,
    },
}

/// A transition category charged by a movement policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementCategory {
    /// Unplaced work becoming admitted.
    NewPlacement,
    /// A real historical target changing to a different real target.
    Relocation,
    /// A real historical target changing to deferred work.
    Retirement,
}

/// Explicit costs for bindings of a particular item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentCosts {
    /// Explicit target fallback; absent values require complete target overrides.
    pub default: Option<Rational>,
    /// Cost overrides keyed by target identifier.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub targets: BTreeMap<String, Rational>,
    /// Explicit cost of binding this item to deferred.
    pub deferred: Rational,
}

/// Costs relative to the fixed observed source for each selected item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MovementCosts {
    /// Declared cost unit, carrying no implicit conversion semantics.
    pub unit: String,
    /// Transition categories charged; unchanged bindings always cost zero.
    pub categories: Vec<MovementCategory>,
    /// Complete costs for selected items' potential destination bindings.
    #[serde(deserialize_with = "deserialize_unique_map")]
    pub costs: BTreeMap<String, AssignmentCosts>,
}

/// A stable reference to one numeric constraint component.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentId {
    /// Identifier of the repairable constraint.
    pub constraint: String,
    /// Component selector: `capacity`, `minimum`, `maximum`, or a scope member ID.
    pub component: String,
}

/// An ordered tier of normalized terms, interpreted as a minimized rational sum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveTier {
    /// Stable tier identifier.
    pub id: String,
    /// Terms combined within this tier; an empty tier has value zero.
    pub terms: Vec<ObjectiveTerm>,
}

/// A weighted metric with explicit orientation and unit normalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveTerm {
    /// Stable identifier, unique across objective terms.
    pub id: String,
    /// Whether increasing or decreasing the metric is preferred.
    pub direction: Direction,
    /// Nonnegative rational coefficient.
    pub weight: Rational,
    /// Strictly positive rational normalization divisor.
    pub normalizer: Rational,
    /// Independently computable metric.
    pub metric: Metric,
}

/// The orientation of an objective metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Smaller metric values are preferred.
    Minimize,
    /// Larger metric values are preferred.
    Maximize,
}

/// A finite utilization selection with an explicit denominator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtilizationMember {
    /// Stable selection identifier within the metric.
    pub id: String,
    /// Named target set whose exact load forms the numerator.
    pub target_set: String,
    /// Resource dimension identifier.
    pub dimension: String,
    /// Accounting phase for the load numerator.
    pub phase: AccountingPhase,
    /// Strictly positive finite denominator in the dimension's quantum.
    pub capacity: Quantity,
}

/// A utilization member and its exact declared reference value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtilizationReference {
    /// The load, phase, and capacity selection.
    pub member: UtilizationMember,
    /// Exact utilization reference used by absolute-deviation evaluation.
    pub reference: Rational,
}

/// A typed exact metric supported by the reference evaluator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Metric {
    /// Counts selected items assigned to real targets.
    AdmittedCount {
        /// Selected item identifiers.
        items: Vec<String>,
    },
    /// Sums explicit nonnegative admitted-item priorities.
    AdmittedPriority {
        /// Item priorities; unplaced items contribute zero.
        #[serde(deserialize_with = "deserialize_unique_map")]
        priorities: BTreeMap<String, Rational>,
    },
    /// Sums explicit per-item binding costs, which may be signed.
    AssignmentCost {
        /// Complete binding cost tables for selected items.
        #[serde(deserialize_with = "deserialize_unique_map")]
        costs: BTreeMap<String, AssignmentCosts>,
    },
    /// Sums nonnegative transition costs relative to observed placement.
    MovementCost {
        /// Selected item identifiers.
        items: Vec<String>,
        /// Applicable transition categories and costs.
        costs: MovementCosts,
    },
    /// Counts distinct real destinations receiving selected items.
    UsedTargets {
        /// Selected item identifiers.
        items: Vec<String>,
    },
    /// Sums explicitly selected repair components in consumer-declared units.
    RepairDebt {
        /// Numeric component references, with no implicit unit conversion.
        components: Vec<ComponentId>,
    },
    /// Takes the maximum of a nonempty utilization selection.
    MaximumUtilization {
        /// Explicit nonempty member selection.
        members: Vec<UtilizationMember>,
    },
    /// Subtracts minimum from maximum over a nonempty utilization selection.
    UtilizationRange {
        /// Explicit nonempty member selection.
        members: Vec<UtilizationMember>,
    },
    /// Sums exact absolute deviations from explicit utilization references.
    TotalAbsoluteDeviation {
        /// Explicit nonempty member and reference selection.
        members: Vec<UtilizationReference>,
    },
}

mod decimal_version {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "model version must be canonical unsigned decimal",
            ));
        }

        value.parse().map_err(serde::de::Error::custom)
    }
}

fn deserialize_unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct UniqueMapVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for UniqueMapVisitor<T> {
        type Value = BTreeMap<String, T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique keys")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some(key) = access.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate object key {key:?}"
                    )));
                }
                values.insert(key, access.next_value()?);
            }

            Ok(values)
        }
    }

    deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
}

fn deserialize_families<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ScopeFamilies, D::Error> {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct UniqueMembers(#[serde(deserialize_with = "deserialize_unique_map")] ScopeFamily);

    let families = deserialize_unique_map::<D, UniqueMembers>(deserializer)?;
    Ok(families
        .into_iter()
        .map(|(id, members)| (id, members.0))
        .collect())
}
