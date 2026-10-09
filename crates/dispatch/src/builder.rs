//! Fluent construction with duplicate detection and inspectable policy data.

use std::collections::BTreeMap;

use crate::{
    Constraint, Dimension, Holding, Item, ModelError, ObjectiveTier, Observation, Problem,
    Quantity, Target, ValidatedProblem, recipes::PolicyExpansion, validate,
};

/// Constructs a problem while retaining the first duplicate-definition error.
///
/// Policy remains ordinary public model data. Construction does not perform a
/// solve or imply that any feasible assignment exists.
///
/// # Examples
///
/// ```no_run
/// use dispatch::ProblemBuilder;
///
/// let problem = ProblemBuilder::new()
///     .dimension("slots", "worker slots", 1)
///     .build()?;
/// # Ok::<(), dispatch::ModelError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ProblemBuilder {
    problem: Problem,
    error: Option<ModelError>,
}

impl Default for ProblemBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProblemBuilder {
    /// Starts an empty problem using the current model semantics.
    pub fn new() -> Self {
        Self {
            problem: Problem {
                model_version: 1,
                ..Problem::default()
            },
            error: None,
        }
    }

    /// Starts from explicit model data without changing its semantics.
    pub fn from_problem(problem: Problem) -> Self {
        Self {
            problem,
            error: None,
        }
    }

    /// Adds one opaque consumer revision to the observation basis.
    pub fn observation_basis(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        insert_unique(
            &mut self.problem.observation_basis,
            key.into(),
            value.into(),
            "observation_basis",
            &mut self.error,
        );
        self
    }

    /// Adds a dimension whose input quantum has an explicit unit.
    pub fn dimension(
        mut self,
        id: impl Into<String>,
        unit: impl Into<String>,
        quantum: u64,
    ) -> Self {
        insert_unique(
            &mut self.problem.dimensions,
            id.into(),
            Dimension {
                unit: unit.into(),
                quantum: Quantity::new(quantum),
            },
            "dimensions",
            &mut self.error,
        );
        self
    }

    /// Adds a target with explicit capacities and fixed loads.
    pub fn target(mut self, id: impl Into<String>, target: Target) -> Self {
        insert_unique(
            &mut self.problem.targets,
            id.into(),
            target,
            "targets",
            &mut self.error,
        );
        self
    }

    /// Adds a shared finite candidate domain.
    pub fn domain(mut self, id: impl Into<String>, targets: Vec<String>) -> Self {
        insert_unique(
            &mut self.problem.domains,
            id.into(),
            targets,
            "domains",
            &mut self.error,
        );
        self
    }

    /// Adds an atomic item with explicit demand and admission semantics.
    pub fn item(mut self, id: impl Into<String>, item: Item) -> Self {
        insert_unique(
            &mut self.problem.items,
            id.into(),
            item,
            "items",
            &mut self.error,
        );
        self
    }

    /// Adds an item's historical binding and ordinary charges.
    pub fn observed(mut self, item: impl Into<String>, observation: Observation) -> Self {
        insert_unique(
            &mut self.problem.observed,
            item.into(),
            observation,
            "observed",
            &mut self.error,
        );
        self
    }

    /// Adds a finite group of distinct items.
    pub fn group(mut self, id: impl Into<String>, items: Vec<String>) -> Self {
        insert_unique(
            &mut self.problem.groups,
            id.into(),
            items,
            "groups",
            &mut self.error,
        );
        self
    }

    /// Adds a named target set, allowing overlap with other named sets.
    pub fn target_set(mut self, id: impl Into<String>, targets: Vec<String>) -> Self {
        insert_unique(
            &mut self.problem.target_sets,
            id.into(),
            targets,
            "target_sets",
            &mut self.error,
        );
        self
    }

    /// Adds a family whose members partition all targets.
    pub fn scope_family(
        mut self,
        id: impl Into<String>,
        members: BTreeMap<String, Vec<String>>,
    ) -> Self {
        insert_unique(
            &mut self.problem.scope_families,
            id.into(),
            members,
            "scope_families",
            &mut self.error,
        );
        self
    }

    /// Adds a named concurrent holding with explicit accounting treatment.
    pub fn holding(mut self, holding: Holding) -> Self {
        self.problem.holdings.push(holding);
        self
    }

    /// Adds a typed constraint without implicit relaxation.
    pub fn constraint(mut self, constraint: Constraint) -> Self {
        self.problem.constraints.push(constraint);
        self
    }

    /// Appends an objective tier after every previously added tier.
    pub fn objective(mut self, tier: ObjectiveTier) -> Self {
        self.problem.objectives.push(tier);
        self
    }

    /// Applies an inspectable policy expansion without overwriting entities.
    pub fn policy(mut self, expansion: PolicyExpansion) -> Self {
        if self.error.is_none()
            && let Err(error) = expansion.apply(&mut self.problem)
        {
            self.error = Some(error);
        }
        self
    }

    /// Returns the assembled model for inspection before validation.
    pub fn as_problem(&self) -> &Problem {
        &self.problem
    }

    /// Returns the draft without claiming structural validation.
    ///
    /// # Errors
    ///
    /// Returns the first duplicate-definition or policy-expansion error.
    pub fn into_problem(self) -> Result<Problem, ModelError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.problem),
        }
    }

    /// Validates and freezes the assembled model.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate definitions, malformed references, invalid
    /// numeric values, or invalid accounting and policy semantics.
    pub fn build(self) -> Result<ValidatedProblem, ModelError> {
        validate(self.into_problem()?)
    }
}

fn insert_unique<T>(
    entries: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    field: &str,
    error: &mut Option<ModelError>,
) {
    match entries.entry(id) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            if error.is_none() {
                *error = Some(ModelError::new(
                    format!("{field}.{}", entry.key()),
                    "duplicate definition",
                ));
            }
        }
    }
}
