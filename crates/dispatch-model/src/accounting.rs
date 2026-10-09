//! Exact ordinary, concurrent, final, and conservative-overlap resource accounting.

use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_traits::Zero;

use crate::{
    AccountingPhase, Assignment, Binding, HoldingKind, Item, ModelError, ObservedBinding, Problem,
};

pub(crate) type LoadMap = BTreeMap<String, BTreeMap<String, BigInt>>;

pub(crate) struct Loads {
    pub(crate) final_load: LoadMap,
    pub(crate) overlap_load: LoadMap,
}

impl Loads {
    pub(crate) fn selected(&self, phase: AccountingPhase) -> &LoadMap {
        match phase {
            AccountingPhase::Final => &self.final_load,
            AccountingPhase::Overlap => &self.overlap_load,
        }
    }

    pub(crate) fn sum(
        &self,
        problem: &Problem,
        target_set: &str,
        dimension: &str,
        phase: AccountingPhase,
    ) -> Result<BigInt, ModelError> {
        let targets = lookup(&problem.target_sets, target_set, "target_sets")?;
        let loads = self.selected(phase);
        let mut total = BigInt::zero();

        for target in targets {
            let dimensions = lookup(loads, target, "loads")?;
            total += lookup(dimensions, dimension, "loads.dimension")?;
        }

        Ok(total)
    }
}

pub(crate) fn lookup<'a, T>(
    values: &'a BTreeMap<String, T>,
    id: &str,
    path: &str,
) -> Result<&'a T, ModelError> {
    values
        .get(id)
        .ok_or_else(|| ModelError::new(path, format!("unknown identifier {id:?}")))
}

pub(crate) fn demand(item: &Item, target: &str, dimension: &str) -> Result<BigInt, ModelError> {
    let values = lookup(&item.demands, dimension, "item.demands")?;
    let quantity = values
        .overrides
        .get(target)
        .copied()
        .or(values.default)
        .ok_or_else(|| {
            ModelError::new(
                "item.demands",
                format!("undefined demand on target {target:?}"),
            )
        })?;

    Ok(BigInt::from(quantity.get()))
}

pub(crate) fn observed_assignment(problem: &Problem) -> Assignment {
    Assignment {
        bindings: problem
            .observed
            .iter()
            .map(|(item, observation)| {
                let binding = match &observation.binding {
                    ObservedBinding::Target { target } => Binding::Target {
                        target: target.clone(),
                    },
                    ObservedBinding::Unplaced => Binding::Deferred,
                };
                (item.clone(), binding)
            })
            .collect(),
    }
}

pub(crate) fn calculate_loads(
    problem: &Problem,
    assignment: &Assignment,
    historical: bool,
) -> Result<Loads, ModelError> {
    let mut final_load = BTreeMap::new();
    for (id, target) in &problem.targets {
        let dimensions = target
            .fixed_load
            .iter()
            .map(|(dimension, quantity)| (dimension.clone(), BigInt::from(quantity.get())))
            .collect();
        final_load.insert(id.clone(), dimensions);
    }

    let mut loads = Loads {
        overlap_load: final_load.clone(),
        final_load,
    };
    for holding in &problem.holdings {
        if let HoldingKind::Additional { retained_at_final } = holding.kind {
            let quantity = BigInt::from(holding.quantity.get());
            add(
                &mut loads.overlap_load,
                &holding.target,
                &holding.dimension,
                &quantity,
            )?;
            if retained_at_final {
                add(
                    &mut loads.final_load,
                    &holding.target,
                    &holding.dimension,
                    &quantity,
                )?;
            }
        }
    }

    for (id, item) in &problem.items {
        let observation = lookup(&problem.observed, id, "observed")?;
        let binding = lookup(&assignment.bindings, id, "assignment.bindings")?;
        let source = match &observation.binding {
            ObservedBinding::Target { target } => Some(target.as_str()),
            ObservedBinding::Unplaced => None,
        };
        let destination = match binding {
            Binding::Target { target } => Some(target.as_str()),
            Binding::Deferred => None,
        };

        for dimension in problem.dimensions.keys() {
            let ordinary =
                BigInt::from(lookup(&observation.charges, dimension, "observed.charges")?.get());
            if historical {
                if let Some(target) = source {
                    add(&mut loads.final_load, target, dimension, &ordinary)?;
                    add(&mut loads.overlap_load, target, dimension, &ordinary)?;
                }
                continue;
            }

            let proposed = match destination {
                Some(target) => demand(item, target, dimension)?,
                None => BigInt::zero(),
            };
            if let Some(target) = destination {
                add(&mut loads.final_load, target, dimension, &proposed)?;
            }

            if source == destination {
                if let Some(target) = source {
                    add(
                        &mut loads.overlap_load,
                        target,
                        dimension,
                        &ordinary.max(proposed),
                    )?;
                }
                continue;
            }

            if let Some(target) = source {
                add(&mut loads.overlap_load, target, dimension, &ordinary)?;
            }
            if let Some(target) = destination {
                add(&mut loads.overlap_load, target, dimension, &proposed)?;
            }
        }
    }

    Ok(loads)
}

fn add(
    loads: &mut LoadMap,
    target: &str,
    dimension: &str,
    quantity: &BigInt,
) -> Result<(), ModelError> {
    let dimensions = loads
        .get_mut(target)
        .ok_or_else(|| ModelError::new("loads", format!("unknown target {target:?}")))?;
    let value = dimensions
        .get_mut(dimension)
        .ok_or_else(|| ModelError::new("loads", format!("unknown dimension {dimension:?}")))?;
    *value += quantity;

    Ok(())
}
