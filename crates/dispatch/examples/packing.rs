//! Builds and compares an inspectable packing policy without starting a solver.

use std::collections::BTreeMap;

use dispatch::{
    AccountingPhase, Assignment, Binding, Capacity, Enforcement, Item, Observation,
    ObservedBinding, ProblemBuilder, Quantity, Target, analysis, recipes,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = ProblemBuilder::new()
        .observation_basis("inventory", "revision-1")
        .dimension("slots", "worker slots", 1)
        .domain("all", vec!["A".into(), "B".into()]);

    for id in ["A", "B"] {
        builder = builder.target(
            id,
            Target {
                capacities: BTreeMap::from([(
                    "slots".into(),
                    Capacity::Finite {
                        limit: Quantity::new(2),
                    },
                )]),
                fixed_load: BTreeMap::from([("slots".into(), Quantity::new(0))]),
            },
        );
    }

    for (item, target) in [("x", "A"), ("y", "B")] {
        builder = builder
            .item(
                item,
                Item {
                    domain: "all".into(),
                    deferrable: false,
                    demands: BTreeMap::from([("slots".into(), recipes::uniform_demand(1))]),
                },
            )
            .observed(
                item,
                Observation {
                    binding: ObservedBinding::Target {
                        target: target.into(),
                    },
                    charges: BTreeMap::from([("slots".into(), Quantity::new(1))]),
                },
            );
    }

    let capacity = recipes::packing_capacity(
        "packing",
        builder.as_problem(),
        &["slots".into()],
        AccountingPhase::Final,
        Enforcement::Hard,
    )?;
    let problem = builder
        .policy(capacity)
        .policy(recipes::minimize_used_targets(
            "packing",
            vec!["x".into(), "y".into()],
        ))
        .build()?;

    let before = Assignment {
        bindings: BTreeMap::from([
            ("x".into(), Binding::Target { target: "A".into() }),
            ("y".into(), Binding::Target { target: "B".into() }),
        ]),
    };
    let after = Assignment {
        bindings: BTreeMap::from([
            ("x".into(), Binding::Target { target: "A".into() }),
            ("y".into(), Binding::Target { target: "A".into() }),
        ]),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&analysis::compare(&problem, &before, &after)?)?
    );
    Ok(())
}
