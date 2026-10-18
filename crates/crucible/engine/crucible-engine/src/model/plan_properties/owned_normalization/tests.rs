//! Differential canonical ordering and ownership-preserving DSL regressions.

use super::*;

fn assertion(name: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: AssertionId {
            name: name.to_owned(),
        },
        message: "fixture".to_owned(),
        property: Property::Always { predicate },
    }
}

fn at(ticks: u64) -> Predicate {
    Predicate::At {
        at: VirtualTime { ticks },
    }
}

#[test]
fn owned_canonical_order_preserves_nested_material_identity() -> Result<(), EngineError> {
    let mut actual = vec![
        assertion(
            "z",
            Predicate::AllOf {
                predicates: vec![
                    at(2),
                    Predicate::AnyOf {
                        predicates: vec![Predicate::Quiescent, at(9)],
                    },
                    at(1),
                ],
            },
        ),
        assertion("a", Predicate::Quiescent),
    ];
    let expected = vec![
        assertion("a", Predicate::Quiescent),
        assertion(
            "z",
            Predicate::AllOf {
                predicates: vec![
                    Predicate::AnyOf {
                        predicates: vec![at(9), Predicate::Quiescent],
                    },
                    at(1),
                    at(2),
                ],
            },
        ),
    ];

    canonicalize_assertions(&mut actual)?;

    assert_eq!(actual, expected);
    assert_eq!(
        canonical_properties_hash(&actual)?,
        ContentHash::from_canonical_material(
            PROPERTY_SCHEMA_DOMAIN,
            &properties_material(&expected),
        )
    );
    Ok(())
}

#[test]
fn owned_dsl_resolution_reuses_the_admitted_assertion_image() -> Result<(), EngineError> {
    let world = World::from_nodes(Vec::new())?;
    let assertions = vec![assertion(
        "a",
        Predicate::Named {
            name: "node_alive:example".to_owned(),
            nodes: Vec::new(),
        },
    )];
    let original_image = assertions.as_ptr();

    let resolved = resolve_assertions(&world, &Plan::empty(), assertions)?;

    assert_eq!(resolved.as_ptr(), original_image);
    assert_eq!(
        resolved[0].property,
        Property::Always {
            predicate: Predicate::Not {
                predicate: Box::new(Predicate::NodeState {
                    node: NodeId {
                        name: "example".to_owned()
                    },
                    state: NodeLifecycle::Crashed,
                }),
            }
        }
    );
    Ok(())
}

#[test]
fn empty_component_hashes_match_full_material_oracles() -> Result<(), EngineError> {
    let plan = Plan::empty();
    assert_eq!(
        plan.content_hash(),
        ContentHash::from_canonical_material("crucible.model.plan.v6", &plan_material(&plan),)
    );
    assert_eq!(
        Properties::empty().content_hash(),
        ContentHash::from_canonical_material(PROPERTY_SCHEMA_DOMAIN, &properties_material(&[]),)
    );
    Ok(())
}

#[test]
fn borrowed_link_comparison_matches_exact_canonical_identity() {
    for (left, right) in [("a", "b"), ("é\nvalue", ""), ("same", "same")] {
        let left = NodeId { name: left.into() };
        let right = NodeId { name: right.into() };
        let identity = LinkId::for_endpoints(&left, &right);

        assert!(identity.matches_endpoints(&left, &right));
        assert!(identity.matches_endpoints(&right, &left));
        let mut truncated = identity.clone();
        truncated.name.pop();
        assert!(!truncated.matches_endpoints(&left, &right));
        let mut extended = identity;
        extended.name.push('x');
        assert!(!extended.matches_endpoints(&left, &right));
    }
}
