//! Checks unchanged property bytes and explicit installed predicate surfaces.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assertion(name: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(name),
        message: name.into(),
        property: Property::Always { predicate },
    }
}

#[test]
fn legacy_adapter_retains_original_property_identity_and_compact_bytes() -> TestResult {
    let world = World::from_nodes(Vec::new())?;
    let assertions = vec![
        assertion("opaque-original", Predicate::named("original-host-oracle")),
        assertion("clock-original", Predicate::at(VirtualTime { ticks: 19 })),
    ];
    let original = Properties::from_assertions_for_world(&world, assertions.clone())?;
    let namespace = PropertyNamespace::from_world(&world);
    let neutral = Properties::from_assertions_for_namespace(&namespace, assertions)?;

    assert_eq!(original, neutral);
    assert_eq!(original.canonical_bytes(), neutral.canonical_bytes());
    assert_eq!(original.to_compact_binary(), neutral.to_compact_binary());
    assert_eq!(
        Properties::from_compact_binary_for_namespace(&namespace, &original.to_compact_binary())?,
        original
    );
    Ok(())
}

#[test]
fn actual_logical_storage_names_do_not_require_a_vm_declaration() -> TestResult {
    let disk = NodeId {
        name: "disk".into(),
    };
    let namespace = PropertyNamespace::new(
        BTreeMap::from([(
            disk.clone(),
            BTreeSet::from([PropertyObservation::Io(IoEventKind::BlockRead)]),
        )]),
        false,
        false,
        BTreeSet::new(),
    )?;
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![assertion(
            "read",
            Predicate::IoPattern {
                node: disk.clone(),
                kind: IoEventKind::BlockRead,
            },
        )],
    )?;
    let encoded = properties.to_compact_binary();

    assert_eq!(
        Properties::from_compact_binary_for_namespace(&namespace, &encoded)?,
        properties
    );
    assert!(
        Properties::from_assertions_for_namespace(
            &namespace,
            vec![assertion(
                "unsupported-family",
                Predicate::IoPattern {
                    node: disk.clone(),
                    kind: IoEventKind::NineP
                }
            )]
        )
        .is_err()
    );
    assert!(
        Properties::from_assertions_for_namespace(
            &namespace,
            vec![assertion(
                "unsupported-console",
                Predicate::ConsoleMatch {
                    node: disk,
                    regex: RegexProgram {
                        pattern: "boot".into()
                    }
                }
            )]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn unsupported_world_and_host_oracle_surfaces_refuse_before_evaluation() -> TestResult {
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, false, BTreeSet::new())?;
    for predicate in [Predicate::named("uninstalled"), Predicate::quiescent()] {
        assert!(
            Properties::from_assertions_for_namespace(
                &namespace,
                vec![assertion("unsupported", predicate)]
            )
            .is_err()
        );
    }
    let mut terminal = assertion("terminal", Predicate::at(VirtualTime { ticks: 7 }));
    terminal.property = Property::AfterQuiescence {
        predicate: Predicate::at(VirtualTime { ticks: 7 }),
    };
    assert!(Properties::from_assertions_for_namespace(&namespace, vec![terminal]).is_err());
    let allowed = PropertyNamespace::new(
        BTreeMap::new(),
        false,
        false,
        BTreeSet::from(["installed".into()]),
    )?;
    assert!(
        Properties::from_assertions_for_namespace(
            &allowed,
            vec![assertion("selected", Predicate::named("installed"))]
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn structural_errors_and_corrupted_original_binary_still_refuse() -> TestResult {
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, false, BTreeSet::new())?;
    let property = assertion("clock", Predicate::at(VirtualTime { ticks: 7 }));
    assert!(
        Properties::from_assertions_for_namespace(
            &namespace,
            vec![property.clone(), property.clone()]
        )
        .is_err()
    );
    assert!(
        Properties::from_assertions_for_namespace(
            &namespace,
            vec![assertion("empty", Predicate::all_of(Vec::new()))]
        )
        .is_err()
    );
    let properties = Properties::from_assertions_for_namespace(&namespace, vec![property])?;
    let mut bytes = properties.to_compact_binary();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(Properties::from_compact_binary_for_namespace(&namespace, &bytes).is_err());
    bytes = properties.to_compact_binary();
    bytes.push(0);
    assert!(Properties::from_compact_binary_for_namespace(&namespace, &bytes).is_err());
    Ok(())
}
