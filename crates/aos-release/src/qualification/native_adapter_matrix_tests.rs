//! Adversarial checks for exact native adapter matrix evidence.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::digest::Sha256Digest;
use crate::evidence::GateResult;
use crate::qualification::{QualificationMethod, QualificationPhase};
use crate::qualification_evidence::{
    CheckObservation, NATIVE_ADAPTER_MATRIX_OBSERVATION_V1, NATIVE_ADAPTER_MATRIX_REQUIREMENT,
    NATIVE_ADAPTER_MATRIX_SPEC_V1, NativeAdapterCellObservation, NativeAdapterCellSpec,
    NativeAdapterInterfaceIdentity, NativeAdapterMatrixComponentIdentity,
    NativeAdapterMatrixEnvironment, NativeAdapterMatrixEnvironmentStatus,
    NativeAdapterMatrixObservation, NativeAdapterMatrixSpec, NativeAdapterMatrixSubject,
    NativeAdapterPostconditionProbe, NativeAdapterRecoverySpec, NativeAdapterSurfaceAdapter,
    NativeAdapterSurfaceLimits, NativeAdapterSurfaceMethod, NativeAdapterSurfaceScenario,
    NativeAdapterSurfaceSpec, QualificationCase, QualificationObservation,
    QualificationPredecessor, native_adapter_matrix_check, validate_matrix_for_case,
    validate_native_adapter_matrix_observation, validate_native_adapter_matrix_spec,
};
use crate::verify::tests::{observations, qualification_fixture};

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(label)
}

fn probe_kind(postcondition: &str) -> &'static str {
    match postcondition {
        "durable-attempt-state-classified" => "journal-timeline",
        "at-most-one-resource-owner" => "ownership-inventory",
        "foreign-resources-unchanged" => "foreign-resource-snapshot",
        "dependent-effects-not-executed" => "dependency-barrier",
        _ => panic!("fixture postcondition has no probe kind"),
    }
}

fn fixture() -> Result<(
    QualificationCase,
    Sha256Digest,
    NativeAdapterMatrixObservation,
)> {
    let first_interface = NativeAdapterInterfaceIdentity {
        name: "aos.fixture-a-effects".into(),
        abi: 1,
        descriptor: digest("interface a"),
    };
    let second_interface = NativeAdapterInterfaceIdentity {
        name: "aos.fixture-z-effects".into(),
        abi: 1,
        descriptor: digest("interface z"),
    };
    let method = |descriptor: Sha256Digest, adapter: &str, interface_name: &str| {
        NativeAdapterSurfaceAdapter {
            adapter: adapter.into(),
            interface_abi: 1,
            interface_descriptor: descriptor,
            interface_name: interface_name.into(),
            methods: vec![NativeAdapterSurfaceMethod {
                cancel: None,
                effect_class: "mutation".into(),
                method: "apply".into(),
                reconcile: Some("apply".into()),
            }],
            scope: "host-resource".into(),
        }
    };
    let scenario = |id: &str| NativeAdapterSurfaceScenario {
        boundary: "before-external-effect".into(),
        candidate: "same".into(),
        failure: "injected-interruption".into(),
        id: id.into(),
        predecessor: "same".into(),
    };
    let surface = NativeAdapterSurfaceSpec {
        adapters: vec![
            method(
                first_interface.descriptor,
                "fixture-a",
                &first_interface.name,
            ),
            method(
                second_interface.descriptor,
                "fixture-z",
                &second_interface.name,
            ),
        ],
        limits: NativeAdapterSurfaceLimits {
            max_adapters: 2,
            max_methods: 2,
            max_scenarios: 2,
        },
        matrix_schema: "aos.qualification.native-adapter-matrix/v1".into(),
        scenarios: vec![scenario("interrupt"), scenario("recovery")],
        schema: "aos.qualification.native-adapter-surface/v1".into(),
        subject_schema: "aos.qualification.native-adapter-subject/v1".into(),
    };
    let subject = NativeAdapterMatrixSubject {
        schema: "aos.qualification.native-adapter-subject/v1".into(),
        matrix_schema: "aos.qualification.native-adapter-matrix/v1".into(),
        surface_digest: Sha256Digest::of_bytes(crate::canonical::to_vec(&surface)?),
        adapter_count: 2,
        method_count: 2,
        scenario_count: 2,
        interfaces: vec![first_interface.clone(), second_interface.clone()],
    };
    let cell = |adapter: &str,
                interface: &NativeAdapterInterfaceIdentity,
                scenario: &str|
     -> NativeAdapterCellSpec {
        NativeAdapterCellSpec {
            id: format!("{adapter}/{}/abi-1/apply/{scenario}", interface.name),
            matrix_schema: subject.matrix_schema.clone(),
            adapter: adapter.into(),
            interface: interface.clone(),
            method: "apply".into(),
            effect_class: "mutation".into(),
            scope: "host-resource".into(),
            boundary: "before-external-effect".into(),
            failure: "injected-interruption".into(),
            predecessor: "same".into(),
            candidate: "same".into(),
            postconditions: vec![
                "durable-attempt-state-classified".into(),
                "at-most-one-resource-owner".into(),
                "foreign-resources-unchanged".into(),
                "dependent-effects-not-executed".into(),
            ],
            recovery: NativeAdapterRecoverySpec {
                reconcile: Some("apply".into()),
                cancel: None,
            },
            invalidated_by: vec![
                "subject".into(),
                "policy".into(),
                "executor".into(),
                "environment".into(),
            ],
        }
    };
    let mut cells = vec![
        cell("fixture-a", &first_interface, "interrupt"),
        cell("fixture-a", &first_interface, "recovery"),
        cell("fixture-z", &second_interface, "interrupt"),
        cell("fixture-z", &second_interface, "recovery"),
    ];
    cells.sort_by(|left, right| left.id.cmp(&right.id));
    let spec = NativeAdapterMatrixSpec {
        schema: NATIVE_ADAPTER_MATRIX_SPEC_V1.into(),
        surface,
        subject,
        cells,
    };
    let spec_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(&spec)?);
    let component =
        |name: &str, component_digest: Sha256Digest| NativeAdapterMatrixComponentIdentity {
            name: name.into(),
            version: "fixture-v1".into(),
            digest: component_digest,
        };
    let executor_digest = digest("executor");
    let environment = NativeAdapterMatrixEnvironment {
        schema_version: "aos.release.native-adapter-matrix-environment/v1".into(),
        status: NativeAdapterMatrixEnvironmentStatus::Production,
        platform: crate::platform::Platform::X86_64Linux,
        spec_digest,
        scenario_registry_digest: executor_digest,
        candidate_subjects_digest: digest("subjects"),
        predecessor_manifest_digest: digest("predecessor"),
        unqualified_reason: None,
        cohort: Some("fixture-cohort".into()),
        qemu: Some(component("qemu", digest("qemu"))),
        firmware: Some(component("firmware", digest("firmware"))),
        guest_kernel: Some(component("guest-kernel", digest("guest kernel"))),
        fault_injection_tool: Some(component("fault-injection-tool", digest("fault tool"))),
        harness: Some(component("matrix-harness", digest("harness closure"))),
    };
    let environment_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(&environment)?);
    let cells = spec
        .cells
        .iter()
        .map(|cell| {
            let cohort_subject = serde_json::json!({
                "schema": "aos.test.native-adapter-cohort-subject/v1",
                "cell": cell.id,
            });
            let cohort_subject_digest =
                Sha256Digest::of_bytes(crate::canonical::to_vec(&cohort_subject)?);
            let probes = cell
                .postconditions
                .iter()
                .map(|name| {
                    let observations = BTreeMap::from([(
                        "fixture-observation".into(),
                        serde_json::json!(format!("{}:{name}", cell.id)),
                    )]);
                    let observation_digest =
                        Sha256Digest::of_bytes(crate::canonical::to_vec(&observations)?);
                    Ok((
                        name.clone(),
                        NativeAdapterPostconditionProbe {
                            schema_version: "aos.release.native-adapter-postcondition-probe/v1"
                                .into(),
                            kind: probe_kind(name).into(),
                            subject_digest: digest("subjects"),
                            cohort_subject_digest,
                            observation_digest,
                            observations,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok(NativeAdapterCellObservation {
                id: cell.id.clone(),
                cell_digest: Sha256Digest::of_bytes(crate::canonical::to_vec(cell)?),
                environment_digest,
                cohort_subject: Some(cohort_subject),
                postconditions: cell
                    .postconditions
                    .iter()
                    .map(|name| {
                        (
                            name.clone(),
                            CheckObservation {
                                passed: true,
                                detail: "observed by the production fixture".into(),
                            },
                        )
                    })
                    .collect(),
                probes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let case = QualificationCase {
        schema_version: Some("aos.release.qualification-case/v2".into()),
        claim: None,
        measurements: BTreeMap::new(),
        minimum_observed_seconds: None,
        id: "ability-native-adapter-matrix/release".into(),
        requirement_id: NATIVE_ADAPTER_MATRIX_REQUIREMENT.into(),
        policy_digest: digest("policy"),
        plan_digest: digest("plan"),
        subjects_digest: digest("subjects"),
        phase: QualificationPhase::Staging,
        platform: None,
        package_role: None,
        target: None,
        subjects: vec!["candidate".into()],
        checks: vec![format!(
            "native-adapter-matrix-v1-sha256-{}",
            spec_digest.hex()
        )],
        method: QualificationMethod::Automated,
        predecessor: Some(QualificationPredecessor {
            registry: "main".into(),
            release_id: "prior".into(),
            manifest_digest: digest("predecessor"),
        }),
    };
    Ok((
        case,
        environment_digest,
        NativeAdapterMatrixObservation {
            schema_version: NATIVE_ADAPTER_MATRIX_OBSERVATION_V1.into(),
            spec,
            spec_digest,
            environment,
            cells,
        },
    ))
}

fn complete_observation(
    case: &QualificationCase,
    environment_digest: Sha256Digest,
    matrix: NativeAdapterMatrixObservation,
) -> Result<QualificationObservation> {
    let passed = validate_native_adapter_matrix_observation(
        case,
        environment_digest,
        digest("executor"),
        &matrix,
    )?;
    let check = native_adapter_matrix_check(&matrix, passed)?;
    let postcondition_count = matrix
        .cells
        .iter()
        .map(|cell| u64::try_from(cell.postconditions.len()))
        .sum::<std::result::Result<u64, _>>()?;

    Ok(QualificationObservation {
        capabilities: None,
        environment: None,
        assessment: None,
        native_adapter_matrix: Some(matrix.clone()),
        case_digest: case.digest()?,
        executor_digest: digest("executor"),
        environment_digest,
        checks: BTreeMap::from([(case.checks[0].clone(), check)]),
        observed_seconds: 1,
        operations: BTreeMap::from([
            (
                "matrix_cells_reported".into(),
                u64::try_from(matrix.cells.len())?,
            ),
            ("matrix_postconditions_reported".into(), postcondition_count),
        ]),
        predecessor: case.predecessor.clone(),
    })
}

fn recommit(
    case: &mut QualificationCase,
    observation: &mut NativeAdapterMatrixObservation,
) -> Result<Sha256Digest> {
    for (spec, result) in observation.spec.cells.iter().zip(&mut observation.cells) {
        result.id.clone_from(&spec.id);
        result.cell_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(spec)?);
    }
    observation.spec_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(&observation.spec)?);
    observation.environment.spec_digest = observation.spec_digest;
    let environment_digest = recommit_environment(observation)?;
    case.checks = vec![format!(
        "native-adapter-matrix-v1-sha256-{}",
        observation.spec_digest.hex()
    )];
    Ok(environment_digest)
}

fn recommit_environment(observation: &mut NativeAdapterMatrixObservation) -> Result<Sha256Digest> {
    let environment_digest =
        Sha256Digest::of_bytes(crate::canonical::to_vec(&observation.environment)?);
    for result in &mut observation.cells {
        result.environment_digest = environment_digest;
    }
    Ok(environment_digest)
}

#[test]
fn exact_cells_derive_the_matrix_result() -> Result<()> {
    let (case, environment, mut observation) = fixture()?;
    assert!(validate_native_adapter_matrix_observation(
        &case,
        environment,
        digest("executor"),
        &observation
    )?);

    observation.cells[0]
        .postconditions
        .get_mut("at-most-one-resource-owner")
        .unwrap()
        .passed = false;
    observation.cells[0]
        .probes
        .remove("at-most-one-resource-owner");
    assert!(!validate_native_adapter_matrix_observation(
        &case,
        environment,
        digest("executor"),
        &observation
    )?);
    Ok(())
}

#[test]
fn cell_population_and_order_are_exact() -> Result<()> {
    let (case, environment, observation) = fixture()?;
    let mut mutations = Vec::new();
    let mut missing = observation.clone();
    missing.cells.pop();
    mutations.push(missing);
    let mut extra = observation.clone();
    extra.cells.push(extra.cells[0].clone());
    mutations.push(extra);
    let mut reordered = observation.clone();
    reordered.cells.swap(0, 1);
    mutations.push(reordered);
    let mut duplicate = observation.clone();
    duplicate.cells[1] = duplicate.cells[0].clone();
    mutations.push(duplicate);

    for mutation in mutations {
        assert!(
            validate_native_adapter_matrix_observation(
                &case,
                environment,
                digest("executor"),
                &mutation,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn committed_identities_and_postconditions_are_exact() -> Result<()> {
    let (case, environment, observation) = fixture()?;
    let mut mutations = Vec::new();
    let mut spec_digest = observation.clone();
    spec_digest.spec_digest = digest("foreign spec");
    mutations.push(spec_digest);
    let mut cell_digest = observation.clone();
    cell_digest.cells[0].cell_digest = digest("foreign cell");
    mutations.push(cell_digest);
    let mut cell_environment = observation.clone();
    cell_environment.cells[0].environment_digest = digest("foreign environment");
    mutations.push(cell_environment);
    let mut missing_postcondition = observation.clone();
    missing_postcondition.cells[0]
        .postconditions
        .remove("at-most-one-resource-owner");
    mutations.push(missing_postcondition);
    let mut extra_postcondition = observation.clone();
    extra_postcondition.cells[0].postconditions.insert(
        "coarse-regression-passed".into(),
        CheckObservation {
            passed: true,
            detail: "source regression".into(),
        },
    );
    mutations.push(extra_postcondition);
    let mut blank_detail = observation;
    blank_detail.cells[0]
        .postconditions
        .get_mut("at-most-one-resource-owner")
        .unwrap()
        .detail
        .clear();
    mutations.push(blank_detail);

    for mutation in mutations {
        assert!(
            validate_native_adapter_matrix_observation(
                &case,
                environment,
                digest("executor"),
                &mutation,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn passing_postconditions_require_independent_subject_bound_probes() -> Result<()> {
    let (case, environment, observation) = fixture()?;
    let first_name = observation.cells[0]
        .postconditions
        .keys()
        .next()
        .expect("fixture cell has a postcondition")
        .clone();
    let second_name = observation.cells[0]
        .postconditions
        .keys()
        .nth(1)
        .expect("fixture cell has a second postcondition")
        .clone();
    let mut mutations = Vec::new();

    let mut missing = observation.clone();
    missing.cells[0].probes.remove(&first_name);
    mutations.push(missing);

    let mut foreign_subject = observation.clone();
    foreign_subject.cells[0]
        .probes
        .get_mut(&first_name)
        .expect("fixture cell retains its probe")
        .subject_digest = digest("foreign subject");
    mutations.push(foreign_subject);

    let mut missing_cohort_subject = observation.clone();
    missing_cohort_subject.cells[0].cohort_subject = None;
    mutations.push(missing_cohort_subject);

    let mut foreign_cohort_subject = observation.clone();
    foreign_cohort_subject.cells[0].cohort_subject = Some(serde_json::json!({
        "schema": "aos.test.native-adapter-cohort-subject/v1",
        "cell": "foreign-cell",
    }));
    mutations.push(foreign_cohort_subject);

    let mut foreign_cohort_digest = observation.clone();
    foreign_cohort_digest.cells[0]
        .probes
        .get_mut(&first_name)
        .expect("fixture cell retains its probe")
        .cohort_subject_digest = digest("foreign cohort subject");
    mutations.push(foreign_cohort_digest);

    let mut false_digest = observation.clone();
    false_digest.cells[0]
        .probes
        .get_mut(&first_name)
        .expect("fixture cell retains its probe")
        .observation_digest = digest("invented probe");
    mutations.push(false_digest);

    let mut wrong_kind = observation.clone();
    wrong_kind.cells[0]
        .probes
        .get_mut(&first_name)
        .expect("fixture cell retains its probe")
        .kind = "dependency-barrier".into();
    mutations.push(wrong_kind);

    let mut duplicate = observation;
    let first_observations = duplicate.cells[0].probes[&first_name].observations.clone();
    let second_probe = duplicate.cells[0]
        .probes
        .get_mut(&second_name)
        .expect("fixture cell retains its second probe");
    second_probe.observation_digest =
        Sha256Digest::of_bytes(crate::canonical::to_vec(&first_observations)?);
    second_probe.observations = first_observations;
    mutations.push(duplicate);

    for mutation in mutations {
        assert!(
            validate_native_adapter_matrix_observation(
                &case,
                environment,
                digest("executor"),
                &mutation,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn matrix_case_requires_a_frozen_predecessor() -> Result<()> {
    let (mut case, environment, observation) = fixture()?;
    case.predecessor = None;

    assert!(
        validate_native_adapter_matrix_observation(
            &case,
            environment,
            digest("executor"),
            &observation,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn matrix_environment_is_typed_and_bound_to_case_and_executor() -> Result<()> {
    let (case, _, observation) = fixture()?;
    let mut mutations = Vec::new();

    let mut candidate = observation.clone();
    candidate.environment.candidate_subjects_digest = digest("foreign candidate");
    mutations.push(candidate);

    let mut predecessor = observation.clone();
    predecessor.environment.predecessor_manifest_digest = digest("foreign predecessor");
    mutations.push(predecessor);

    let mut registry = observation.clone();
    registry.environment.scenario_registry_digest = digest("foreign scenario registry");
    mutations.push(registry);

    let mut incomplete = observation.clone();
    incomplete.environment.qemu = None;
    mutations.push(incomplete);

    let mut empty_harness = observation;
    empty_harness
        .environment
        .harness
        .as_mut()
        .expect("production fixture has a harness")
        .name
        .clear();
    mutations.push(empty_harness);

    for mut mutation in mutations {
        let environment = recommit_environment(&mut mutation)?;
        assert!(
            validate_native_adapter_matrix_observation(
                &case,
                environment,
                digest("executor"),
                &mutation,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn unqualified_environment_can_only_retain_a_failed_matrix() -> Result<()> {
    let (case, _, mut observation) = fixture()?;
    observation.environment.status = NativeAdapterMatrixEnvironmentStatus::Unqualified;
    observation.environment.unqualified_reason = Some("production cohort unavailable".into());
    observation.environment.cohort = None;
    observation.environment.qemu = None;
    observation.environment.firmware = None;
    observation.environment.guest_kernel = None;
    observation.environment.fault_injection_tool = None;
    observation.environment.harness = None;
    let environment = recommit_environment(&mut observation)?;

    assert!(
        validate_native_adapter_matrix_observation(
            &case,
            environment,
            digest("executor"),
            &observation,
        )
        .is_err()
    );

    for cell in &mut observation.cells {
        for postcondition in cell.postconditions.values_mut() {
            postcondition.passed = false;
        }
        cell.cohort_subject = None;
        cell.probes.clear();
    }
    assert!(!validate_native_adapter_matrix_observation(
        &case,
        environment,
        digest("executor"),
        &observation,
    )?);
    Ok(())
}

#[test]
fn unknown_status_and_regression_fields_are_rejected() -> Result<()> {
    let (_, _, observation) = fixture()?;
    let mut value = serde_json::to_value(&observation)?;
    let first = value["cells"][0]
        .as_object_mut()
        .expect("fixture cell must be an object");
    first.insert("passed".into(), serde_json::Value::Bool(true));
    first.insert(
        "regressions".into(),
        serde_json::json!(["checks.fleet.ability-native-postgresql"]),
    );

    assert!(serde_json::from_value::<NativeAdapterMatrixObservation>(value).is_err());

    let mut value = serde_json::to_value(&observation)?;
    value["cells"][0]["probes"]["at-most-one-resource-owner"]
        .as_object_mut()
        .expect("fixture probe must be an object")
        .insert("claimed_by_adapter".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<NativeAdapterMatrixObservation>(value).is_err());

    let mut value = serde_json::to_value(&observation)?;
    value["spec"]["surface"]
        .as_object_mut()
        .expect("fixture surface must be an object")
        .insert("surface_claim".into(), serde_json::json!("unbound"));
    assert!(serde_json::from_value::<NativeAdapterMatrixObservation>(value).is_err());

    let mut value = serde_json::to_value(&observation)?;
    value["environment"]
        .as_object_mut()
        .expect("fixture environment must be an object")
        .insert("host_claim".into(), serde_json::json!("unbound-host"));
    assert!(serde_json::from_value::<NativeAdapterMatrixObservation>(value).is_err());

    let mut value = serde_json::to_value(observation)?;
    value["spec"]["cells"][0]
        .as_object_mut()
        .expect("fixture specification cell must be an object")
        .insert(
            "evidence".into(),
            serde_json::json!({
                "status": "passed",
                "regressions": ["checks.fleet.ability-native-postgresql"]
            }),
        );
    assert!(serde_json::from_value::<NativeAdapterMatrixObservation>(value).is_err());
    Ok(())
}

#[test]
fn specification_order_and_v1_bounds_are_enforced() -> Result<()> {
    let (mut case, _, mut unsorted_interfaces) = fixture()?;
    unsorted_interfaces.spec.subject.interfaces.swap(0, 1);
    let environment = recommit(&mut case, &mut unsorted_interfaces)?;
    assert!(
        validate_native_adapter_matrix_observation(
            &case,
            environment,
            digest("executor"),
            &unsorted_interfaces
        )
        .is_err()
    );

    let (mut case, _, mut unsorted_cells) = fixture()?;
    unsorted_cells.spec.cells.swap(0, 1);
    unsorted_cells.cells.swap(0, 1);
    let environment = recommit(&mut case, &mut unsorted_cells)?;
    assert!(
        validate_native_adapter_matrix_observation(
            &case,
            environment,
            digest("executor"),
            &unsorted_cells
        )
        .is_err()
    );

    let (_, _, mut oversized) = fixture()?;
    oversized.spec.subject.adapter_count = 13;
    assert!(validate_native_adapter_matrix_spec(&oversized.spec).is_err());

    let (mut case, _, mut incomplete_interfaces) = fixture()?;
    let first_interface = incomplete_interfaces.spec.subject.interfaces[0].clone();
    for cell in &mut incomplete_interfaces.spec.cells[2..] {
        let scenario = cell
            .id
            .rsplit('/')
            .next()
            .expect("fixture cell has a scenario")
            .to_owned();
        cell.interface.clone_from(&first_interface);
        cell.id = format!(
            "{}/{}/abi-{}/{}/{}",
            cell.adapter, cell.interface.name, cell.interface.abi, cell.method, scenario
        );
    }
    let environment = recommit(&mut case, &mut incomplete_interfaces)?;
    assert!(
        validate_native_adapter_matrix_observation(
            &case,
            environment,
            digest("executor"),
            &incomplete_interfaces,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn surface_digest_subject_and_cell_expansion_are_recomputed() -> Result<()> {
    let (case, _, observation) = fixture()?;
    let mut mutations = Vec::new();

    let mut surface_bytes = observation.clone();
    surface_bytes.spec.surface.adapters[0].interface_descriptor = digest("changed interface");
    mutations.push(surface_bytes);

    let mut surface_digest = observation.clone();
    surface_digest.spec.subject.surface_digest = digest("claimed surface");
    mutations.push(surface_digest);

    let mut limits = observation.clone();
    limits.spec.surface.limits.max_methods += 1;
    mutations.push(limits);

    let mut method = observation.clone();
    method.spec.surface.adapters[0].methods[0].effect_class = "observation".into();
    mutations.push(method);

    let mut recovery = observation.clone();
    recovery.spec.surface.adapters[0].methods[0].reconcile = Some("missing-route".into());
    mutations.push(recovery);

    let mut scenario = observation.clone();
    scenario.spec.surface.scenarios[0].candidate = "replacement".into();
    mutations.push(scenario);

    let mut expansion = observation;
    expansion.spec.cells[0].boundary = "after-acquisition".into();
    mutations.push(expansion);

    for mut mutation in mutations {
        let mut mutation_case = case.clone();
        let environment = recommit(&mut mutation_case, &mut mutation)?;
        assert!(
            validate_native_adapter_matrix_observation(
                &mutation_case,
                environment,
                digest("executor"),
                &mutation,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn aggregate_check_and_operation_denominators_are_derived() -> Result<()> {
    let (case, environment, matrix) = fixture()?;
    let observation = complete_observation(&case, environment, matrix)?;
    assert_eq!(validate_matrix_for_case(&case, &observation)?, Some(true));

    let mut arbitrary_detail = observation.clone();
    arbitrary_detail
        .checks
        .get_mut(&case.checks[0])
        .unwrap()
        .detail = "a coarse regression passed".into();
    assert!(validate_matrix_for_case(&case, &arbitrary_detail).is_err());

    let mut extra_operation = observation.clone();
    extra_operation
        .operations
        .insert("coarse_regressions_passed".into(), 4);
    assert!(validate_matrix_for_case(&case, &extra_operation).is_err());

    let mut missing_operation = observation;
    missing_operation.operations.remove("matrix_cells_reported");
    assert!(validate_matrix_for_case(&case, &missing_operation).is_err());
    Ok(())
}

#[test]
fn central_phase_rejects_failed_cells_and_prepared_environment_mutation() -> Result<()> {
    const NOW: &str = "2026-09-01T00:00:02Z";

    let (plan, manifest) = qualification_fixture()?;
    let complete = observations(&plan, &manifest, QualificationPhase::Staging)?;
    let matrix_index = complete
        .iter()
        .position(|record| record.policy_id == NATIVE_ADAPTER_MATRIX_REQUIREMENT)
        .expect("fixture includes the production matrix requirement");

    let mut failed = complete.clone();
    let failed_record = &mut failed[matrix_index];
    let failed_observation = failed_record
        .qualification
        .as_mut()
        .expect("matrix record has an observation");
    let failed_matrix = failed_observation
        .native_adapter_matrix
        .as_mut()
        .expect("matrix record has cell evidence");
    let failed_name = failed_matrix.cells[0]
        .postconditions
        .keys()
        .next()
        .expect("matrix cell has a postcondition")
        .clone();
    failed_matrix.cells[0]
        .postconditions
        .get_mut(&failed_name)
        .expect("matrix cell retains the selected postcondition")
        .passed = false;
    failed_matrix.cells[0].probes.remove(&failed_name);
    let check_name = failed_observation
        .checks
        .keys()
        .next()
        .expect("matrix observation has its aggregate check")
        .clone();
    let failed_check = native_adapter_matrix_check(failed_matrix, false)?;
    failed_observation.checks.insert(check_name, failed_check);
    failed_record.result = GateResult::Failed;
    assert!(
        crate::qualification_evidence::assess_observations(
            &plan,
            &manifest,
            QualificationPhase::Staging,
            &failed,
            NOW,
        )
        .is_err()
    );

    let mut changed_environment = complete;
    changed_environment[matrix_index]
        .qualification
        .as_mut()
        .and_then(|observation| observation.native_adapter_matrix.as_mut())
        .and_then(|matrix| matrix.environment.qemu.as_mut())
        .expect("production matrix fixture has QEMU identity")
        .version = "mutated-after-observation".into();
    assert!(
        crate::qualification_evidence::assess_observations(
            &plan,
            &manifest,
            QualificationPhase::Staging,
            &changed_environment,
            NOW,
        )
        .is_err()
    );
    Ok(())
}
