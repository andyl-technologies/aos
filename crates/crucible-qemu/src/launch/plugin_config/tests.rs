//! Plugin launch argument and continuation tests.

use super::*;

#[test]
fn complete_scenario_seed_controls_the_plugin_decision_root() {
    let mut first = [0_u8; 32];
    first[..8].copy_from_slice(&11_u64.to_le_bytes());
    let mut second = first;
    second[31] = 1;

    let first = QemuLaunchAppRandomConfig::from_seed(Seed::from_bytes(first), 8, "a");
    let second = QemuLaunchAppRandomConfig::from_seed(Seed::from_bytes(second), 8, "a");

    assert_eq!(first.scenario_seed, second.scenario_seed);
    assert_ne!(first.authoritative_seed(), second.authoritative_seed());
    assert_ne!(first.decision_rng_root_seed, second.decision_rng_root_seed);
}

#[test]
fn app_random_branch_and_continuation_arguments_are_canonical() {
    let positions = BTreeMap::from([
        (String::from("app-random/node:1:a/stream:4:beta"), 1),
        (String::from("app-random/node:1:a/stream:5:alpha"), 2),
    ]);
    let app_random = QemuLaunchAppRandomConfig::new(11, 8, "a")
        .with_branch_reseed(29, 3)
        .with_continuation(3, positions.clone());
    assert_eq!(app_random.branch_seed(), Some(Seed::from_u64(29)));
    let arguments = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0)
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_app_random(app_random)
        .plugin_args_raw();

    assert!(arguments.contains(&format!(
        "app_random_branch_seed={}",
        Seed::from_u64(29).decision_rng_root_seed()
    )));
    assert!(arguments.contains("app_random_branch_after=3"));
    assert!(arguments.contains("app_random_draw_offset=3"));
    assert!(arguments.contains(&format!(
        "app_random_positions={}",
        encode_stream_positions(&positions)
    )));
    assert_eq!(
        encode_stream_positions(&positions),
        "6170702d72616e646f6d2f6e6f64653a313a612f73747265616d3a343a62657461:1;\
         6170702d72616e646f6d2f6e6f64653a313a612f73747265616d3a353a616c706861:2"
    );
}

#[test]
fn process_generation_is_canonical_and_nonzero() {
    let config = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0).with_process_generation(42);

    assert_eq!(config.process_generation(), 42);
    assert!(config.plugin_args_raw().contains("process_generation=42"));
    assert_eq!(config.validate(), Ok(()));

    let zero = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0).with_process_generation(0);
    assert_eq!(
        zero.validate(),
        Err(QemuLaunchCommandError::ZeroProcessGeneration)
    );
}

#[test]
fn authored_storage_history_limits_are_explicit_and_fail_closed() {
    let config = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0)
        .with_storage_completed_history_limits(7, 9);

    assert_eq!(config.storage_completed_history_epochs(), 7);
    assert_eq!(config.storage_completed_history_gaps(), 9);
    assert!(
        config
            .plugin_args_raw()
            .contains("storage_completed_history_epochs=7,storage_completed_history_gaps=9")
    );
    assert_eq!(config.validate(), Ok(()));

    let hard = crucible::model::FaultResourceLimits::compiled_maximum();
    let invalid = config.clone().with_storage_completed_history_limits(
        hard.storage_completed_history_epochs + 1,
        hard.storage_completed_history_gaps,
    );
    assert_eq!(
        invalid.validate(),
        Err(QemuLaunchCommandError::InvalidPluginResourceLimit {
            field: PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS,
            configured: hard.storage_completed_history_epochs + 1,
            hard: hard.storage_completed_history_epochs,
        })
    );
}

#[test]
fn app_random_branch_plan_must_name_the_launched_node() -> Result<(), Box<dyn std::error::Error>> {
    let stream = crucible_protocol::app_random_transport::app_random_stream_name("b", "draw");
    let entry = crucible_protocol::app_random_branch_plan::AppRandomBranchPlanEntry::new(
        0, 7, 9, [0x5a; 32], stream,
    )?;
    let plan = crucible_protocol::app_random_branch_plan::AppRandomBranchPlan::new(vec![entry])?;
    let config = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0)
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_whitebox_setup(
            super::whitebox_setup::QemuWhiteboxSetupValidation::test_x86_unclaimed(),
        )
        .with_app_random(QemuLaunchAppRandomConfig::new(11, 8, "a").with_branch_plan(plan));

    assert_eq!(
        config.validate(),
        Err(QemuLaunchCommandError::InvalidAppRandomBranchConfiguration)
    );
    Ok(())
}

#[test]
fn selectable_catalog_requires_whitebox_mode() -> Result<(), Box<dyn std::error::Error>> {
    use crucible_protocol::selectable_catalog_plan::{
        SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
        SelectablePlanLimits, SelectablePlanPresence,
    };

    let empty = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0)
        .with_selectable_catalog_plan(SelectableCatalogPlan::default());
    assert_eq!(empty.validate(), Ok(()));

    let declaration = SelectablePlanDeclaration::new(
        "network.policy",
        vec![1, 2],
        vec![1],
        vec!["recovery".to_owned()],
        SelectablePlanPresence::Required,
    )?;
    let plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 3, 3)?,
        vec![declaration],
        SelectablePlanContinuation::cold(),
    )?;
    let config =
        QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0).with_selectable_catalog_plan(plan);

    assert_eq!(
        config.validate(),
        Err(QemuLaunchCommandError::SelectableCatalogWhileWhiteboxDisabled)
    );
    Ok(())
}
