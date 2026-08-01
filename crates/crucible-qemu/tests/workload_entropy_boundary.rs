//! Checks RFC-0010 T-WL-2 workload entropy-boundary invariants.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{ContentHash, GuestWorkloadBinary};
use crucible_qemu::{
    DeterministicLaunchProfile, LaunchProfileCandidate, QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuControlPlaneObservation,
    QemuDeterminismBoundaryError, QemuEntropyElimination, QemuExecutionFingerprintDefinition,
    QemuLaunchArtifact, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuPreSpawnLaunchValidationError, QemuSimulationMode, QemuVmLaunchConfig,
    qemu_entropy_elimination_microtests, validate_pre_spawn_qemu_launch_args,
    validate_qemu_determinism_boundary, validate_x86_whitebox_hmp_mtree,
};

#[test]
fn workload_guest_rng_transcript_is_seeded_by_scenario_entropy_boundary() {
    let first = workload_profile(0xfeed_0010, GuestWorkloadBinary::ClientLoop);
    let repeated = workload_profile(0xfeed_0010, GuestWorkloadBinary::ClientLoop);
    let changed_seed = workload_profile(0xfeed_0011, GuestWorkloadBinary::ClientLoop);

    assert_eq!(first.guest_entropy_seed(), repeated.guest_entropy_seed());
    assert_eq!(
        workload_entropy_material(&first),
        workload_entropy_material(&repeated)
    );
    assert_ne!(
        first.guest_entropy_seed(),
        changed_seed.guest_entropy_seed()
    );
    assert_ne!(
        workload_entropy_material(&first),
        workload_entropy_material(&changed_seed)
    );

    let append = option_value(&first.canonical_qemu_args(), "-append");
    assert!(
        append
            .split_ascii_whitespace()
            .any(|arg| arg == "crucible.workload=httpget")
    );
    // The guest cmdline carries only the workload selector; entropy determinism
    // is delivered host-side by the seeded fw_cfg seed and builtin RNG below, so
    // no `random.trust_*` suppression flags are required in the guest cmdline.

    let args = first.canonical_qemu_args();
    assert_eq!(
        option_value(&args, "-fw_cfg"),
        "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin"
    );
    assert_eq!(
        option_value(&args, "-object"),
        "rng-builtin,id=crucible-rng0"
    );
    assert_eq!(
        option_value(&args, "-device"),
        "virtio-rng-pci,rng=crucible-rng0"
    );

    let material = first.scenario_hash_material();
    assert!(material.contains("guest_entropy_seed_source=scenario-seed"));
    assert!(material.contains("guest_entropy_rng_device=virtio-rng-pci,rng=crucible-rng0"));
    assert!(material.contains("guest_entropy_host_sources=disabled"));
}

#[test]
fn workload_new_entropy_source_fails_loudly() {
    let profile = workload_profile(0xfeed_0010, GuestWorkloadBinary::ClientLoop);
    let definition = QemuExecutionFingerprintDefinition::black_box_plugin(
        QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
    )
    .expect("canonical QEMU fingerprint definition should validate");
    let microtests = qemu_entropy_elimination_microtests();
    let report = validate_qemu_determinism_boundary(
        &profile,
        sim_on_observation(&profile),
        &definition,
        &microtests,
    )
    .expect("workload launch should satisfy QEMU determinism boundary");

    assert!(
        report
            .covered_entropy_eliminations
            .contains(&QemuEntropyElimination::GuestEntropyFwCfgSeed)
    );
    assert!(
        report
            .covered_entropy_eliminations
            .contains(&QemuEntropyElimination::CpuModelEntropyPin)
    );

    let mut host_rng_object = profile.canonical_qemu_args();
    host_rng_object.push(String::from("-object"));
    host_rng_object.push(String::from("rng-random,id=hostrng,filename=/dev/urandom"));
    assert_host_entropy_rejected(&host_rng_object, "host entropy");

    let mut unseeded_guest_rng = profile.canonical_qemu_args();
    replace_option_value(
        &mut unseeded_guest_rng,
        "-device",
        "virtio-rng-pci,rng=host-rng0",
    );
    assert_host_entropy_rejected(&unseeded_guest_rng, "unseeded guest entropy");

    let missing_fw_cfg_microtests = microtests
        .iter()
        .copied()
        .filter(|microtest| microtest.elimination != QemuEntropyElimination::GuestEntropyFwCfgSeed)
        .collect::<Vec<_>>();
    let error = validate_qemu_determinism_boundary(
        &profile,
        sim_on_observation(&profile),
        &definition,
        &missing_fw_cfg_microtests,
    )
    .expect_err("removing the guest entropy microtest must fail loudly");
    assert_eq!(
        error,
        QemuDeterminismBoundaryError::MissingMicrotest {
            elimination: QemuEntropyElimination::GuestEntropyFwCfgSeed,
        }
    );
}

fn workload_profile(seed: u64, workload: GuestWorkloadBinary) -> DeterministicLaunchProfile {
    let base = LaunchProfileCandidate::default();
    let cmdline = workload.selected_cmdline(&base.kernel_cmdline);
    LaunchProfileCandidate::default()
        .with_scenario_seed(seed)
        .with_kernel_cmdline(cmdline)
        .try_into_deterministic()
        .expect("workload launch profile should validate")
}

fn workload_entropy_material(profile: &DeterministicLaunchProfile) -> String {
    format!(
        "scenario_seed={}\nguest_entropy_seed_hex={}\n{}",
        profile.scenario_seed(),
        profile.guest_entropy_seed().to_lower_hex(),
        profile.scenario_hash_material()
    )
}

fn option_value(args: &[String], option: &str) -> String {
    args.windows(2)
        .find_map(|window| (window[0] == option).then(|| window[1].clone()))
        .unwrap_or_else(|| panic!("missing QEMU option {option}"))
}

fn replace_option_value(args: &mut [String], option: &str, replacement: &str) {
    let value = args
        .windows(2)
        .position(|window| window[0] == option)
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("missing QEMU option {option}"));
    args[value] = replacement.to_owned();
}

fn assert_host_entropy_rejected(args: &[String], reason: &'static str) {
    let error = validate_pre_spawn_qemu_launch_args(args)
        .expect_err("host entropy source must be rejected before QEMU spawn");
    match error {
        QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
            reason: actual, ..
        } => assert_eq!(actual, reason),
        other => panic!("expected host entropy launch rejection, got {other:?}"),
    }
}

fn sim_on_observation(profile: &DeterministicLaunchProfile) -> QemuControlPlaneObservation {
    let command = profile
        .qemu_launch_command(default_vm_config(), default_qemu_binary(), plugin_config())
        .expect("sim-on workload launch command should validate");
    QemuControlPlaneObservation {
        simulation_mode: QemuSimulationMode::On,
        qemu_args: command.args().to_vec(),
        ..QemuControlPlaneObservation::sim_on_protocol_contract()
    }
}

fn plugin_config() -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_whitebox(QemuLaunchPluginSwitch::On)
    .with_whitebox_setup(
        validate_x86_whitebox_hmp_mtree(
            "FlatView #2\n AS \"I/O\", root: io\n  00000000000000e0-00000000000000ef (prio 0, i/o): io @00000000000000e0\n",
        )
        .unwrap_or_else(|error| panic!("test white-box setup validation failed: {error}")),
    )
}

fn default_vm_config() -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new(
        "workload-client",
        artifact(
            "kernel",
            "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        ),
        artifact(
            "root-image",
            "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
        ),
    )
}

fn default_qemu_binary() -> &'static str {
    "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
}

fn artifact(label: &str, path: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(ContentHash::from_bytes(label.as_bytes()), path)
}

#[test]
fn workload_plugin_observation_uses_fixed_setup_fds() {
    let plugin = plugin_config();
    let argument = plugin.qemu_plugin_argument();
    assert!(argument.contains(&format!("simfd={QEMU_PLUGIN_CONTROL_FD}")));
    assert!(argument.contains(&format!("shmemfd={QEMU_PLUGIN_SHMEM_FD}")));
    assert!(argument.contains(&format!("wakefd={QEMU_PLUGIN_WAKE_FD}")));
    assert!(argument.contains("whitebox=on"));
}
