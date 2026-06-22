//! Deterministic QEMU launch-profile integration tests.
//!
//! These tests lock the public Contract-A launch API to the deterministic
//! launch surface required by RFC-0010 T-DET-1.

use crucible::ScenarioDef;
use crucible_qemu::{
    DeterministicLaunchProfile, DiskImageMode, IcountShiftSetting, InputPolicy,
    LaunchProfileCandidate, LaunchProfileError, MachineResetMode,
};

fn default_profile() -> DeterministicLaunchProfile {
    match DeterministicLaunchProfile::conservative_default() {
        Ok(profile) => profile,
        Err(error) => panic!("default deterministic launch profile failed: {error}"),
    }
}

fn deterministic(candidate: LaunchProfileCandidate) -> DeterministicLaunchProfile {
    match candidate.try_into_deterministic() {
        Ok(profile) => profile,
        Err(error) => panic!("candidate should be deterministic: {error}"),
    }
}

#[test]
fn default_launch_profile_pins_contract_a_arguments() {
    let args = default_profile().canonical_qemu_args();

    assert!(
        args.windows(2)
            .any(|window| window == ["-cpu", "qemu64,-rdrand,-rdseed"])
    );
    assert!(
        args.windows(2)
            .any(|window| window == ["-accel", "tcg,thread=single"])
    );
    assert!(
        args.windows(2)
            .any(|window| window == ["-machine", "pc-q35-9.2"])
    );
    assert!(args.windows(2).any(|window| window == ["-m", "512M"]));
    assert!(args.windows(2).any(|window| window == ["-smp", "1"]));
    assert!(
        args.windows(2)
            .any(|window| window == ["-icount", "shift=0,sleep=off,align=off"])
    );
    assert!(
        args.windows(2)
            .any(|window| window == ["-rtc", "base=2026-01-01T00:00:00,clock=vm"])
    );
    assert!(args.windows(2).any(|window| window == ["-seed", "1097729"]));
    assert!(args.iter().any(|arg| arg == "-nodefaults"));
    assert!(args.iter().any(|arg| arg == "-no-user-config"));
}

#[test]
fn launch_profile_rejects_host_entropy_and_host_timing() {
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_cpu_model("host")
            .try_into_deterministic(),
        Err(LaunchProfileError::CpuModelUsesHost)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_cpu_model("qemu64,+rdrand")
            .try_into_deterministic(),
        Err(LaunchProfileError::CpuEntropyFeatureEnabled { feature: "rdrand" })
    );
    assert!(matches!(
        LaunchProfileCandidate::default()
            .with_accelerator("tcg,thread=multi")
            .try_into_deterministic(),
        Err(LaunchProfileError::AcceleratorNotSingleThreadTcg { .. })
    ));
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_icount_shift(IcountShiftSetting::Auto)
            .try_into_deterministic(),
        Err(LaunchProfileError::IcountShiftAuto)
    );
    assert!(matches!(
        LaunchProfileCandidate::default()
            .with_rtc_clock("host")
            .try_into_deterministic(),
        Err(LaunchProfileError::RtcClockNotVm { .. })
    ));
}

#[test]
fn launch_profile_rejects_mutating_or_interactive_state() {
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_memory_mib(0)
            .try_into_deterministic(),
        Err(LaunchProfileError::MemorySizeZero)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_smp_vcpus(2)
            .try_into_deterministic(),
        Err(LaunchProfileError::SmpNotSingleVcpu { requested: 2 })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_machine_reset(MachineResetMode::HostProvided)
            .try_into_deterministic(),
        Err(LaunchProfileError::MachineResetNotDeterministic {
            mode: MachineResetMode::HostProvided,
        })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_disk_image_mode(DiskImageMode::WritableBacking)
            .try_into_deterministic(),
        Err(LaunchProfileError::DiskImageMutatesBacking {
            mode: DiskImageMode::WritableBacking,
        })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_input_policy(InputPolicy::HostInteractive)
            .try_into_deterministic(),
        Err(LaunchProfileError::InteractiveInputEnabled {
            policy: InputPolicy::HostInteractive,
        })
    );
}

#[test]
fn launch_hash_material_records_every_determinism_field() {
    let material = default_profile().scenario_hash_material();

    for expected in [
        "crucible.launch.v1",
        "cpu_model=qemu64,-rdrand,-rdseed",
        "machine_type=pc-q35-9.2",
        "memory_mib=512",
        "smp_vcpus=1",
        "accelerator=tcg,thread=single",
        "icount_shift=0",
        "virtual_time_ns=icount<<shift",
        "rtc_epoch_utc=2026-01-01T00:00:00",
        "rtc_clock=vm",
        "machine_reset=deterministic-zeroed-ram-fixed-devices",
        "ram_reset=zeroed-fresh-anonymous-memory",
        "disk_image_mode=copy-on-write-overlay",
        "input_policy=no-interactive-input",
        "qemu_run_seed=1097729",
        "qemu_run_seed_controls=guest-random,glib-global-prng",
        "kernel_cmdline=console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off",
    ] {
        assert!(material.contains(expected), "missing {expected}");
    }

    let shifted = deterministic(
        LaunchProfileCandidate::default().with_icount_shift(IcountShiftSetting::Fixed(1)),
    )
    .scenario_hash_material();
    let machine = deterministic(LaunchProfileCandidate::default().with_machine_type("pc-q35-9.1"))
        .scenario_hash_material();
    let memory = deterministic(LaunchProfileCandidate::default().with_memory_mib(1024))
        .scenario_hash_material();
    let epoch =
        deterministic(LaunchProfileCandidate::default().with_rtc_epoch_utc("2026-01-02T00:00:00"))
            .scenario_hash_material();
    let cmdline = deterministic(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet"),
    )
    .scenario_hash_material();
    let run_seed = deterministic(LaunchProfileCandidate::default().with_run_seed(0x1234))
        .scenario_hash_material();

    assert_ne!(material, shifted);
    assert_ne!(material, machine);
    assert_ne!(material, memory);
    assert_ne!(material, epoch);
    assert_ne!(material, cmdline);
    assert_ne!(material, run_seed);
}

#[test]
fn virtual_time_uses_checked_icount_shift_mapping() {
    let profile = deterministic(
        LaunchProfileCandidate::default().with_icount_shift(IcountShiftSetting::Fixed(4)),
    );

    assert_eq!(profile.virtual_ns_from_icount(3), Ok(48));
    assert_eq!(
        profile.virtual_ns_from_icount(u64::MAX),
        Err(LaunchProfileError::VirtualTimeOverflow {
            icount: u64::MAX,
            shift: 4,
        })
    );
}

#[test]
fn launch_material_feeds_scenario_identity() {
    let profile = default_profile();
    let shifted = deterministic(
        LaunchProfileCandidate::default().with_icount_shift(IcountShiftSetting::Fixed(1)),
    );

    let base_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &profile.scenario_hash_material(),
    );
    let repeated_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &profile.scenario_hash_material(),
    );
    let shifted_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &shifted.scenario_hash_material(),
    );

    assert_eq!(base_scenario, repeated_scenario);
    assert_ne!(base_scenario.id, shifted_scenario.id);
}
