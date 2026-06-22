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
    assert!(args.windows(2).any(|window| {
        window[0] == "-fw_cfg"
            && window[1] == "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin"
    }));
    assert!(
        args.windows(2)
            .any(|window| window == ["-object", "rng-builtin,id=crucible-rng0"])
    );
    assert!(
        args.windows(2)
            .any(|window| window == ["-device", "virtio-rng-pci,rng=crucible-rng0"])
    );
    let append = args
        .windows(2)
        .find_map(|window| (window[0] == "-append").then_some(window[1].as_str()))
        .unwrap_or_default();
    assert!(append.split_ascii_whitespace().any(|arg| arg == "nokaslr"));
    assert!(
        append
            .split_ascii_whitespace()
            .any(|arg| arg == "norandmaps")
    );
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
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet")
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelCpuRandomTrustNotDisabled)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off")
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelBootloaderRandomTrustNotDisabled)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off random.trust_bootloader=on",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelTrustsBootloaderRandom)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off random.trust_cpu=1 random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelCpuRandomTrustAmbiguous)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=1 random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelTrustsHostCpuRandom)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off random.trust_bootloader=off random.trust_bootloader=1",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelBootloaderRandomTrustAmbiguous)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet norandmaps random.trust_cpu=off random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelKaslrNotDisabled)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet nokaslr random.trust_cpu=off random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::UserspaceAslrNotDisabled)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet kaslr nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelKaslrExplicitlyEnabled)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet nokaslr nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::KernelKaslrFlagAmbiguous)
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline(
                "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps=0 random.trust_cpu=off random.trust_bootloader=off",
            )
            .try_into_deterministic(),
        Err(LaunchProfileError::UserspaceAslrFlagAmbiguous)
    );
    assert_eq!(
        LaunchProfileCandidate {
            run_seed: 0x1234,
            ..LaunchProfileCandidate::default()
        }
        .try_into_deterministic(),
        Err(LaunchProfileError::RunSeedDiffersFromScenarioSeed {
            scenario_seed: 0x0010_c001,
            run_seed: 0x1234,
        })
    );
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
        "scenario_seed=1097729",
        "qemu_run_seed=1097729",
        "qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin",
        "guest_entropy_fw_cfg_name=opt/crucible/seed",
        "guest_entropy_seed_file_name=crucible-guest-entropy-seed.bin",
        "guest_entropy_seed_source=scenario-seed",
        "guest_entropy_rng_object=rng-builtin,id=crucible-rng0",
        "guest_entropy_rng_device=virtio-rng-pci,rng=crucible-rng0",
        "guest_entropy_host_sources=disabled",
        "kernel_cmdline=console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off",
    ] {
        assert!(material.contains(expected), "missing {expected}");
    }
    let seed_hex_line = material
        .lines()
        .find(|line| line.starts_with("guest_entropy_seed_hex="))
        .unwrap_or_default();
    assert_eq!(
        seed_hex_line.len(),
        "guest_entropy_seed_hex=".len() + 64,
        "guest entropy seed must be 32 bytes of lowercase hex"
    );

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
    let cmdline = deterministic(LaunchProfileCandidate::default().with_kernel_cmdline(
        "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off net.ifnames=0",
    ))
    .scenario_hash_material();
    let scenario_seed = deterministic(LaunchProfileCandidate::default().with_scenario_seed(0x1234))
        .scenario_hash_material();
    let run_seed = deterministic(LaunchProfileCandidate::default().with_run_seed(0x1234))
        .scenario_hash_material();

    assert_ne!(material, shifted);
    assert_ne!(material, machine);
    assert_ne!(material, memory);
    assert_ne!(material, epoch);
    assert_ne!(material, cmdline);
    assert_ne!(material, scenario_seed);
    assert_ne!(material, run_seed);
}

#[test]
fn launch_profile_binds_fw_cfg_file_to_guest_entropy_seed() {
    let profile = default_profile();
    let seed_file = profile.guest_entropy_seed_file();

    assert_eq!(seed_file.file_name(), "crucible-guest-entropy-seed.bin");
    assert_eq!(seed_file.bytes(), profile.guest_entropy_seed().bytes());
    assert!(profile.canonical_qemu_args().windows(2).any(|window| {
        window[0] == "-fw_cfg"
            && window[1] == format!("name=opt/crucible/seed,file={}", seed_file.file_name())
    }));

    let mut dir = std::env::temp_dir();
    dir.push(format!("crucible-qemu-seed-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!("failed to create temporary seed-file directory {dir:?}: {error}");
    });

    let path = seed_file.write_to_dir(&dir).unwrap_or_else(|error| {
        panic!("failed to write deterministic seed file into {dir:?}: {error}");
    });
    let written = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read deterministic seed file {path:?}: {error}");
    });
    assert_eq!(written.as_slice(), seed_file.bytes());

    std::fs::remove_dir_all(&dir).unwrap_or_else(|error| {
        panic!("failed to remove temporary seed-file directory {dir:?}: {error}");
    });
}

#[test]
fn guest_entropy_seed_is_scenario_seed_derived() {
    let first = default_profile();
    let repeated = default_profile();
    let changed_scenario_seed =
        deterministic(LaunchProfileCandidate::default().with_scenario_seed(0x1234));
    let changed_run_seed = deterministic(LaunchProfileCandidate::default().with_run_seed(0x1234));

    assert_eq!(first.guest_entropy_seed(), repeated.guest_entropy_seed());
    assert_eq!(first.guest_entropy_seed().bytes().len(), 32);
    assert_ne!(
        first.guest_entropy_seed(),
        changed_scenario_seed.guest_entropy_seed()
    );
    assert_ne!(
        first.guest_entropy_seed(),
        changed_run_seed.guest_entropy_seed(),
        "the QEMU internal seed is unified with the guest CSPRNG scenario seed"
    );
    assert_eq!(first.scenario_seed(), 0x0010_c001);
    assert_eq!(changed_scenario_seed.scenario_seed(), 0x1234);
    assert_eq!(changed_run_seed.scenario_seed(), 0x1234);
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
