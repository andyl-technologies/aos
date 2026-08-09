//! Deterministic QEMU launch-profile integration tests.
//!
//! These tests lock the public Contract-A launch API to the deterministic
//! launch surface required by RFC-0010 T-DET-1.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{ContentHash, NodeId, ScenarioDef, SchedulerNodeId, SchedulingNodeKind};
use crucible_qemu::{
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    IcountShiftSetting, InputPolicy, LaunchProfileCandidate, LaunchProfileError, MachineResetMode,
    NodeIcountShift, QemuLaunchArtifact, QemuLaunchCommand, QemuLaunchCommandBuilder,
    QemuLaunchCommandError, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuPreSpawnLaunchValidationError, QemuVmLaunchConfig, validate_pre_spawn_qemu_launch_args,
    validate_x86_whitebox_hmp_mtree,
};

#[path = "deterministic_launch/fingerprint_options.rs"]
mod fingerprint_options;
#[path = "deterministic_launch/launch_artifacts.rs"]
mod launch_artifacts;

use fingerprint_options::validated_whitebox_setup;

fn default_profile() -> DeterministicLaunchProfile {
    match DeterministicLaunchProfile::conservative_default() {
        Ok(profile) => profile,
        Err(error) => panic!("default deterministic launch profile failed: {error}"),
    }
}

fn default_plugin_config() -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
}

fn default_vm_config() -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new(
        "vm-a",
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

fn firmware_boot_vm_config() -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new_firmware_boot(
        "vm-firmware",
        artifact(
            "firmware",
            "/nix/store/77777777777777777777777777777777-crucible-firmware/bios.bin",
        ),
    )
}

fn default_qemu_binary() -> &'static str {
    "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
}

fn artifact(domain: &str, path: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(ContentHash::from_canonical_material(domain, path), path)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn default_launch_command() -> QemuLaunchCommand {
    default_profile()
        .qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("default QEMU launch command failed: {error}"))
}

fn deterministic(candidate: LaunchProfileCandidate) -> DeterministicLaunchProfile {
    match candidate.try_into_deterministic() {
        Ok(profile) => profile,
        Err(error) => panic!("candidate should be deterministic: {error}"),
    }
}

fn scenario_material_for_nodes(
    profile: &DeterministicLaunchProfile,
    node_shifts: &[NodeIcountShift],
) -> String {
    profile
        .scenario_hash_material_for_nodes(node_shifts)
        .unwrap_or_else(|error| panic!("node shift material should be valid: {error}"))
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
            .any(|window| window == ["-accel", "sim,thread=single"])
    );
    assert!(
        args.windows(2)
            .any(|window| window == ["-machine", "pc-q35-9.2"])
    );
    assert!(args.windows(2).any(|window| window == ["-m", "512M"]));
    assert!(args.windows(2).any(|window| window == ["-smp", "1"]));
    assert!(args.windows(2).any(|window| window
        == [
            "-icount",
            "shift=0,sleep=off,align=off,rr_switch_quantum=4096"
        ]));
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
    assert_eq!(append, "console=ttyS0 reboot=k panic=1 quiet");
    assert!(args.iter().any(|arg| arg == "-nodefaults"));
    assert!(args.iter().any(|arg| arg == "-no-user-config"));
}

#[test]
fn pre_spawn_launch_validation_accepts_canonical_arguments() {
    let args = default_profile().canonical_qemu_args();
    let validation = validate_pre_spawn_qemu_launch_args(&args)
        .unwrap_or_else(|error| panic!("canonical launch args should validate: {error}"));

    assert_eq!(validation.accelerator(), "sim,thread=single");
    assert_eq!(validation.icount_shift(), 0);
    assert_eq!(validation.rr_switch_quantum(), 4096);
    assert_eq!(validation.smp_vcpus(), 1);
    assert_eq!(validation.cpu_model(), "qemu64,-rdrand,-rdseed");
}

#[test]
fn multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed() {
    let profile = deterministic(
        LaunchProfileCandidate::default()
            .with_smp_vcpus(4)
            .with_rr_switch_quantum(8192),
    );
    let args = profile.canonical_qemu_args();

    assert_eq!(profile.smp_vcpus(), 4);
    assert_eq!(profile.rr_switch_quantum(), 8192);
    let scheduler_policy = profile
        .scheduler_run_subdivision_policy(SchedulerNodeId {
            node: NodeId {
                name: String::from("vm-a"),
            },
            kind: SchedulingNodeKind::Vm,
        })
        .unwrap_or_else(|error| {
            panic!("launch profile should derive scheduler RR policy: {error}")
        });
    assert_eq!(scheduler_policy.vcpu_count, 4);
    assert_eq!(scheduler_policy.rr_switch_quantum, 8192);
    assert!(
        args.windows(2)
            .any(|window| window == ["-accel", "sim,thread=single"])
    );
    assert!(args.windows(2).any(|window| window == ["-smp", "4"]));
    assert!(args.windows(2).any(|window| window
        == [
            "-icount",
            "shift=0,sleep=off,align=off,rr_switch_quantum=8192"
        ]));

    let validation = validate_pre_spawn_qemu_launch_args(&args)
        .unwrap_or_else(|error| panic!("multi-vCPU RR launch args should validate: {error}"));
    assert_eq!(validation.accelerator(), "sim,thread=single");
    assert_eq!(validation.smp_vcpus(), 4);
    assert_eq!(validation.rr_switch_quantum(), 8192);
    assert_eq!(validation.cpu_model(), "qemu64,-rdrand,-rdseed");

    let mut alias_args = args.clone();
    replace_option_value(
        &mut alias_args,
        "-icount",
        "shift=0,sleep=off,align=off,crucible-rr-quantum-icount=8192",
    );
    let alias_validation = validate_pre_spawn_qemu_launch_args(&alias_args)
        .unwrap_or_else(|error| panic!("RFC alias RR quantum args should validate: {error}"));
    assert_eq!(alias_validation.smp_vcpus(), 4);
    assert_eq!(alias_validation.rr_switch_quantum(), 8192);

    let material = profile.scenario_hash_material();
    assert!(material.contains("smp_vcpus=4"));
    assert!(material.contains("vcpu_topology=fixed-at-genesis"));
    assert!(material.contains("runtime_cpu_hotplug=forbidden"));
    assert!(material.contains("rr_switch_quantum=8192"));
    assert!(material.contains("rr_switch_quantum_units=node-icount"));
    assert!(material.contains("rr_vcpu_rotation=ascending-vcpu-id"));
    assert!(material.contains("per_vcpu_cpu_model=uniform"));
    assert!(material.contains("per_vcpu_tsc_source=node-icount"));
    assert!(material.contains("per_vcpu_rng_source=scenario-seed-and-run-seed"));
    assert!(material.contains("per_vcpu_rng_timing_axis=node-icount"));
    assert!(material.contains("secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic"));

    let different_vcpu_count = deterministic(
        LaunchProfileCandidate::default()
            .with_smp_vcpus(2)
            .with_rr_switch_quantum(8192),
    )
    .scenario_hash_material();
    let different_quantum = deterministic(
        LaunchProfileCandidate::default()
            .with_smp_vcpus(4)
            .with_rr_switch_quantum(4096),
    )
    .scenario_hash_material();
    assert_ne!(material, different_vcpu_count);
    assert_ne!(material, different_quantum);
}

#[test]
fn pre_spawn_launch_validation_rejects_kvm_and_non_sim_accelerators() {
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&qemu_args(["-enable-kvm"])),
        Err(
            QemuPreSpawnLaunchValidationError::KvmOrHardwareAcceleration {
                argument: String::from("-enable-kvm"),
            }
        )
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&qemu_args([
            "-accel",
            "kvm",
            "-smp",
            "1",
            "-icount",
            "shift=0,sleep=off,align=off,rr_switch_quantum=4096",
            "-cpu",
            "qemu64,-rdrand,-rdseed",
        ])),
        Err(
            QemuPreSpawnLaunchValidationError::KvmOrHardwareAcceleration {
                argument: String::from("kvm"),
            }
        )
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&qemu_args([
            "-accel",
            "hvf",
            "-smp",
            "1",
            "-icount",
            "shift=0,sleep=off,align=off,rr_switch_quantum=4096",
            "-cpu",
            "qemu64,-rdrand,-rdseed",
        ])),
        Err(
            QemuPreSpawnLaunchValidationError::KvmOrHardwareAcceleration {
                argument: String::from("hvf"),
            }
        )
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&qemu_args([
            "-accel",
            "sim,thread=single",
            "-machine",
            "q35,accel=kvm",
            "-smp",
            "1",
            "-icount",
            "shift=0,sleep=off,align=off,rr_switch_quantum=4096",
            "-cpu",
            "qemu64,-rdrand,-rdseed",
        ])),
        Err(
            QemuPreSpawnLaunchValidationError::MachineUsesNonSimAcceleration {
                machine: String::from("q35,accel=kvm"),
            }
        )
    );
}

#[test]
fn pre_spawn_launch_validation_rejects_bad_icount_and_mttcg() {
    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=auto,sleep=off,align=off,rr_switch_quantum=4096",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::IcountShiftAuto)
    );

    let mut args = default_profile().canonical_qemu_args();
    remove_option_pair(&mut args, "-icount");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::MissingOption { option: "-icount" })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-accel", "sim,thread=multi");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::MultiThreadTcg {
            accelerator: String::from("sim,thread=multi"),
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-accel", "sim,thread=single,thread=multi");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::DuplicateSubOption {
            option: "-accel",
            key: "thread",
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-accel", "sim");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::SingleThreadSimNotPinned {
                accelerator: String::from("sim"),
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-accel", "tcg,thread=single");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::NonSimAccelerator {
            accelerator: String::from("tcg,thread=single"),
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-icount", "shift=0,sleep=off,align=off");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumUnpinned)
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=0,sleep=off,align=off,rr_switch_quantum=2147483648",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumTooLarge {
            quantum: i32::MAX as u64 + 1,
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=0,sleep=on,align=off,rr_switch_quantum=4096",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::IcountOptionInvalid {
            key: "sleep",
            expected: "off",
            value: String::from("on"),
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=0,sleep=off,align=on,rr_switch_quantum=4096",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::IcountOptionInvalid {
            key: "align",
            expected: "off",
            value: String::from("on"),
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=0,sleep=off,align=off,rr_switch_quantum=4096,rr_switch_quantum=8192",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::DuplicateSubOption {
            option: "-icount",
            key: "rr_switch_quantum",
        })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(
        &mut args,
        "-icount",
        "shift=0,sleep=off,align=off,rr_switch_quantum=4096,crucible-rr-quantum-icount=4096",
    );
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::DuplicateSubOption {
            option: "-icount",
            key: "rr_switch_quantum",
        })
    );
}

#[test]
fn pre_spawn_launch_validation_rejects_host_cpu_timing_and_entropy() {
    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-cpu", "host");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::CpuModelUsesHost)
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-cpu", "qemu64,+rdrand");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::CpuEntropyFeatureEnabled { feature: "rdrand" })
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-rtc", "base=localtime,clock=host");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-rtc base=localtime,clock=host"),
                reason: "host RTC clock",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-rtc", "clock=vm");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-rtc clock=vm"),
                reason: "host RTC base",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    replace_option_value(&mut args, "-rtc", "base=utc,clock=vm");
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-rtc base=utc,clock=vm"),
                reason: "host RTC base",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    remove_option_pair(&mut args, "-rtc");
    args.push(String::from("-rtc=base=utc,clock=vm"));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-rtc base=utc,clock=vm"),
                reason: "host RTC base",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args(["-netdev", "user,id=net0"]));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-netdev user,id=net0"),
                reason: "host-timing user networking",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.push(String::from("-netdev=user,id=net1"));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-netdev=user,id=net1"),
                reason: "host-timing user networking",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args(["-realtime", "mlock=on"]));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-realtime"),
                reason: "host realtime clocking",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args(["-real-time", "mlock=off"]));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-real-time"),
                reason: "host realtime clocking",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args([
        "-object",
        "rng-random,id=hostrng,filename=/dev/urandom",
    ]));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-object rng-random,id=hostrng,filename=/dev/urandom"),
                reason: "host entropy",
            }
        )
    );

    let mut args = default_profile().canonical_qemu_args();
    args.push(String::from(
        "-object=rng-random,id=hostrng,filename=/tmp/seed",
    ));
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: String::from("-object=rng-random,id=hostrng,filename=/tmp/seed"),
                reason: "host entropy",
            }
        )
    );
}

#[test]
fn pre_spawn_launch_validation_accepts_only_an_unbridged_hubport() {
    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args([
        "-netdev",
        "hubport,id=crucible-netdev0,hubid=0",
    ]));
    assert!(validate_pre_spawn_qemu_launch_args(&args).is_ok());

    for value in [
        "hubport,id=net0,hubid=0,netdev=tap0",
        "hubport,id=net0",
        "hubport,hubid=0",
        "hubport,id=net0,hubid=not-a-number",
    ] {
        let mut args = default_profile().canonical_qemu_args();
        args.extend(qemu_args(["-netdev", value]));
        assert!(matches!(
            validate_pre_spawn_qemu_launch_args(&args),
            Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    reason: "host-timed or host-fed networking",
                    ..
                }
            )
        ));
    }
}

#[test]
fn pre_spawn_launch_validation_rejects_host_input_bypass_forms() {
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["-netdev", "tap,id=net0,ifname=tap0"],
            "-netdev tap,id=net0,ifname=tap0",
            "host-timed or host-fed networking",
        ),
        (
            &["-net=socket,listen=:1234"],
            "-net=socket,listen=:1234",
            "host-timed or host-fed networking",
        ),
        (
            &["-nic", "socket,connect=127.0.0.1:1234"],
            "-nic socket,connect=127.0.0.1:1234",
            "host-timed or host-fed networking",
        ),
        (
            &["-chardev", "socket,id=hostchar,path=/tmp/qemu.sock"],
            "-chardev socket,id=hostchar,path=/tmp/qemu.sock",
            "host-backed character-device input",
        ),
        (
            &["-chardev=file,id=hostlog,path=/tmp/qemu.log"],
            "-chardev=file,id=hostlog,path=/tmp/qemu.log",
            "host-backed character-device input",
        ),
        (
            &["-serial", "tcp:127.0.0.1:4444,server=on"],
            "-serial tcp:127.0.0.1:4444,server=on",
            "host-backed character frontend input",
        ),
        (
            &["-parallel=file:/tmp/parallel"],
            "-parallel=file:/tmp/parallel",
            "host-backed character frontend input",
        ),
        (
            &["-device", "usb-host,hostbus=1,hostaddr=2"],
            "-device usb-host,hostbus=1,hostaddr=2",
            "host device passthrough",
        ),
        (
            &["-device=usb-host,hostbus=1,hostaddr=2"],
            "-device=usb-host,hostbus=1,hostaddr=2",
            "host device passthrough",
        ),
        (
            &["-usbdevice", "host:1.2"],
            "-usbdevice host:1.2",
            "host USB or legacy passthrough input",
        ),
    ];

    for (extra_args, expected_argument, expected_reason) in cases {
        let mut args = default_profile().canonical_qemu_args();
        args.extend(extra_args.iter().map(|argument| (*argument).to_owned()));
        assert_eq!(
            validate_pre_spawn_qemu_launch_args(&args),
            Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    argument: (*expected_argument).to_owned(),
                    reason: expected_reason,
                }
            ),
            "host input bypass should fail closed: {extra_args:?}"
        );
    }
}

#[test]
fn pre_spawn_launch_validation_preserves_disabled_and_internal_channels() {
    let mut args = default_profile().canonical_qemu_args();
    args.extend(qemu_args(["-net", "none"]));
    args.push(String::from("-netdev=none"));
    args.extend(qemu_args(["-nic", "none"]));
    args.extend(qemu_args(["-chardev", "null,id=null0"]));
    args.push(String::from("-chardev=ringbuf,id=ring0,size=4096"));

    assert!(
        validate_pre_spawn_qemu_launch_args(&args).is_ok(),
        "disabled network frontends and in-process chardevs must remain valid"
    );
}

#[test]
fn launch_profile_enforces_guest_non_modification() {
    let profile = default_profile();
    let args = profile.canonical_qemu_args();
    let material = profile.scenario_hash_material();

    for expected in [
        "disk_image_mode=copy-on-write-overlay",
        "guest_write_policy=copy-on-write-overlay",
        "guest_backing_state=byte-identical-genesis",
        "guest_on_disk_mutation_policy=forbidden-by-launch-profile",
        "guest_core_content=host-side-only",
    ] {
        assert!(material.contains(expected), "missing {expected}");
    }

    for forbidden_flag in [
        "-drive",
        "-blockdev",
        "-cdrom",
        "-hda",
        "-hdb",
        "-hdc",
        "-hdd",
    ] {
        assert!(
            !args.iter().any(|arg| arg == forbidden_flag),
            "diskless Contract-A profile must not expose writable backing flag {forbidden_flag}"
        );
    }
    for forbidden_fragment in ["virtio-blk", "ide-hd", "scsi-hd", "virtio-9p"] {
        assert!(
            !args.iter().any(|arg| arg.contains(forbidden_fragment)),
            "diskless Contract-A profile must not expose writable device {forbidden_fragment}"
        );
    }

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
            .with_guest_backing_state(GuestBackingStateMode::HostMutableGenesis)
            .try_into_deterministic(),
        Err(LaunchProfileError::GuestBackingStateNotByteIdentical {
            mode: GuestBackingStateMode::HostMutableGenesis,
        })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_guest_core_content(GuestCoreContentMode::GuestInjectedContent)
            .try_into_deterministic(),
        Err(LaunchProfileError::GuestCoreContentRequired {
            mode: GuestCoreContentMode::GuestInjectedContent,
        })
    );
}

#[test]
fn launch_profile_admits_only_consistent_diskless_storage() {
    let diskless = LaunchProfileCandidate::default()
        .with_disk_image_mode(DiskImageMode::NoBlockDevice)
        .with_guest_backing_state(GuestBackingStateMode::NoBlockDevice)
        .try_into_deterministic()
        .unwrap_or_else(|error| panic!("diskless deterministic profile should validate: {error}"));
    assert_eq!(diskless.disk_image_mode(), DiskImageMode::NoBlockDevice);
    assert_eq!(
        diskless.guest_backing_state(),
        GuestBackingStateMode::NoBlockDevice
    );
    assert!(
        diskless
            .scenario_hash_material()
            .contains("disk_image_mode=no-block-device")
    );

    assert_eq!(
        LaunchProfileCandidate::default()
            .with_disk_image_mode(DiskImageMode::NoBlockDevice)
            .try_into_deterministic(),
        Err(LaunchProfileError::StorageModeMismatch {
            disk: DiskImageMode::NoBlockDevice,
            backing: GuestBackingStateMode::ByteIdenticalGenesis,
        })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_guest_backing_state(GuestBackingStateMode::NoBlockDevice)
            .try_into_deterministic(),
        Err(LaunchProfileError::StorageModeMismatch {
            disk: DiskImageMode::CopyOnWriteOverlay,
            backing: GuestBackingStateMode::NoBlockDevice,
        })
    );
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
            .with_accelerator("sim,thread=multi")
            .try_into_deterministic(),
        Err(LaunchProfileError::AcceleratorNotSingleThreadSim { .. })
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
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_rr_switch_quantum(i32::MAX as u64 + 1)
            .try_into_deterministic(),
        Err(LaunchProfileError::RrSwitchQuantumTooLarge {
            quantum: i32::MAX as u64 + 1,
        })
    );
}

#[test]
fn launch_profile_accepts_any_guest_kernel_cmdline() {
    // Determinism is delivered host-side (seeded fw_cfg entropy + builtin RNG),
    // so the guest kernel command line is the guest's own choice. A stock
    // cmdline with no entropy-suppression flags validates, and a cmdline that
    // itself opts into `nokaslr`/`norandmaps`/`random.trust_*` is equally legal.
    for cmdline in [
        "console=ttyS0 reboot=k panic=1 quiet",
        "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off",
        "console=ttyS0 reboot=k panic=1 quiet kaslr random.trust_cpu=on",
        "root=/dev/vda1 rw",
    ] {
        let profile = deterministic(LaunchProfileCandidate::default().with_kernel_cmdline(cmdline));
        assert_eq!(
            option_value(&profile.canonical_qemu_args(), "-append"),
            cmdline,
            "the launch profile passes the guest cmdline through unchanged"
        );
        assert!(
            validate_pre_spawn_qemu_launch_args(&profile.canonical_qemu_args()).is_ok(),
            "any guest cmdline must pass pre-spawn validation with host-side seals intact"
        );
    }
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
            .with_smp_vcpus(0)
            .try_into_deterministic(),
        Err(LaunchProfileError::SmpVcpuCountZero)
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
            .with_guest_backing_state(GuestBackingStateMode::HostMutableGenesis)
            .try_into_deterministic(),
        Err(LaunchProfileError::GuestBackingStateNotByteIdentical {
            mode: GuestBackingStateMode::HostMutableGenesis,
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
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_guest_core_content(GuestCoreContentMode::GuestInjectedContent)
            .try_into_deterministic(),
        Err(LaunchProfileError::GuestCoreContentRequired {
            mode: GuestCoreContentMode::GuestInjectedContent,
        })
    );
}

#[test]
fn launch_profile_rejects_per_node_icount_shift_mismatch() {
    let profile = default_profile();

    assert_eq!(profile.icount_shift(), 0);
    assert_eq!(profile.smp_vcpus(), 1);
    assert_eq!(profile.rr_switch_quantum(), 4096);
    assert_eq!(
        profile.validate_node_icount_shifts(&[
            NodeIcountShift::new("vm-a", 0),
            NodeIcountShift::new("vm-b", 0),
        ]),
        Ok(())
    );
    let material = scenario_material_for_nodes(
        &profile,
        &[
            NodeIcountShift::new("vm-b", 0),
            NodeIcountShift::new("vm-a", 0),
        ],
    );
    let vm_a_line = material
        .lines()
        .position(|line| line == "node_icount_shift[vm-a]=0")
        .unwrap_or_else(|| panic!("missing vm-a node shift line in {material}"));
    let vm_b_line = material
        .lines()
        .position(|line| line == "node_icount_shift[vm-b]=0")
        .unwrap_or_else(|| panic!("missing vm-b node shift line in {material}"));
    assert!(
        vm_a_line < vm_b_line,
        "node shift material must be sorted by node id"
    );
    assert_eq!(
        profile.scenario_hash_material_for_nodes(&[
            NodeIcountShift::new("vm-a", 0),
            NodeIcountShift::new("vm-b", 1),
        ]),
        Err(LaunchProfileError::IcountShiftMismatch {
            node_id: String::from("vm-b"),
            scenario_shift: 0,
            node_shift: 1,
        })
    );
    assert_eq!(
        profile.scenario_hash_material_for_nodes(&[NodeIcountShift::new("vm-a", 63)]),
        Err(LaunchProfileError::IcountShiftTooLarge { shift: 63 })
    );
    assert_eq!(
        LaunchProfileCandidate::default()
            .with_rr_switch_quantum(0)
            .try_into_deterministic(),
        Err(LaunchProfileError::RrSwitchQuantumZero)
    );
    assert_eq!(
        profile.scenario_hash_material_for_nodes(&[NodeIcountShift::new("", 0)]),
        Err(LaunchProfileError::InvalidFixedText { field: "node_id" })
    );
    assert_eq!(
        profile.scenario_hash_material_for_nodes(&[
            NodeIcountShift::new("vm-a", 0),
            NodeIcountShift::new("vm-a", 0),
        ]),
        Err(LaunchProfileError::DuplicateNodeIcountShift {
            node_id: String::from("vm-a"),
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
        "vcpu_topology=fixed-at-genesis",
        "runtime_cpu_hotplug=forbidden",
        "accelerator=sim,thread=single",
        "accelerator_family=tcg-derived-sim",
        "simulation_mode=on",
        "stock_tcg_crucible_runtime=forbidden",
        "icount_shift=0",
        "rr_switch_quantum=4096",
        "rr_switch_quantum_units=node-icount",
        "rr_vcpu_rotation=ascending-vcpu-id",
        "virtual_time_ns=icount<<shift",
        "per_vcpu_cpu_model=uniform",
        "per_vcpu_tsc_source=node-icount",
        "rtc_epoch_utc=2026-01-01T00:00:00",
        "rtc_clock=vm",
        "guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time",
        "guest_time_epoch=fixed-rtc-epoch",
        "time_control_owner=crucible-qemu-plugin",
        "time_control_acquire=registration-before-first-visible-instruction",
        "idle_warp_under_time_control=suppressed",
        "icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL",
        "realtime_deadline_in_precise_budget=false",
        "machine_reset=deterministic-zeroed-ram-fixed-devices",
        "ram_reset=zeroed-fresh-anonymous-memory",
        "disk_image_mode=copy-on-write-overlay",
        "guest_write_policy=copy-on-write-overlay",
        "guest_backing_state=byte-identical-genesis",
        "guest_on_disk_mutation_policy=forbidden-by-launch-profile",
        "guest_core_content=host-side-only",
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
        "per_vcpu_rng_source=scenario-seed-and-run-seed",
        "per_vcpu_rng_timing_axis=node-icount",
        "secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic",
        "kernel_cmdline=console=ttyS0 reboot=k panic=1 quiet",
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
    let rr_quantum = deterministic(LaunchProfileCandidate::default().with_rr_switch_quantum(8192))
        .scenario_hash_material();
    let smp_vcpus =
        deterministic(LaunchProfileCandidate::default().with_smp_vcpus(2)).scenario_hash_material();
    let machine = deterministic(LaunchProfileCandidate::default().with_machine_type("pc-q35-9.1"))
        .scenario_hash_material();
    let memory = deterministic(LaunchProfileCandidate::default().with_memory_mib(1024))
        .scenario_hash_material();
    let cmdline = deterministic(
        LaunchProfileCandidate::default()
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet net.ifnames=0"),
    )
    .scenario_hash_material();
    let scenario_seed = deterministic(LaunchProfileCandidate::default().with_scenario_seed(0x1234))
        .scenario_hash_material();
    let run_seed = deterministic(LaunchProfileCandidate::default().with_run_seed(0x1234))
        .scenario_hash_material();

    assert_ne!(material, shifted);
    assert_ne!(material, rr_quantum);
    assert_ne!(material, smp_vcpus);
    assert_ne!(material, machine);
    assert_ne!(material, memory);
    assert_ne!(material, cmdline);
    assert_ne!(material, scenario_seed);
    assert_ne!(material, run_seed);
}

#[test]
fn launch_command_builder_adds_plugin_and_hashes_full_argv() {
    let command = default_launch_command();
    let args = command.args();
    let fault_hash = lowercase_hex(&default_plugin_config().fault_node_hash());
    let plugin_argument = format!(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so,simfd=3,slot=0,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=off,coverage=off"
    );

    assert_eq!(command.executable(), default_qemu_binary());
    assert!(args.windows(2).any(|window| {
        window
            == [
                "-kernel",
                "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
            ]
    }));
    assert!(args.windows(2).any(|window| {
        window
            == [
                "-drive",
                "id=crucible-root0,file=crucible-root-overlay.qcow2,backing.driver=qcow2,backing.file.driver=file,backing.file.filename=/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2,if=none,format=qcow2,cache=none,aio=threads,discard=unmap",
            ]
    }));
    assert!(args.windows(2).any(|window| {
        window
            == [
                "-device",
                "virtio-blk-pci,drive=crucible-root0,id=crucible-root-device0",
            ]
    }));
    assert!(
        args.windows(2)
            .any(|window| window[0] == "-plugin" && window[1] == plugin_argument)
    );
    assert!(
        validate_pre_spawn_qemu_launch_args(args).is_ok(),
        "full launch command must remain accepted by the pre-spawn determinism validator"
    );

    let material = command.command_line_hash_material();
    for expected in [
        "crucible.qemu-launch-command.v1",
        "command_line_in_hash=executable-and-argv",
        "executable=/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64",
        "argv[0]=-nodefaults",
        "argv[14]=-accel",
        "argv[15]=sim,thread=single",
        "argv[34]=-blockdev",
        "argv[35]=driver=qcow2,node-name=vmstate,file.driver=file,file.filename=crucible-vmstate.qcow2",
        "argv[36]=-kernel",
        "argv[37]=/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        "argv[42]=-plugin",
        &format!("argv[43]={plugin_argument}"),
    ] {
        assert!(material.contains(expected), "missing {expected}");
    }

    let vm_config = default_vm_config().with_initrd(artifact(
        "initrd",
        "/nix/store/55555555555555555555555555555555-crucible-initrd/initrd",
    ));
    let plugin_config =
        QemuLaunchPluginConfig::new(
            "/nix/store/66666666666666666666666666666666-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
            2,
        )
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_whitebox_setup(validated_whitebox_setup())
        .with_coverage(QemuLaunchPluginSwitch::On);
    let fault_hash = lowercase_hex(&plugin_config.fault_node_hash());
    let expected_plugin_args = format!(
        "simfd=3,slot=2,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=on,coverage=on,whitebox_setup=x86-port-00e7-unclaimed-v1"
    );
    assert_eq!(plugin_config.plugin_args_raw(), expected_plugin_args);
    let command = default_profile()
        .qemu_launch_command(vm_config, default_qemu_binary(), plugin_config)
        .unwrap_or_else(|error| panic!("complete plugin launch command should build: {error}"));
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-plugin"
            && window[1]
                == format!(
                    "/nix/store/66666666666666666666666666666666-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so,{expected_plugin_args}"
                )
    }));
    assert!(command.args().windows(2).any(|window| {
        window
            == [
                "-initrd",
                "/nix/store/55555555555555555555555555555555-crucible-initrd/initrd",
            ]
    }));
    let vm_material = command.vm_launch_hash_material();
    for expected in [
        "crucible.qemu-vm-launch.v1",
        "node_id=vm-a",
        "kernel_hash=",
        "root_image_hash=",
        "root_disk_policy=copy-on-write-overlay",
        "root_overlay_file=crucible-root-overlay.qcow2",
        "root_device_model=virtio-blk-pci",
        "initrd_hash=",
    ] {
        assert!(vm_material.contains(expected), "missing {expected}");
    }
}

#[test]
fn firmware_boot_omits_direct_kernel_and_has_explicit_identity() {
    let command = default_profile()
        .qemu_launch_command(
            firmware_boot_vm_config(),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("firmware boot launch should build: {error}"));

    assert!(!command.args().iter().any(|argument| argument == "-kernel"));
    assert!(!command.args().iter().any(|argument| argument == "-append"));
    assert!(command.args().windows(2).any(|window| {
        window
            == [
                "-bios",
                "/nix/store/77777777777777777777777777777777-crucible-firmware/bios.bin",
            ]
    }));
    assert!(
        command
            .vm_launch_hash_material()
            .contains("kernel=firmware-boot")
    );
}

#[test]
fn firmware_boot_rejects_initrd_without_direct_kernel() {
    let vm = firmware_boot_vm_config().with_initrd(artifact(
        "initrd",
        "/nix/store/55555555555555555555555555555555-crucible-initrd/initrd",
    ));
    let error = default_profile()
        .qemu_launch_command(vm, default_qemu_binary(), default_plugin_config())
        .unwrap_err();

    assert_eq!(error, QemuLaunchCommandError::InitrdWithoutKernel);
}

#[test]
fn launch_command_hash_material_feeds_scenario_identity() {
    let profile = default_profile();
    let command = profile
        .qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("default launch command should build: {error}"));
    let repeated = profile
        .qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("repeated launch command should build: {error}"));
    let changed_slot = profile
        .qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            QemuLaunchPluginConfig::new(
                "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
                1,
            ),
        )
        .unwrap_or_else(|error| panic!("changed-slot launch command should build: {error}"));
    let changed_kernel = profile
        .qemu_launch_command(
            QemuVmLaunchConfig::new(
                "vm-a",
                artifact(
                    "kernel-alt",
                    "/nix/store/77777777777777777777777777777777-crucible-kernel/bzImage",
                ),
                artifact(
                    "root-image",
                    "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
                ),
            ),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("changed-kernel launch command should build: {error}"));
    let changed_qemu = profile
        .qemu_launch_command(
            default_vm_config(),
            "/nix/store/88888888888888888888888888888888-aos-qemu/bin/qemu-system-x86_64",
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("changed-qemu launch command should build: {error}"));
    let changed_path = profile
        .qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            QemuLaunchPluginConfig::new(
                "/nix/store/99999999999999999999999999999999-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
                0,
            ),
        )
        .unwrap_or_else(|error| panic!("changed-path launch command should build: {error}"));

    let material = profile.scenario_hash_material_for_launch_command(&command);
    let repeated_material = profile.scenario_hash_material_for_launch_command(&repeated);
    let changed_slot_material = profile.scenario_hash_material_for_launch_command(&changed_slot);
    let changed_kernel_material =
        profile.scenario_hash_material_for_launch_command(&changed_kernel);
    let changed_qemu_material = profile.scenario_hash_material_for_launch_command(&changed_qemu);
    let changed_path_material = profile.scenario_hash_material_for_launch_command(&changed_path);

    let scenario =
        ScenarioDef::from_canonical_material("crucible.scenario.v1.qemu-launch", &material);
    let repeated_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &repeated_material,
    );
    let changed_slot_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &changed_slot_material,
    );
    let changed_kernel_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &changed_kernel_material,
    );
    let changed_qemu_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &changed_qemu_material,
    );
    let changed_path_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &changed_path_material,
    );

    assert_eq!(scenario, repeated_scenario);
    assert_ne!(scenario.id(), changed_slot_scenario.id());
    assert_ne!(scenario.id(), changed_kernel_scenario.id());
    assert_ne!(scenario.id(), changed_qemu_scenario.id());
    assert_ne!(scenario.id(), changed_path_scenario.id());
}

#[test]
fn launch_command_builder_rejects_invalid_tool_or_plugin_paths() {
    let profile = default_profile();

    assert_eq!(
        QemuLaunchCommandBuilder::new(
            profile.clone(),
            default_vm_config(),
            "",
            default_plugin_config(),
        )
        .build(),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "qemu_executable",
        })
    );
    assert_eq!(
        profile.qemu_launch_command(
            default_vm_config(),
            "qemu-system-x86_64",
            default_plugin_config()
        ),
        Err(QemuLaunchCommandError::InvalidStorePath {
            field: "qemu_executable",
            path: String::from("qemu-system-x86_64"),
        })
    );
    assert_eq!(
        profile.qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            QemuLaunchPluginConfig::new("/nix/store/bad,plugin/lib/libcrucible_qemu_plugin.so", 0,),
        ),
        Err(QemuLaunchCommandError::PluginPathContainsComma)
    );
    assert_eq!(
        profile.qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            QemuLaunchPluginConfig::new("plugin.so", 0),
        ),
        Err(QemuLaunchCommandError::InvalidStorePath {
            field: "plugin_path",
            path: String::from("plugin.so"),
        })
    );
    assert_eq!(
        profile.qemu_launch_command(
            QemuVmLaunchConfig::new(
                "vm-a",
                artifact("kernel", "relative-kernel"),
                artifact(
                    "root-image",
                    "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
                ),
            ),
            default_qemu_binary(),
            default_plugin_config(),
        ),
        Err(QemuLaunchCommandError::InvalidStorePath {
            field: "kernel_path",
            path: String::from("relative-kernel"),
        })
    );
    assert_eq!(
        profile.qemu_launch_command(
            QemuVmLaunchConfig::new(
                "vm-a",
                artifact("kernel", "/nix/store/../tmp/kernel"),
                artifact(
                    "root-image",
                    "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
                ),
            ),
            default_qemu_binary(),
            default_plugin_config(),
        ),
        Err(QemuLaunchCommandError::InvalidStorePath {
            field: "kernel_path",
            path: String::from("/nix/store/../tmp/kernel"),
        })
    );
    assert_eq!(
        profile.qemu_launch_command(
            default_vm_config().with_root_overlay_file_name("../root.qcow2"),
            default_qemu_binary(),
            default_plugin_config(),
        ),
        Err(QemuLaunchCommandError::InvalidOverlayFileName {
            file_name: String::from("../root.qcow2"),
        })
    );
}

fn qemu_args<const N: usize>(parts: [&str; N]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn option_value(args: &[String], option: &str) -> String {
    args.windows(2)
        .find_map(|window| (window[0] == option).then(|| window[1].clone()))
        .unwrap_or_else(|| panic!("missing QEMU option {option}"))
}

fn replace_option_value(args: &mut [String], option: &str, replacement: &str) {
    if let Some(index) = args.iter().position(|arg| arg == option)
        && let Some(value) = args.get_mut(index + 1)
    {
        *value = replacement.to_owned();
    }
}

fn remove_option_pair(args: &mut Vec<String>, option: &str) {
    if let Some(index) = args.iter().position(|arg| arg == option) {
        let end = (index + 2).min(args.len());
        args.drain(index..end);
    }
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
