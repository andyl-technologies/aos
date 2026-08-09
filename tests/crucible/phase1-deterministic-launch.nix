{
  pkgs,
  lib,
}: let
  root = ../..;
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineModelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  engineModelTests = builtins.readFile ../../crates/crucible/src/tests/model_core.rs;
  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  rustFilesUnder = relativeRoot: let
    absoluteRoot = root + "/${relativeRoot}";
    entries = builtins.readDir absoluteRoot;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        relative = "${relativeRoot}/${name}";
      in
        if kind == "regular" && lib.hasSuffix ".rs" name
        then [relative]
        else if kind == "directory"
        then rustFilesUnder relative
        else []
    )
    (builtins.attrNames entries);
  launchRust =
    builtins.concatStringsSep "\n"
    (map (relative: builtins.readFile (root + "/${relative}"))
      (["crates/crucible-qemu/src/launch.rs"] ++ rustFilesUnder "crates/crucible-qemu/src/launch"));
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  # The any-guest contract ([G-2], D-31): the launch layer MUST NOT bake guest
  # entropy-suppression flags into the shipped default cmdline or gate a launch
  # on their presence. These strings must be absent from the launch source.

  forbiddenSourceRequirements = [
    {
      label = "shipped default appends nokaslr";
      needle = "nokaslr";
    }
    {
      label = "shipped default appends norandmaps";
      needle = "norandmaps";
    }
    {
      label = "shipped default forces random.trust_cpu";
      needle = "random.trust_cpu";
    }
    {
      label = "shipped default forces random.trust_bootloader";
      needle = "random.trust_bootloader";
    }
    {
      label = "launch gates on missing KASLR suppression";
      needle = "KernelKaslrNotDisabled";
    }
    {
      label = "launch gates on missing ASLR suppression";
      needle = "UserspaceAslrNotDisabled";
    }
  ];

  sourceRequirements = [
    {
      label = "fixed non-host CPU without hardware entropy";
      needle = "const DEFAULT_CPU_MODEL: &str = \"qemu64,-rdrand,-rdseed\";";
    }
    {
      label = "single-thread TCG-derived sim accelerator";
      needle = "const DEFAULT_ACCEL: &str = \"sim,thread=single\";";
    }
    {
      label = "fixed machine type";
      needle = "const DEFAULT_MACHINE_TYPE: &str = \"pc-q35-9.2\";";
    }
    {
      label = "fixed memory size";
      needle = "const DEFAULT_MEMORY_MIB: u32 = 512;";
    }
    {
      label = "fixed RTC epoch";
      needle = "const DEFAULT_RTC_EPOCH_UTC: &str = \"2026-01-01T00:00:00\";";
    }
    {
      label = "fixed deterministic run seed";
      needle = "const DEFAULT_RUN_SEED: u64 = 0x0010_c001;";
    }
    {
      label = "fixed default scenario seed";
      needle = "const DEFAULT_SCENARIO_SEED: u64 = 0x0010_c001;";
    }
    {
      label = "guest entropy fw_cfg name";
      needle = "const GUEST_ENTROPY_FW_CFG_NAME: &str = \"opt/crucible/seed\";";
    }
    {
      label = "guest entropy deterministic rng id";
      needle = "const GUEST_ENTROPY_RNG_ID: &str = \"crucible-rng0\";";
    }
    {
      label = "guest entropy seed filename";
      needle = "const GUEST_ENTROPY_SEED_FILE_NAME: &str = \"crucible-guest-entropy-seed.bin\";";
    }
    {
      label = "guest entropy seed size";
      needle = "const GUEST_ENTROPY_SEED_BYTES: usize = 32;";
    }
    {
      label = "guest entropy seed file artifact";
      needle = "pub struct GuestEntropySeedFile";
    }
    {
      label = "seed file materialization helper";
      needle = "pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> std::io::Result<PathBuf>";
    }
    {
      label = "stock guest kernel cmdline default (no entropy suppression)";
      needle = "const DEFAULT_KERNEL_CMDLINE: &str = \"console=ttyS0 reboot=k panic=1 quiet\";";
    }
    {
      label = "single vCPU default";
      needle = "smp_vcpus: 1,";
    }
    {
      label = "machine type default";
      needle = "machine_type: DEFAULT_MACHINE_TYPE.to_owned(),";
    }
    {
      label = "memory size default";
      needle = "memory_mib: DEFAULT_MEMORY_MIB,";
    }
    {
      label = "fixed icount default";
      needle = "IcountShiftSetting::Fixed(0),";
    }
    {
      label = "fixed RR switch quantum default";
      needle = "rr_switch_quantum: DEFAULT_RR_SWITCH_QUANTUM,";
    }
    {
      label = "VM RTC clock default";
      needle = "rtc_clock: \"vm\".to_owned(),";
    }
    {
      label = "deterministic machine reset default";
      needle = "machine_reset: MachineResetMode::Deterministic,";
    }
    {
      label = "copy-on-write disk default";
      needle = "disk_image_mode: DiskImageMode::CopyOnWriteOverlay,";
    }
    {
      label = "byte-identical genesis backing default";
      needle = "guest_backing_state: GuestBackingStateMode::ByteIdenticalGenesis,";
    }
    {
      label = "host-side guest core content default";
      needle = "guest_core_content: GuestCoreContentMode::HostSideOnly,";
    }
    {
      label = "no host interactive input default";
      needle = "input_policy: InputPolicy::NoInteractiveInput,";
    }
    {
      label = "host CPU model rejection";
      needle = "if base == \"host\"";
    }
    {
      label = "RDRAND rejection";
      needle = "reject_enabled_entropy_feature(&lower, \"rdrand\")?";
    }
    {
      label = "RDSEED rejection";
      needle = "reject_enabled_entropy_feature(&lower, \"rdseed\")?";
    }
    {
      label = "zero-vCPU rejection";
      needle = "if self.smp_vcpus == 0";
    }
    {
      label = "machine type validation";
      needle = "validate_fixed_text(\"machine_type\", &self.machine_type)?;";
    }
    {
      label = "zero memory rejection";
      needle = "if self.memory_mib == 0";
    }
    {
      label = "adaptive icount rejection";
      needle = "IcountShiftSetting::Auto => return Err(LaunchProfileError::IcountShiftAuto),";
    }
    {
      label = "host RTC rejection";
      needle = "if self.rtc_clock != \"vm\"";
    }
    {
      label = "run seed scenario seed unification";
      needle = "RunSeedDiffersFromScenarioSeed";
    }
    {
      label = "guest-injected core content rejection";
      needle = "GuestCoreContentRequired";
    }
    {
      label = "host-mutable genesis backing rejection";
      needle = "GuestBackingStateNotByteIdentical";
    }
    {
      label = "scenario seed setter updates run seed";
      needle = "self.run_seed = scenario_seed;";
    }
    {
      label = "run seed setter updates scenario seed";
      needle = "self.scenario_seed = run_seed;";
    }
    {
      label = "nodefaults launch flag";
      needle = "\"-nodefaults\".to_owned(),";
    }
    {
      label = "no user config launch flag";
      needle = "\"-no-user-config\".to_owned(),";
    }
    {
      label = "machine launch flag";
      needle = "\"-machine\".to_owned(),";
    }
    {
      label = "memory launch flag";
      needle = "\"-m\".to_owned(),";
    }
    {
      label = "fixed icount launch flag";
      needle = "\"shift={},sleep=off,align=off,rr_switch_quantum={}\",";
    }
    {
      label = "VM-clock RTC launch flag";
      needle = "format!(\"base={DEFAULT_RTC_EPOCH_UTC},clock=vm\"),";
    }
    {
      label = "QEMU deterministic seed launch flag";
      needle = "\"-seed\".to_owned(),";
    }
    {
      label = "QEMU deterministic seed argument";
      needle = "self.run_seed.to_string(),";
    }
    {
      label = "guest entropy fw_cfg launch flag";
      needle = "\"-fw_cfg\".to_owned(),";
    }
    {
      label = "guest entropy fw_cfg seed argument";
      needle = "seed_file.file_name()";
    }
    {
      label = "guest entropy seed file accessor";
      needle = "pub fn guest_entropy_seed_file(&self) -> GuestEntropySeedFile";
    }
    {
      label = "deterministic virtio rng object";
      needle = "format!(\"rng-builtin,id={GUEST_ENTROPY_RNG_ID}\")";
    }
    {
      label = "deterministic virtio rng device";
      needle = "format!(\"virtio-rng-pci,rng={GUEST_ENTROPY_RNG_ID}\")";
    }
    {
      label = "launch hash version";
      needle = "\"crucible.launch.v1\".to_owned(),";
    }
    {
      label = "CPU in hash material";
      needle = "format!(\"cpu_model={}\", self.cpu_model),";
    }
    {
      label = "machine type in hash material";
      needle = "format!(\"machine_type={}\", self.machine_type),";
    }
    {
      label = "memory size in hash material";
      needle = "format!(\"memory_mib={}\", self.memory_mib),";
    }
    {
      label = "vCPU count in hash material";
      needle = "format!(\"smp_vcpus={}\", self.smp_vcpus),";
    }
    {
      label = "accelerator in hash material";
      needle = "format!(\"accelerator={DEFAULT_ACCEL}\"),";
    }
    {
      label = "icount shift in hash material";
      needle = "format!(\"icount_shift={}\", self.icount_shift),";
    }
    {
      label = "RR switch quantum in hash material";
      needle = "format!(\"rr_switch_quantum={}\", self.rr_switch_quantum),";
    }
    {
      label = "RR switch quantum units in hash material";
      needle = "\"rr_switch_quantum_units=node-icount\".to_owned(),";
    }
    {
      label = "RR vCPU rotation in hash material";
      needle = "\"rr_vcpu_rotation=ascending-vcpu-id\".to_owned(),";
    }
    {
      label = "icount-derived time in hash material";
      needle = "\"virtual_time_ns=icount<<shift\".to_owned(),";
    }
    {
      label = "guest-visible time source policy in hash material";
      needle = "\"guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time\".to_owned(),";
    }
    {
      label = "fixed guest time epoch in hash material";
      needle = "\"guest_time_epoch=fixed-rtc-epoch\".to_owned(),";
    }
    {
      label = "time-control owner in hash material";
      needle = "\"time_control_owner=crucible-qemu-plugin\".to_owned(),";
    }
    {
      label = "time-control acquisition order in hash material";
      needle = "\"time_control_acquire=registration-before-first-visible-instruction\".to_owned(),";
    }
    {
      label = "idle warp suppression in hash material";
      needle = "\"idle_warp_under_time_control=suppressed\".to_owned(),";
    }
    {
      label = "virtual-only icount budget in hash material";
      needle = "\"icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL\".to_owned(),";
    }
    {
      label = "realtime deadline ban in hash material";
      needle = "\"realtime_deadline_in_precise_budget=false\".to_owned(),";
    }
    {
      label = "RAM reset in hash material";
      needle = "\"ram_reset=zeroed-fresh-anonymous-memory\".to_owned(),";
    }
    {
      label = "CoW guest write policy in hash material";
      needle = "format!(\"guest_write_policy={}\", self.disk_image_mode),";
    }
    {
      label = "byte-identical genesis backing in hash material";
      needle = "format!(\"guest_backing_state={}\", self.guest_backing_state),";
    }
    {
      label = "guest disk non-mutation in hash material";
      needle = "\"guest_on_disk_mutation_policy=forbidden-by-launch-profile\".to_owned(),";
    }
    {
      label = "host-side guest content policy in hash material";
      needle = "format!(\"guest_core_content={}\", self.guest_core_content),";
    }
    {
      label = "scenario seed in hash material";
      needle = "format!(\"scenario_seed={}\", self.scenario_seed),";
    }
    {
      label = "QEMU run seed in hash material";
      needle = "format!(\"qemu_run_seed={}\", self.run_seed),";
    }
    {
      label = "QEMU run seed entropy scope in hash material";
      needle = "\"qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin\".to_owned(),";
    }
    {
      label = "guest entropy fw_cfg name in hash material";
      needle = "format!(\"guest_entropy_fw_cfg_name={GUEST_ENTROPY_FW_CFG_NAME}\"),";
    }
    {
      label = "guest entropy seed source in hash material";
      needle = "\"guest_entropy_seed_source=scenario-seed\".to_owned(),";
    }
    {
      label = "guest entropy seed in hash material";
      needle = "format!(\n                \"guest_entropy_seed_hex={}\",";
    }
    {
      label = "guest entropy host source ban in hash material";
      needle = "\"guest_entropy_host_sources=disabled\".to_owned(),";
    }
    {
      label = "checked virtual time conversion";
      needle = ".checked_mul(scale)";
    }
    {
      label = "guest entropy seed derivation";
      needle = "GuestEntropySeed::from_scenario_seed(self.scenario_seed)";
    }
    {
      label = "guest entropy splitmix derivation";
      needle = "fn splitmix64(mut value: u64) -> u64";
    }
  ];

  testRequirements = [
    {
      label = "canonical arguments test";
      needle = "default_launch_profile_pins_contract_a_arguments";
    }
    {
      label = "host CPU entropy feature rejection (host-side seal, not guest cmdline)";
      needle = "fn pre_spawn_launch_validation_rejects_host_cpu_timing_and_entropy()";
    }
    {
      label = "host RDRAND enablement rejected at pre-spawn validation";
      needle = "QemuPreSpawnLaunchValidationError::CpuEntropyFeatureEnabled { feature: \"rdrand\" }";
    }
    {
      label = "host entropy and timing rejection test";
      needle = "launch_profile_rejects_host_entropy_and_host_timing";
    }
    {
      label = "mutating and interactive state rejection test";
      needle = "launch_profile_rejects_mutating_or_interactive_state";
    }
    {
      label = "guest non-modification test";
      needle = "launch_profile_enforces_guest_non_modification";
    }
    {
      label = "hash material coverage test";
      needle = "launch_hash_material_records_every_determinism_field";
    }
    {
      label = "virtual-time mapping test";
      needle = "virtual_time_uses_checked_icount_shift_mapping";
    }
    {
      label = "CPU argument assertion";
      needle = "qemu64,-rdrand,-rdseed";
    }
    {
      label = "TCG-derived sim accelerator assertion";
      needle = "sim,thread=single";
    }
    {
      label = "stock TCG runtime rejection assertion";
      needle = "QemuPreSpawnLaunchValidationError::NonSimAccelerator";
    }
    {
      label = "machine type assertion";
      needle = "pc-q35-9.2";
    }
    {
      label = "memory size assertion";
      needle = "512M";
    }
    {
      label = "deterministic seed assertion";
      needle = "[\"-seed\", \"1097729\"]";
    }
    {
      label = "fw_cfg seed assertion";
      needle = "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin";
    }
    {
      label = "fw_cfg seed file binding assertion";
      needle = "launch_profile_binds_fw_cfg_file_to_guest_entropy_seed";
    }
    {
      label = "seed file write assertion";
      needle = "seed_file.write_to_dir(&dir)";
    }
    {
      label = "rng-builtin assertion";
      needle = "[\"-object\", \"rng-builtin,id=crucible-rng0\"]";
    }
    {
      label = "virtio-rng assertion";
      needle = "[\"-device\", \"virtio-rng-pci,rng=crucible-rng0\"]";
    }
    {
      label = "any-guest stock cmdline pass-through test";
      needle = "fn launch_profile_accepts_any_guest_kernel_cmdline()";
    }
    {
      label = "guest cmdline passed through unchanged";
      needle = "the launch profile passes the guest cmdline through unchanged";
    }
    {
      label = "any cmdline validates with host-side seals intact";
      needle = "any guest cmdline must pass pre-spawn validation with host-side seals intact";
    }
    {
      label = "guest-set suppression flags are equally legal (not required)";
      needle = "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off";
    }
    {
      label = "guest-set opt-in randomization is legal";
      needle = "console=ttyS0 reboot=k panic=1 quiet kaslr random.trust_cpu=on";
    }
    {
      label = "split seed rejection assertion";
      needle = "LaunchProfileError::RunSeedDiffersFromScenarioSeed";
    }
    {
      label = "zero memory rejection assertion";
      needle = "LaunchProfileError::MemorySizeZero";
    }
    {
      label = "adaptive icount rejection assertion";
      needle = "IcountShiftSetting::Auto";
    }
    {
      label = "virtual-time overflow assertion";
      needle = "LaunchProfileError::VirtualTimeOverflow";
    }
    {
      label = "run seed hash material assertion";
      needle = "qemu_run_seed=1097729";
    }
    {
      label = "guest CoW write policy assertion";
      needle = "guest_write_policy=copy-on-write-overlay";
    }
    {
      label = "guest byte-identical genesis assertion";
      needle = "guest_backing_state=byte-identical-genesis";
    }
    {
      label = "guest disk non-mutation assertion";
      needle = "guest_on_disk_mutation_policy=forbidden-by-launch-profile";
    }
    {
      label = "host-side guest core content assertion";
      needle = "guest_core_content=host-side-only";
    }
    {
      label = "host-mutable genesis rejection assertion";
      needle = "GuestBackingStateMode::HostMutableGenesis";
    }
    {
      label = "guest-injected content rejection assertion";
      needle = "GuestCoreContentMode::GuestInjectedContent";
    }
    {
      label = "scenario seed hash material assertion";
      needle = "scenario_seed=1097729";
    }
    {
      label = "guest entropy seed hash material assertion";
      needle = "guest_entropy_seed_hex=";
    }
    {
      label = "guest entropy source assertion";
      needle = "guest_entropy_seed_source=scenario-seed";
    }
    {
      label = "guest entropy host-source ban assertion";
      needle = "guest_entropy_host_sources=disabled";
    }
    {
      label = "guest entropy seed derivation test";
      needle = "guest_entropy_seed_is_scenario_seed_derived";
    }
    {
      label = "run seed drift assertion";
      needle = "with_run_seed(0x1234)";
    }
    {
      label = "scenario seed drift assertion";
      needle = "with_scenario_seed(0x1234)";
    }
    {
      label = "launch material scenario identity test";
      needle = "launch_material_feeds_scenario_identity";
    }
    {
      label = "launch material enters ScenarioDef identity";
      needle = "ScenarioDef::from_canonical_material";
    }
    {
      label = "QEMU launch scenario domain";
      needle = "crucible.scenario.v1.qemu-launch";
    }
  ];

  qemuCargoRequirements = [
    {
      label = "production engine dependency";
      needle = "crucible = { path = \"../crucible\" }";
    }
    {
      label = "explicit deterministic test-support feature";
      needle = "test-support = [\"crucible/test-double\"]";
    }
  ];

  engineModelRequirements = [
    {
      label = "generic content hash constructor";
      needle = "pub fn from_canonical_material(domain: &str, material: &str) -> Self";
    }
    {
      label = "scenario definition material constructor";
      needle = "pub fn from_canonical_material(domain: &str, material: &str) -> Self";
    }
  ];

  engineModelCanonicalRequirements = [
    {
      label = "stable material hasher";
      needle = "let mut hasher = MaterialHasher::new();";
    }
    {
      label = "content-hash version tag";
      needle = "crucible.content-hash.v1";
    }
    {
      label = "domain enters content hash";
      needle = "hasher.write_bytes(domain.as_bytes());";
    }
    {
      label = "material enters content hash";
      needle = "hasher.write_bytes(material.as_bytes());";
    }
  ];

  engineModelTestRequirements = [
    {
      label = "generic scenario identity stability test";
      needle = "canonical_material_builds_stable_scenario_identity";
    }
    {
      label = "generic scenario identity drift assertion";
      needle = "assert_ne!(first.id(), changed_material.id());";
    }
  ];

  failures =
    failuresFor "crates/crucible/src/model.rs" engineModel engineModelRequirements
    ++ failuresFor "crates/crucible/src/model/canonical.rs" engineModelCanonical engineModelCanonicalRequirements
    ++ failuresFor "crates/crucible/src/tests/model_core.rs" engineModelTests engineModelTestRequirements
    ++ failuresFor "crates/crucible-qemu/Cargo.toml" qemuCargo qemuCargoRequirements
    ++ failuresFor "crates/crucible-qemu/src/launch*.rs" launchRust sourceRequirements
    ++ forbiddenFor "crates/crucible-qemu/src/launch*.rs" launchRust forbiddenSourceRequirements
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest testRequirements;
in
  if failures != []
  then throw "crucible phase1 deterministic launch check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-deterministic-launch";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.deterministicLaunch
            gate=gate:layer0-determinism
            tasks=T-DET-1
            rust_test=crucible-qemu::deterministic_launch,crucible::canonical_material_builds_stable_scenario_identity
            scenario_hash=crucible.scenario.v1.qemu-launch
            cpu=qemu64,-rdrand,-rdseed
            machine=pc-q35-9.2
            memory=512M
            accelerator=sim,thread=single
            accelerator_family=tcg-derived-sim
            simulation_mode=on
            stock_tcg_crucible_runtime=forbidden
            smp=1
            smp_vcpus=1
            icount=shift=0,sleep=off,align=off,rr_switch_quantum=4096
            rr_switch_quantum=4096
            rr_switch_quantum_units=node-icount
            rr_vcpu_rotation=ascending-vcpu-id
            rtc=base=2026-01-01T00:00:00,clock=vm
            timers=virtual-clock-driven
            interrupt_timing=icount-tb-boundaries
            qemu_seed=1097729
            qemu_seed_controls=guest-random,glib-global-prng,rng-builtin
            scenario_seed=1097729
            guest_entropy_fw_cfg=opt/crucible/seed
            guest_entropy_seed_source=scenario-seed
            guest_entropy_rng_object=rng-builtin,id=crucible-rng0
            guest_entropy_rng_device=virtio-rng-pci,rng=crucible-rng0
            guest_entropy_host_sources=disabled
            virtual_time_ns=icount<<shift
            tsc_source=icount
            guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time
            guest_time_epoch=fixed-rtc-epoch
            time_control_owner=crucible-qemu-plugin
            time_control_acquire=registration-before-first-visible-instruction
            idle_warp_under_time_control=suppressed
            icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL
            realtime_deadline_in_precise_budget=false
            machine_reset=deterministic-zeroed-ram-fixed-devices
            ram_reset=zeroed-fresh-anonymous-memory
            guest_write_policy=copy-on-write-overlay
            guest_backing_state=byte-identical-genesis
            guest_on_disk_mutation_policy=forbidden-by-launch-profile
            guest_core_content=host-side-only
            input_policy=no-interactive-input
            RESULT
          '';
        }
      ];
    }
