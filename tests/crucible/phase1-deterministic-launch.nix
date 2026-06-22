{
  pkgs,
  lib,
}: let
  engineModel = builtins.readFile ../../crates/crucible/src/model.rs;
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  launchRust = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  launchTest = builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  sourceRequirements = [
    {
      label = "fixed non-host CPU without hardware entropy";
      needle = "const DEFAULT_CPU_MODEL: &str = \"qemu64,-rdrand,-rdseed\";";
    }
    {
      label = "single-thread TCG accelerator";
      needle = "const DEFAULT_ACCEL: &str = \"tcg,thread=single\";";
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
      label = "guest refuses CPU randomness";
      needle = "random.trust_cpu=off";
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
      label = "non-single-vCPU rejection";
      needle = "if self.smp_vcpus != 1";
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
      label = "host CPU random trust rejection";
      needle = "random.trust_cpu=on";
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
      needle = "format!(\"shift={},sleep=off,align=off\", self.icount_shift),";
    }
    {
      label = "VM-clock RTC launch flag";
      needle = "format!(\"base={},clock=vm\", self.rtc_epoch_utc),";
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
      label = "single vCPU in hash material";
      needle = "\"smp_vcpus=1\".to_owned(),";
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
      label = "icount-derived time in hash material";
      needle = "\"virtual_time_ns=icount<<shift\".to_owned(),";
    }
    {
      label = "RAM reset in hash material";
      needle = "\"ram_reset=zeroed-fresh-anonymous-memory\".to_owned(),";
    }
    {
      label = "QEMU run seed in hash material";
      needle = "format!(\"qemu_run_seed={}\", self.run_seed),";
    }
    {
      label = "QEMU run seed entropy scope in hash material";
      needle = "\"qemu_run_seed_controls=guest-random,glib-global-prng\".to_owned(),";
    }
    {
      label = "checked virtual time conversion";
      needle = ".checked_mul(scale)";
    }
  ];

  testRequirements = [
    {
      label = "canonical arguments test";
      needle = "default_launch_profile_pins_contract_a_arguments";
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
      label = "TCG accelerator assertion";
      needle = "tcg,thread=single";
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
      label = "run seed drift assertion";
      needle = "with_run_seed(0x1234)";
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
      label = "dev-only engine dependency for identity regression";
      needle = "crucible = { path = \"../crucible\" }";
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

  engineLibRequirements = [
    {
      label = "generic scenario identity stability test";
      needle = "canonical_material_builds_stable_scenario_identity";
    }
    {
      label = "generic scenario identity drift assertion";
      needle = "assert_ne!(first.id, changed_material.id);";
    }
  ];

  failures =
    failuresFor "crates/crucible/src/model.rs" engineModel engineModelRequirements
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib engineLibRequirements
    ++ failuresFor "crates/crucible-qemu/Cargo.toml" qemuCargo qemuCargoRequirements
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" launchRust sourceRequirements
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest testRequirements
    ;
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
            accelerator=tcg,thread=single
            smp=1
            icount=shift=0,sleep=off,align=off
            rtc=base=2026-01-01T00:00:00,clock=vm
            qemu_seed=1097729
            qemu_seed_controls=guest-random,glib-global-prng
            virtual_time_ns=icount<<shift
            RESULT
          '';
        }
      ];
    }
