{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLaunchBuilder",
  taskIds ? ["T-QEMU-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  faultCapabilityLib = builtins.readFile ../../crates/crucible-qemu/src/fault_capability.rs;
  launchLib =
    builtins.readFile ../../crates/crucible-qemu/src/launch.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/error.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/helpers.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/plugin_config.rs;
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/fingerprint_options.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-1 completion note names launch-command builder";
        needle = "typed `crucible-qemu` launch-command builder";
      }
      {
        label = "T-QEMU-1 completion note preserves fd-passing follow-up";
        needle = "Child ownership/fd-passing remains tracked by";
      }
      {
        label = "T-QEMU-1 completion note requires store-resolved artifacts";
        needle = "requires content-addressed VM launch artifacts resolved";
      }
      {
        label = "T-QEMU-1 completion note names fixed child fds";
        needle = "`simfd=3`, `shmemfd=4`, `wakefd=5`";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "launch artifact export";
        needle = "QemuLaunchArtifact";
      }
      {
        label = "launch command export";
        needle = "QemuLaunchCommand";
      }
      {
        label = "launch command builder export";
        needle = "QemuLaunchCommandBuilder";
      }
      {
        label = "plugin config export";
        needle = "QemuLaunchPluginConfig";
      }
      {
        label = "launch command error export";
        needle = "QemuLaunchCommandError";
      }
      {
        label = "VM launch config export";
        needle = "QemuVmLaunchConfig";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" launchLib [
      {
        label = "launch command type";
        needle = "pub struct QemuLaunchCommand";
      }
      {
        label = "launch command builder type";
        needle = "pub struct QemuLaunchCommandBuilder";
      }
      {
        label = "builder build API";
        needle = "pub fn build(self) -> Result<QemuLaunchCommand, QemuLaunchCommandError>";
      }
      {
        label = "builder requires VM launch config";
        needle = "vm: QemuVmLaunchConfig,";
      }
      {
        label = "builder requires explicit executable";
        needle = "executable: impl Into<String>,";
      }
      {
        label = "builder requires explicit fault capabilities";
        needle = "fault_capability_requirement: crate::QemuFaultCapabilityRequirement,";
      }
      {
        label = "production launch rejects non-World requirements";
        needle = "!fault_capability_requirement.is_world_bound()";
      }
      {
        label = "production launch requires an exact manifest";
        needle = "required_target.exact_manifest().is_none()";
      }
      {
        label = "launch verifies World node identity";
        needle = "QemuLaunchCommandError::FaultCapabilityNodeMismatch";
      }
      {
        label = "launch verifies executable architecture";
        needle = "QemuLaunchCommandError::FaultCapabilityArchitectureMismatch";
      }
      {
        label = "launch verifies realized CPU model";
        needle = "QemuLaunchCommandError::FaultCapabilityCpuModelMismatch";
      }
      {
        label = "fixed plugin control fd";
        needle = "const FIXED_PLUGIN_SIM_FD: i32 = 3;";
      }
      {
        label = "fixed plugin shmem fd";
        needle = "const FIXED_PLUGIN_SHMEM_FD: i32 = 4;";
      }
      {
        label = "fixed plugin wake fd";
        needle = "const FIXED_PLUGIN_WAKE_FD: i32 = 5;";
      }
      {
        label = "launch artifact type";
        needle = "pub struct QemuLaunchArtifact";
      }
      {
        label = "VM launch config type";
        needle = "pub struct QemuVmLaunchConfig";
      }
      {
        label = "VM launch material version";
        needle = "\"crucible.qemu-vm-launch.v1\".to_owned(),";
      }
      {
        label = "kernel hash material";
        needle = "\"kernel_hash={}\",";
      }
      {
        label = "root image hash material";
        needle = "root_image_hash={}";
      }
      {
        label = "CoW disk policy material";
        needle = "lines.push(\"root_disk_policy=copy-on-write-overlay\".to_owned());";
      }
      {
        label = "kernel argv";
        needle = "\"-kernel\".to_owned(),";
      }
      {
        label = "CoW drive argv";
        needle = "\"-drive\".to_owned(),";
      }
      {
        label = "typed root backing driver appears in drive argv";
        needle = "self.root_image_format.qemu_driver()";
      }
      {
        label = "raw root backing format";
        needle = "QemuRootImageFormat::Raw";
      }
      {
        label = "root backing file driver appears in drive argv";
        needle = "backing.file.driver=file";
      }
      {
        label = "root overlay backing file path syntax";
        needle = "backing.file.filename={}";
      }
      {
        label = "virtio-blk device argv";
        needle = "\"virtio-blk-pci,drive={ROOT_DRIVE_ID},id={ROOT_DEVICE_ID}\"";
      }
      {
        label = "store-path validator";
        needle = "fn validate_store_path";
      }
      {
        label = "AOS store path prefix";
        needle = "path.starts_with(\"/nix/store/\")";
      }
      {
        label = "store path traversal rejection";
        needle = "!path.contains(\"/../\")";
      }
      {
        label = "store path comma rejection";
        needle = "!path.contains(',')";
      }
      {
        label = "overlay name validator";
        needle = "fn validate_overlay_file_name";
      }
      {
        label = "invalid store path error";
        needle = "InvalidStorePath";
      }
      {
        label = "plugin config type";
        needle = "pub struct QemuLaunchPluginConfig";
      }
      {
        label = "plugin simfd key";
        needle = "const PLUGIN_ARG_SIMFD: &str = \"simfd\";";
      }
      {
        label = "plugin slot key";
        needle = "const PLUGIN_ARG_SLOT: &str = \"slot\";";
      }
      {
        label = "plugin inherited shmem key";
        needle = "const PLUGIN_ARG_SHMEMFD: &str = \"shmemfd\";";
      }
      {
        label = "plugin inherited wake key";
        needle = "const PLUGIN_ARG_WAKEFD: &str = \"wakefd\";";
      }
      {
        label = "plugin fixed simfd argument";
        needle = "format!(\"{PLUGIN_ARG_SIMFD}={FIXED_PLUGIN_SIM_FD}\"),";
      }
      {
        label = "plugin fixed shmemfd argument";
        needle = "format!(\"{PLUGIN_ARG_SHMEMFD}={FIXED_PLUGIN_SHMEM_FD}\"),";
      }
      {
        label = "plugin fixed wakefd argument";
        needle = "format!(\"{PLUGIN_ARG_WAKEFD}={FIXED_PLUGIN_WAKE_FD}\"),";
      }
      {
        label = "plugin argument renderer";
        needle = "pub fn qemu_plugin_argument(&self) -> String";
      }
      {
        label = "plugin argv appended";
        needle = "\"-plugin\".to_owned(),";
      }
      {
        label = "plugin argv value appended";
        needle = "self.plugin.qemu_plugin_argument()";
      }
      {
        label = "final argv pre-spawn validation";
        needle = "validate_pre_spawn_qemu_launch_args(&args)";
      }
      {
        label = "command-line hash version";
        needle = "\"crucible.qemu-launch-command.v1\".to_owned()";
      }
      {
        label = "argv hash material";
        needle = "format!(\"argv[{index}]={argument}\")";
      }
      {
        label = "profile command material join";
        needle = "pub fn scenario_hash_material_for_launch_command(&self, command: &QemuLaunchCommand) -> String";
      }
      {
        label = "command material folded into scenario material";
        needle = "command.command_line_hash_material()";
      }
      {
        label = "VM material folded into scenario material";
        needle = "command.vm_launch_hash_material()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/fault_capability.rs" faultCapabilityLib [
      {
        label = "World-bound capability constructor";
        needle = "pub fn current_v1_for_node(";
      }
      {
        label = "exact World register manifest binding";
        needle = "target.exact_manifest = Some(manifest.clone());";
      }
      {
        label = "World node identity binding";
        needle = "crate::qemu_fault_target_hash(node.node.as_str()),";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/fault_capability.rs" faultCapabilityLib [
      {
        label = "public arbitrary exact capability constructor";
        needle = "pub fn exact(rows:";
      }
      {
        label = "public unbound current capability constructor";
        needle = "pub fn current_v1(";
      }
      {
        label = "public ABI-only capability constructor";
        needle = "pub fn abi_boundary_v1(";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/launch.rs" launchLib [
      {
        label = "post-construction fault capability override";
        needle = "with_fault_capability_requirement";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "launch command builder test";
        needle = "launch_command_builder_adds_plugin_and_hashes_full_argv";
      }
      {
        label = "launch command scenario identity test";
        needle = "launch_command_hash_material_feeds_scenario_identity";
      }
      {
        label = "launch command invalid input test";
        needle = "launch_command_builder_rejects_invalid_tool_or_plugin_paths";
      }
      {
        label = "default plugin argv assertion";
        needle = "simfd=3,slot=0,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=off,coverage=off";
      }
      {
        label = "fixed fd plugin argv assertion";
        needle = "simfd=3,slot=2,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=on,coverage=on";
      }
      {
        label = "kernel argv assertion";
        needle = "\"-kernel\",";
      }
      {
        label = "CoW drive argv assertion";
        needle = "backing.file.filename=/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2";
      }
      {
        label = "virtio-blk argv assertion";
        needle = "virtio-blk-pci,drive=crucible-root0";
      }
      {
        label = "store path rejection assertion";
        needle = "QemuLaunchCommandError::InvalidStorePath";
      }
      {
        label = "store traversal rejection assertion";
        needle = "/nix/store/../tmp/kernel";
      }
      {
        label = "overlay path rejection assertion";
        needle = "QemuLaunchCommandError::InvalidOverlayFileName";
      }
      {
        label = "final argv validator assertion";
        needle = "validate_pre_spawn_qemu_launch_args(args).is_ok()";
      }
      {
        label = "scenario identity includes command material";
        needle = "scenario_hash_material_for_launch_command";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes QEMU launch builder check";
        needle = "qemuLaunchBuilder = import ./phase2-qemu-launch-builder.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu launch-builder check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-launch-builder";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-qemu-launch-builder";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-launch-builder-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            check_scope=task-level
            related_gates=gate:content-address,gate:single-vm-fingerprint,gate:layer0-determinism
            rust_test=crucible-qemu::deterministic_launch
            launch_builder=typed
            qemu_binary=AOS-store-path-required
            plugin_path=AOS-store-path-required
            vm_artifacts=content-addressed-kernel-root-image-optional-initrd
            root_disk=copy-on-write-overlay
            plugin_arg=simfd=3,slot=0,shmemfd=4,wakefd=5,whitebox=off,coverage=off
            fixed_child_fds=simfd:3,shmemfd:4,wakefd:5
            command_line_hash=executable-and-argv
            vm_launch_hash=world-derived-artifacts
            pre_spawn_validation=true
            child_spawn_deferred_to=T-QEMU-3,T-QEMU-7
            multi_vcpu_extension=checks.crucible.phase2.qemuMultiVcpuLaunch
            RESULT
          '';
        }
      ];
    }
