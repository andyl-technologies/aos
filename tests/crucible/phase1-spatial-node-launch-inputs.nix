{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialNodeLaunchInputs",
  taskIds ? ["T-SPAT-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-5 completion names node launch test";
        needle = "`world_node_launch_inputs_are_portable_and_identity_bearing`";
      }
      {
        label = "T-SPAT-5 completion names gate";
        needle = "`checks.crucible.phase1.spatialNodeLaunchInputs`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "VM architecture enum";
        needle = "pub enum VmArchitecture";
      }
      {
        label = "x86_64 architecture variant";
        needle = "X86_64";
      }
      {
        label = "aarch64 architecture variant";
        needle = "Aarch64";
      }
      {
        label = "node architecture field";
        needle = "pub arch: VmArchitecture";
      }
      {
        label = "node memory field";
        needle = "pub memory_mib: u32";
      }
      {
        label = "node command line field";
        needle = "pub cmdline: String";
      }
      {
        label = "default architecture";
        needle = "pub const DEFAULT_ARCH";
      }
      {
        label = "default memory size";
        needle = "pub const DEFAULT_MEMORY_MIB";
      }
      {
        label = "architecture builder";
        needle = "pub fn arch(mut self, arch: VmArchitecture) -> Self";
      }
      {
        label = "memory builder";
        needle = "pub fn memory_mib(mut self, memory_mib: u32) -> Self";
      }
      {
        label = "command line builder";
        needle = "pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self";
      }
      {
        label = "memory validation error";
        needle = "WorldNodeMemoryMibZero";
      }
      {
        label = "minimum memory validation";
        needle = "if node.memory_mib < MIN_WORLD_MEMORY_MIB";
      }
      {
        label = "architecture material";
        needle = "arch={}";
      }
      {
        label = "memory material";
        needle = "memory_mib={}";
      }
      {
        label = "command line length material";
        needle = "cmdline_len={}";
      }
      {
        label = "command line material";
        needle = "cmdline={}";
      }
      {
        label = "TOML architecture field";
        needle = "arch: VmArchitectureToml";
      }
      {
        label = "TOML memory field";
        needle = "memory_mib: u32";
      }
      {
        label = "TOML command line field";
        needle = "cmdline: String";
      }
      {
        label = "binary architecture writer";
        needle = "write_vm_arch_binary(node.arch, writer)";
      }
      {
        label = "binary memory writer";
        needle = "writer.write_u32(node.memory_mib)";
      }
      {
        label = "binary command line writer";
        needle = "writer.write_string(&node.cmdline)";
      }
      {
        label = "content-addressed blob ref";
        needle = "ContentAddressedBlobRef";
      }
      {
        label = "host path rejection hook";
        needle = "validate_no_host_path_image_refs_in_toml";
      }
      {
        label = "non-content-addressed image error";
        needle = "ScenarioImageReferenceNotContentAddressed";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "VM architecture re-export";
        needle = "VmArchitecture";
      }
      {
        label = "focused node launch test";
        needle = "fn world_node_launch_inputs_are_portable_and_identity_bearing()";
      }
      {
        label = "test uses NodeTemplate";
        needle = "NodeTemplate::fixed_icount";
      }
      {
        label = "test uses aarch64 launch input";
        needle = "VmArchitecture::Aarch64";
      }
      {
        label = "test checks TOML round trip";
        needle = "World::from_canonical_toml(&toml)";
      }
      {
        label = "test checks binary round trip";
        needle = "World::from_compact_binary(&base_world.to_compact_binary())";
      }
      {
        label = "test rejects host path image refs";
        needle = "ScenarioImageReferenceNotContentAddressed";
      }
      {
        label = "test rejects host path value";
        needle = "/nix/store/kernel";
      }
      {
        label = "test checks launch input identity changes";
        needle = "assert_identity_changes";
      }
      {
        label = "test checks memory validation";
        needle = "WorldNodeMemoryMibZero";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial node launch inputs check";
        needle = "spatialNodeLaunchInputs = import ./phase1-spatial-node-launch-inputs.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial node launch inputs check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-node-launch-inputs";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
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
          name = "run-spatial-node-launch-inputs";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-node-launch-inputs-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              world_node_launch_inputs_are_portable_and_identity_bearing \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
                        set -eu
                        mkdir -p "$out"
                        cat > "$out/result" <<'RESULT'
            status=pass
            component=spatial-node-launch-inputs
            RESULT
          '';
        }
      ];
    }
