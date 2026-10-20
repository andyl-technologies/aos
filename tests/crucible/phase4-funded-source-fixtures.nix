# Produces real portable input files for distinct actual host executable families.
{
  pkgs,
  lib,
  components,
}: let
  inherit (components) source support cli peers buildClosure;
  inputs = executable:
    builtins.toJSON {
      host_executable = executable;
      peer_executable = "${peers}/bin/crucible-reference-packet-provider";
      sources = {
        adapter_source = "${source}/crates/crucible/engine/crucible-engine/src/node_adapters/cnp/packet_complete_source.rs";
        build_closure = "${buildClosure}/inventory.json";
        contract_source = "${source}/crates/crucible/host/crucible-node-transport/src/reference_packet/continuation_contracts.rs";
        harness_source = "${source}/crates/crucible/control/crucible-daemon/src/node_qualification/packet_collection/complete/installed/source/fresh_target/prepared.rs";
        native_source = "${source}/crates/crucible/host/crucible-node-transport/src/reference_packet/service/native_startup.rs";
        program_source = "${source}/crates/crucible/host/crucible-node-transport/src/reference_packet/connected.rs";
        provider_source = "${source}/crates/crucible/host/crucible-node-transport/src/bin/crucible-reference-packet-provider.rs";
        recipe = "${./phase4-funded-source-components.nix}";
      };
      # These are explicit ordinary scene policies, not a fit assertion. Actual
      # construction/admission still derives and checks its original demand.
      resources = {
        cpu_budget_ns = "3000000000";
        memory_bytes = "4294967296";
        writable_bytes = "1048576";
        processes = "3";
        descriptors = "128";
        pending_events = "16";
        content_bytes = "536870912";
        maximum_operations = "64";
        extensions = {};
      };
      maximum_coordinator_records = 256;
    };
  cases = ["templates-a" "templates-b" "bad-pin" "cli"];
  deployment = name: {
    format = "crucible.node-operational-deployment";
    version = 1;
    parent = {
      cpu_seconds = 60;
      address_space_bytes = 8589934592;
      descriptors = 256;
    };
    worker = {
      cgroup_root = "/sys/fs/cgroup/funded-source";
      run_root = "/var/lib/funded-source/attempts/run-${name}";
      project_id = 31415;
      user_id = 20000;
      group_id = 20000;
      limits = {
        memory_bytes = 33554432;
        address_space_bytes = 268435456;
        cpu_seconds = 2;
        descriptors = 32;
        disk_bytes = 1048576;
        inodes = 32;
        input_bytes = 1024;
        maximum_input_elements = 1024;
        maximum_result_bytes = 1024;
        diagnostic_bytes = 256;
        stdout_bytes = 2048;
        stderr_bytes = 2048;
        wall_seconds = 15;
      };
    };
    export_workspace_slots = 1;
  };
  daemon = name: {
    format = "crucible.node-daemon-policy";
    version = 1;
    state_directory = "/var/lib/funded-source/attempts/state-${name}";
    socket = "/var/lib/funded-source/attempts/state-${name}/node.sock";
    device_executable = "${peers}/bin/crucible-reference-device";
    control_timeout_ms = 5000;
    maximum_worlds = 1;
    maximum_pending_requests = 4;
    immutable_artifacts = [];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-funded-source-portable-fixtures";
    version = "0";
    buildDeps = [pkgs.coreutils pkgs.jq support];
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "produce-and-independently-measure";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > support-inputs.json <<'EOF'
          ${inputs "${support}/bin/crucible-funded-source-templates-flight"}
          EOF
          cat > cli-inputs.json <<'EOF'
          ${inputs "${cli}/bin/crucible"}
          EOF
          producer=${support}/bin/crucible-complete-scene-fixture
          "$producer" build "$PWD/support-inputs.json" "$out/support"
          "$producer" measure "$out/support/configuration.json" "$out/support/expected.json"
          "$producer" build "$PWD/cli-inputs.json" "$out/cli"
          "$producer" measure "$out/cli/configuration.json" "$out/cli/expected.json"
          "$producer" measure-elf ${peers}/bin/crucible-reference-device "$out/device-expected.json"
          ${lib.concatMapStringsSep "\n" (name: ''
              mkdir -p "$out/${name}"
              cat > "$out/${name}/operational.json" <<'EOF'
              ${builtins.toJSON (deployment name)}
              EOF
              cat > daemon-template.json <<'EOF'
              ${builtins.toJSON (daemon name)}
              EOF
              jq --slurpfile expected "$out/device-expected.json" \
                '.expected_device = $expected[0]' daemon-template.json > "$out/${name}/daemon.json"
            '')
            cases}
          # This deliberately foreign pin remains well-typed; the real pinned
          # reader must refuse it, retaining the first failure and world debit.
          jq '.hash.digest = ("0" * 64)' "$out/support/expected.json" > "$out/bad-pin/expected.json"
          cp support-inputs.json cli-inputs.json "$out/"
          sha256sum "$out/support/configuration.json" "$out/cli/configuration.json" \
            "$out/support/expected.json" "$out/cli/expected.json" \
            "$out/device-expected.json" > "$out/inputs.sha256"
        '';
      }
    ];
  }
