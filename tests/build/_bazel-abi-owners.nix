##! Compares migrated ABI owner executions while retaining the canonical gate.
{pkgs}: let
  protocol = import ./_bazel-protocol.nix {inherit pkgs;};
  plugin = import ./_bazel-qemu-plugin-tests.nix {inherit pkgs;};
  guest = import ./_bazel-guest.nix {inherit pkgs;};
  engine = import ./_bazel-engine.nix {inherit pkgs;};
  session = import ./_bazel-session.nix {inherit pkgs;};

  owner = workspace: target: count: canonical: filter: {
    inherit workspace target count canonical filter;
  };
  contracts = {
    harness =
      owner engine.workspace
      "//crates/crucible/crucible-test-support:gate_abi_conformance"
      4
      "gate_abi_conformance_is_implemented_in_catalog_and_targets"
      null;
    api =
      owner session.workspace
      "//crates/crucible/crucible-control-api:gate_abi_conformance"
      6
      "rpc_abi_conformance_runs_named_checks"
      null;
    shmem =
      owner protocol.workspace
      "//crates/crucible/crucible-qemu-shmem:gate_abi_conformance"
      5
      "gate_cases::gate_abi_conformance_checks_generated_header_and_golden_vectors"
      null;
    protocol =
      owner protocol.workspace
      "//crates/crucible/crucible-qemu-protocol:gate_abi_conformance"
      18
      "protocol_abi_conformance_runs_named_checks"
      null;
    protocol-golden =
      owner protocol.workspace
      "//crates/crucible/crucible-qemu-protocol:golden_vectors"
      7
      "golden_vectors_match_canonical_codec_bytes"
      null;
    protocol-doorbell =
      owner protocol.workspace
      "//crates/crucible/crucible-qemu-protocol:unit"
      3
      "doorbell_abi::tests::doorbell_abi_vectors_cover_x86_64_and_aarch64" "doorbell_abi";
    plugin-io-wire =
      owner plugin.workspace
      "//crates/crucible/crucible-qemu-plugin:unit"
      8
      "io_wire_fuzz::tests::io_wire_regression_corpus_exercises_block_and_9p_wire_cases" "io_wire_fuzz";
    plugin-doorbell =
      owner plugin.workspace
      "//crates/crucible/crucible-qemu-plugin:unit"
      54
      "whitebox_doorbell::tests::whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box" "whitebox_doorbell";
    plugin-owner =
      owner plugin.workspace
      "//crates/crucible/crucible-qemu-plugin:gate_abi_conformance"
      2
      "gate_abi_conformance_covers_plugin_io_wire_fuzzing"
      null;
    guest =
      owner guest.workspace
      "//crates/crucible/crucible-guest:gate_abi_conformance"
      5
      "guest_cli_verbs_encode_shared_marker_payloads"
      null;
    engine =
      owner engine.workspace
      "//crates/crucible/crucible-engine:gate_abi_conformance_test_double"
      2
      "gate_abi_conformance_engine_aggregates_boundary_abi_owners"
      null;
  };
  selections = builtins.mapAttrs (_: contract: removeAttrs contract ["workspace"]) contracts;
  verifier = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-abi-owner-verifier";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in rec {
  # Check the complete selected inventory before sharding or running any case.
  # These comparisons do not bypass the canonical gate's prerequisites or its
  # source audits. The named gate still owns the full prerequisite chain.
  owners = builtins.mapAttrs (name: contract:
    pkgs.mkAosBazelCheck {
      pname = "aos-bazel-abi-owner-${name}";
      inherit (contract) workspace;
      targets = [contract.target];
      testArguments =
        [
          "--expected-count=${toString contract.count}"
          "--require-case=${contract.canonical}"
          "--jobs=1"
        ]
        ++ pkgs.lib.optional (contract.filter != null) "--filter=${contract.filter}";
    })
  contracts;

  all = pkgs.runCommand "aos-bazel-abi-owner-comparisons" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out/owners"
    ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: result: ''
        ln -s ${result} "$out/owners/${name}"
      '')
      owners)}
    printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
      schema_version = 1;
      canonical_gate_sha256 = builtins.hashFile "sha256" ../crucible/phase2-abi-conformance.nix;
      inherit selections;
      qualification = "Owner execution comparison only; the named ABI gate remains authoritative.";
    })} > "$out/selections.json"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${verifier}/verify_abi_owners.py \
      --canonical ${../crucible/phase2-abi-conformance.nix} --comparison "$out"
  '';

  # Qualify the canonical driver's Bazel branch independently. The named gate
  # remains responsible for its license, determinism and other prerequisites.
  driver-comparison = import ../crucible/phase2-abi-conformance.nix {
    inherit pkgs;
    inherit (pkgs) lib;
    abiOwnerExecutions = all;
    attrPath = "checks.build.bazel.abi-owners.driver-comparison";
  };
}
