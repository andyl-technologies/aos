# Retains actual source identities separately from deterministic guest work.
# The named roots cover all local normal, target, dev and build dependencies
# of the original flight, protected worker and plugin. Each measured revision
# retains its own complete bodies and workspace build policy.
{
  pkgs,
  revision,
  sampleId,
}: let
  sourceRoot = ../..;
  crateNames = [
    "crucible"
    "crucible-api"
    "crucible-campaign"
    "crucible-cas"
    "crucible-cli"
    "crucible-daemon"
    "crucible-device"
    "crucible-guest"
    "crucible-harness"
    "crucible-linux-resource"
    "crucible-protocol"
    "crucible-qemu"
    "crucible-qemu-plugin"
    "crucible-s3-store"
    "crucible-session"
    "crucible-shmem"
    "crucible-sim"
  ];
  filesUnder = relative: let
    entries = builtins.readDir (sourceRoot + "/${relative}");
  in
    builtins.concatMap (name: let
      path = "${relative}/${name}";
      kind = entries.${name};
    in
      if kind == "directory"
      then filesUnder path
      else if kind == "regular"
      then [path]
      else throw "performance source manifest refuses nonregular source ${path}")
    (builtins.attrNames entries);
  sourceFiles =
    [
      "crates/Cargo.toml"
      # These explicit path/include inputs are compiled outside the src roots.
      "crates/crucible-daemon/tests/support/campaign_queue_scan.rs"
      "crates/crucible-shmem/tests/fixtures/fault_register_manifest_v1.hex"
      "docs/rfcs/0020-crucible-campaigns/schema-registry.tsv"
      "docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md"
      "tests/crucible/fixtures/e2e-determinism.scenario.toml"
      "tests/crucible/fixtures/live-qemu-fuzz.family.toml"
    ]
    ++ builtins.concatMap (name:
      filesUnder "crates/${name}/src"
      ++ ["crates/${name}/Cargo.toml"]
      ++ (
        if builtins.pathExists (sourceRoot + "/crates/${name}/build.rs")
        then ["crates/${name}/build.rs"]
        else []
      ))
    crateNames;
  production =
    builtins.listToAttrs (map (path: {
        name = path;
        value = builtins.hashFile "sha256" (sourceRoot + "/${path}");
      })
      sourceFiles)
    // {
      "native/atomic-patch" = pkgs.qemu-crucible.passthru.atomicPatchHash;
      "native/shared-header" = pkgs.qemu-crucible.passthru.shmemHeaderHash;
    };
  hashJson = value: builtins.hashString "sha256" (builtins.toJSON value);
  conditions = {
    semantic_inputs = hashJson {
      scenario = builtins.hashFile "sha256" ./fixtures/e2e-determinism.scenario.toml;
      guest_recipe = builtins.hashFile "sha256" ./_nginx-curl-http-200-guest.nix;
      guest_derivation = (import ./_nginx-curl-http-200-guest.nix {inherit pkgs;}).drvPath;
    };
    toolchain = hashJson {
      rust = toString pkgs.rust;
      openssl = toString pkgs.openssl;
      sqlite = toString pkgs.sqlite;
      lock = builtins.hashFile "sha256" ../../crates/Cargo.lock;
      build = "frozen-offline-release-original-scaling-flight";
    };
    native_configuration = hashJson {
      kernel = toString pkgs.linux;
      configure_flags_sha256 = pkgs.qemu-crucible.passthru.qemuConfigureFlagsHash;
      execution = "original-native-performance-case-fixed-vcpu-shapes";
    };
    host_configuration = builtins.hashFile "sha256" ./fixtures/campaign-performance-reference-host-v1.env;
    cache_configuration = hashJson "fresh-original-performance-storage-and-protected-worker";
    measurement_fixture = hashJson {
      work = builtins.hashFile "sha256" ../../crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence/performance_work.rs;
      comparison = builtins.hashFile "sha256" ./campaign-performance-comparison.py;
    };
  };
  manifest = {
    schema = "crucible.campaign-performance.source.v2";
    inherit revision production conditions;
    sample_id = sampleId;
  };
  text = builtins.toJSON manifest;
in
  if builtins.length sourceFiles > 4096 || builtins.stringLength text > 1024 * 1024
  then throw "campaign performance source manifest exceeds bounded named source scope"
  else {inherit manifest production conditions text;}
