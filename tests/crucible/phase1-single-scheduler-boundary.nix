{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  engineLib = builtins.readFile (cratesDir + "/crucible/src/lib.rs");
  model = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  apiSource = sourceFor "crucible-api";
  sessionManifest = builtins.fromTOML (builtins.readFile (cratesDir + "/crucible-session/Cargo.toml"));

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  rustFilesUnder = dir: let
    entries = builtins.readDir dir;
  in
    lib.concatMap (
      name: let
        path = dir + "/${name}";
        kind = entries.${name};
      in
        if kind == "directory"
        then rustFilesUnder path
        else if kind == "regular" && builtins.match ".*\\.rs" name != null
        then [path]
        else []
    ) (builtins.attrNames entries);

  sourceFor = package: let
    srcDir = cratesDir + "/${package}/src";
    paths =
      if builtins.pathExists srcDir
      then rustFilesUnder srcDir
      else [];
  in
    builtins.concatStringsSep "\n" (map builtins.readFile paths);

  lowerPackages = [
    "crucible-sim"
    "crucible-assert"
    "crucible-shmem"
    "crucible-protocol"
    "crucible-device"
    "crucible-qemu"
    "crucible-qemu-plugin"
    "crucible-guest"
    "crucible-cli"
  ];

  lowerPackageFailures =
    lib.concatMap (
      package: let
        source = sourceFor package;
      in
        lib.optionals (hasInfix "pub trait QuantumLoop" source) [
          "${package}: must not define QuantumLoop; L3 owns the quantum-loop trait"
        ]
        ++ lib.optionals (hasInfix "pub fn drive_quantum" source) [
          "${package}: must not expose drive_quantum; L4 drives L3's boundary"
        ]
        ++ lib.optionals (hasInfix ".drive_quantum(" source || hasInfix "QuantumLoop::drive_quantum" source) [
          "${package}: must not call drive_quantum; only crucible-session may drive the L3 boundary"
        ]
    )
    lowerPackages;

  sessionDependsOnEngine =
    sessionManifest ? dependencies && sessionManifest.dependencies ? crucible;

  failures =
    lib.optionals (!(hasInfix "pub mod scheduler;" engineLib)) [
      "crucible: crate root must expose the scheduler boundary module"
    ]
    ++ lib.optionals (!(hasInfix "pub trait QuantumLoop" scheduler)) [
      "crucible: scheduler module must define QuantumLoop"
    ]
    ++ lib.optionals (!(hasInfix "pub struct QuantumRequest" scheduler)) [
      "crucible: scheduler module must define QuantumRequest"
    ]
    ++ lib.optionals (!(hasInfix "pub struct ScheduledEventKey" scheduler)) [
      "crucible: scheduler module must define ScheduledEventKey"
    ]
    ++ lib.optionals (!(hasInfix "pub enum SchedulingNodeKind" model)) [
      "crucible: model module must define scheduler node kinds"
    ]
    ++ lib.optionals (!(hasInfix "pub struct SessionDriver" sessionLib)) [
      "crucible-session: must expose SessionDriver"
    ]
    ++ lib.optionals (!(hasInfix "QuantumLoop" sessionLib)) [
      "crucible-session: must drive the L3 QuantumLoop boundary"
    ]
    ++ lib.optionals (!sessionDependsOnEngine) [
      "crucible-session: must depend on crucible to drive the L3 boundary"
    ]
    ++ lib.optionals (hasInfix "pub trait QuantumLoop" apiSource) [
      "crucible-api: must consume, not redefine, the L3 QuantumLoop boundary"
    ]
    ++ lib.optionals (!(hasInfix "impl QuantumLoop for ProductionVmLifecycleLoop" apiSource)) [
      "crucible-api: production VM lifecycle must adapt to the L3 QuantumLoop boundary"
    ]
    ++ lowerPackageFailures;
in
  if failures != []
  then throw "crucible phase1 single-scheduler boundary lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-single-scheduler-boundary";
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
            check=checks.crucible.phase1.singleSchedulerBoundary
            tasks=T-ARCH-5
            rust_test=crucible-harness::single_scheduler_boundary
            engine_boundary=crucible::scheduler::QuantumLoop
            session_driver=crucible_session::SessionDriver
            RESULT
          '';
        }
      ];
    }
