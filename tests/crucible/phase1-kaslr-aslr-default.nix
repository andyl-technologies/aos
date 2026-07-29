{
  pkgs,
  lib,
}: let
  root = ../..;
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
  deterministicLaunchCheck = builtins.readFile ./phase1-deterministic-launch.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  risksSpikes = builtins.readFile ../../docs/rfcs/0010-crucible/30-risks-spikes.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;


  # The any-guest contract (D-31): guest entropy-suppression flags MUST NOT be
  # baked into the shipped default cmdline or gated on by the launch layer.

  # Launch-source strings that only exist under the old conservative-default
  # contract (suppression flags appended, KASLR/ASLR error variants that gate a
  # launch on their presence). None may appear in the flipped launch layer.
  forbiddenLaunchSource = [
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
      label = "launch gates on explicit KASLR enablement";
      needle = "KernelKaslrExplicitlyEnabled";
    }
    {
      label = "launch gates on missing ASLR suppression";
      needle = "UserspaceAslrNotDisabled";
    }
  ];

  failures =
    failuresFor "crates/crucible-qemu/src/launch*.rs" launchRust [
      {
        label = "stock guest kernel cmdline default (no entropy suppression)";
        needle = "const DEFAULT_KERNEL_CMDLINE: &str = \"console=ttyS0 reboot=k panic=1 quiet\";";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/launch*.rs" launchRust forbiddenLaunchSource
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "any-guest cmdline pass-through test";
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
        label = "guest-set suppression flags are legal but not required";
        needle = "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off";
      }
      {
        label = "guest-set opt-in randomization is legal";
        needle = "console=ttyS0 reboot=k panic=1 quiet kaslr random.trust_cpu=on";
      }
      {
        label = "stock cmdline enters hash material unchanged";
        needle = "kernel_cmdline=console=ttyS0 reboot=k panic=1 quiet";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-deterministic-launch.nix" deterministicLaunchCheck [
      {
        label = "deterministic launch asserts stock cmdline default";
        needle = "stock guest kernel cmdline default";
      }
      {
        label = "deterministic launch forbids appended suppression flags";
        needle = "shipped default appends nokaslr";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-6 checklist complete";
        needle = "- [x] **T-DET-6**";
      }
      {
        label = "T-DET-6 references RISK-13 retirement";
        needle = "RISK-13";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/30-risks-spikes.md" risksSpikes [
      {
        label = "S6 retired";
        needle = "**RISK-13** is retired by `T-RISK-6`";
      }
      {
        label = "D-31 flip on S6 evidence";
        needle = "On this evidence, **D-31** made the stock guest cmdline";
      }
      {
        label = "no fallback adopted";
        needle = "fallback_adopted=none";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes kaslr/aslr default check";
        needle = "kaslrAslrDefault = import ./phase1-kaslr-aslr-default.nix";
      }
      {
        label = "layer0 gate lists T-DET-6";
        needle = "\"T-DET-6\"";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 KASLR/ASLR default check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-kaslr-aslr-default";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "record-kaslr-aslr-default";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.kaslrAslrDefault
            gate=gate:layer0-determinism
            tasks=T-DET-6
            default_kernel_randomization=kaslr-enabled-stock
            default_userspace_randomization=aslr-enabled-stock
            spike=RISK-13/T-RISK-6
            spike_result=randomization_reproducible_with_fully_seeded_entropy
            default_decision=stock-guest-cmdline-host-side-sealed
            global_default=stock-no-entropy-suppression
            determinism_mechanism=host-side-qemu-icount-seeded-entropy
            fallback_adopted=none
            RESULT
          '';
        }
      ];
    }
