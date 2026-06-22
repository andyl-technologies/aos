{
  pkgs,
  lib,
}: let
  launchRust = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  launchTest = builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs;
  deterministicLaunchCheck = builtins.readFile ./phase1-deterministic-launch.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  risksSpikes = builtins.readFile ../../docs/rfcs/0010-crucible/30-risks-spikes.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  failures =
    failuresFor "crates/crucible-qemu/src/launch.rs" launchRust [
      {
        label = "conservative default disables KASLR";
        needle = "nokaslr norandmaps random.trust_cpu=off";
      }
      {
        label = "explicit KASLR enablement rejected";
        needle = "KernelKaslrExplicitlyEnabled";
      }
      {
        label = "missing nokaslr rejected";
        needle = "KernelKaslrNotDisabled";
      }
      {
        label = "ambiguous nokaslr rejected";
        needle = "KernelKaslrFlagAmbiguous";
      }
      {
        label = "missing norandmaps rejected";
        needle = "UserspaceAslrNotDisabled";
      }
      {
        label = "ambiguous norandmaps rejected";
        needle = "UserspaceAslrFlagAmbiguous";
      }
      {
        label = "bare flag parser";
        needle = "fn require_kernel_bare_flag_once";
      }
      {
        label = "opposing kaslr parser";
        needle = "reject_kernel_cmdline_key(";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "append includes nokaslr";
        needle = "any(|arg| arg == \"nokaslr\")";
      }
      {
        label = "append includes norandmaps";
        needle = "any(|arg| arg == \"norandmaps\")";
      }
      {
        label = "hash material includes conservative flags";
        needle = "kernel_cmdline=console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps";
      }
      {
        label = "missing nokaslr assertion";
        needle = "LaunchProfileError::KernelKaslrNotDisabled";
      }
      {
        label = "missing norandmaps assertion";
        needle = "LaunchProfileError::UserspaceAslrNotDisabled";
      }
      {
        label = "explicit kaslr assertion";
        needle = "LaunchProfileError::KernelKaslrExplicitlyEnabled";
      }
      {
        label = "ambiguous nokaslr assertion";
        needle = "LaunchProfileError::KernelKaslrFlagAmbiguous";
      }
      {
        label = "ambiguous norandmaps assertion";
        needle = "LaunchProfileError::UserspaceAslrFlagAmbiguous";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-deterministic-launch.nix" deterministicLaunchCheck [
      {
        label = "deterministic launch tracks T-DET-6";
        needle = "KernelKaslrNotDisabled";
      }
      {
        label = "deterministic launch tracks userspace ASLR";
        needle = "UserspaceAslrNotDisabled";
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
        label = "per-image capability decision";
        needle = "default_decision=randomization_may_be_enabled_per_image";
      }
      {
        label = "no fallback adopted";
        needle = "fallback_adopted=none";
      }
      {
        label = "global default not flipped";
        needle = "it is not a global default flip";
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
            default_kernel_randomization=nokaslr
            default_userspace_randomization=norandmaps
            spike=RISK-13/T-RISK-6
            spike_result=randomization_reproducible_with_fully_seeded_entropy
            default_decision=randomization_may_be_enabled_per_image
            global_default=nokaslr,norandmaps
            fallback_adopted=none
            RESULT
          '';
        }
      ];
    }
