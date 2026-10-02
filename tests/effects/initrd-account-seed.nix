##! Checks bootstrap account rows against completed native network identity policy.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  shells = import ../../pkgs/system/_systemd-abilities/identity-shells.nix {
    inherit (pkgs) bash util-linux;
  };
  evaluate = operator:
    (lib.evalPackageModules {
      scope = ["system" "initrd"];
      packages = [pkgs.systemd];
      operatorModules = [operator];
    }).config;
  seed = config:
    import ../../pkgs/system/_systemd-abilities/platform/_identity-bootstrap.nix {
      inherit lib shells;
      identities = config.aos.abilities.identity.operations;
      accounts = config.aos.users;
      principalReferences = lib.unique (builtins.concatMap (effect: effect.input.accounts)
        (builtins.attrValues (lib.filterAttrs (_: effect: effect.enable)
            config.aos.abilities.network.operations.configure.effects)));
    };
  baseline = evaluate {};
  baselineSeed = seed baseline;
  row = name: text:
    builtins.filter (line: lib.hasPrefix "${name}:" line) (lib.splitString "\n" text);
  expected = name: let
    principal = baseline.aos.abilities.identity.operations.principal.effects.${name}.input;
    group = baseline.aos.abilities.identity.operations.group.effects.${lib.last principal.primary_group.identity}.input;
  in "${name}:x:${toString principal.requested_id}:${toString group.requested_id}:${principal.description}:${principal.home_directory}:${shells.nologin}";
  overridden = evaluate ({config, ...}: {
    aos.abilities.network.operations.configure.effects.host.input.accounts = lib.mkForce [
      config.aos.abilities.identity.operations.principal.effects.systemd-resolve.outputs.name
    ];
  });
  disabled = evaluate {
    aos.abilities.network.operations.configure.effects.host.enable = false;
  };
  supplementary = evaluate {
    aos.abilities.identity.operations.principal.effects.systemd-network.input.supplementary_groups = ["wheel"];
    aos.users.groups.wheel.members = ["root"];
    aos.users.groups.systemd-network = {
      gid = 192;
      members = ["root"];
    };
  };
  supplementarySeed = seed supplementary;
  builder = import ../../pkgs/system/_systemd-abilities/platform/_initrd-builder.nix {
    inherit lib;
    mkDerivation = arguments: arguments;
    runtimePackages = pkgs;
    kernel = {};
    loadModules = [];
    initrdUnits = "unused";
    initrdRuntimeRoots = [];
    handoff = {};
    deploymentBundle = "unused";
    registration = "unused";
    accountSeed = baselineSeed;
  };
  accountPhase = builtins.head (builtins.filter (phase: phase.name == "seed-accounts") builder.phases);
  expectedFile = name:
    pkgs.writeTextFile {
      name = "expected-initrd-${name}";
      text = baselineSeed.${name};
    };
in {
  serialization = pkgs.mkDerivation {
    pname = "aos-initrd-account-serialization-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.gawk];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p root/etc
          ${accountPhase.script}
          ${lib.concatMapStringsSep "\n" (name: ''
            cmp root/etc/${name} ${expectedFile name}
            awk 'NF == 0 { exit 1 }' root/etc/${name}
          '') ["passwd" "group" "shadow"]}
          test "$(stat -c %a root/etc/shadow)" = 600
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  };
  checks = {
    completeNetworkRow = row "systemd-network" baselineSeed.passwd == [(expected "systemd-network")];
    completeResolverRow = row "systemd-resolve" baselineSeed.passwd == [(expected "systemd-resolve")];
    configuredAccountsOverride =
      row "systemd-network" (seed overridden).passwd
      == []
      && row "systemd-resolve" (seed overridden).passwd == [(expected "systemd-resolve")];
    disabledNetworkHasNoSeed =
      row "systemd-network" (seed disabled).passwd
      == []
      && row "systemd-resolve" (seed disabled).passwd == []
      && builtins.length (row "root" (seed disabled).passwd) == 1
      && builtins.length (row "nobody" (seed disabled).passwd) == 1;
    supplementaryMembershipPreserved = row "wheel" supplementarySeed.group == ["wheel:x:10:root,systemd-network"];
    existingNativeGroupMemberPreserved = row "systemd-network" supplementarySeed.group == ["systemd-network:x:192:root"];
  };
}
