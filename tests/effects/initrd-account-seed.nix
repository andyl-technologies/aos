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
in {
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
}
