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
  host = operator:
    (lib.evalPackageModules {
      scope = ["system"];
      packages = [pkgs.systemd pkgs.dbus];
      operatorModules = [operator];
    }).config;
  hostSeed = config:
    (import ../../pkgs/system/_systemd-abilities/platform/account-seed.nix {
      inherit config lib pkgs;
    }).environment.etc;
  hostBaseline = host {};
  hostAccounts = hostSeed hostBaseline;
  nativeHostRows = config:
    import ../../pkgs/system/_systemd-abilities/platform/_identity-bootstrap.nix {
      inherit lib shells;
      identities = config.aos.abilities.identity.operations;
      accounts = config.aos.users;
      groupReferences =
        map (effect: effect.outputs.name)
        (builtins.attrValues (lib.filterAttrs (_: effect:
          effect.enable && effect.input.requested_id != null)
        config.aos.abilities.identity.operations.group.effects));
      principalReferences =
        map (effect: effect.outputs.name)
        (builtins.attrValues (lib.filterAttrs (_: effect:
          effect.enable && effect.input.requested_id != null && !(builtins.elem effect.input.name ["root" "nobody"]))
        config.aos.abilities.identity.operations.principal.effects));
    };
  hostDisabledConfig = host {
    aos.abilities.network.operations.configure.effects.host.enable = false;
  };
  hostOverriddenConfig = host ({config, ...}: {
    aos.abilities.network.operations.configure.effects.host.input.accounts = lib.mkForce [
      config.aos.abilities.identity.operations.principal.effects.systemd-resolve.outputs.name
    ];
  });
  hostDisabled = hostSeed hostDisabledConfig;
  hostOverridden = hostSeed hostOverriddenConfig;
  hostIdentityDisabledConfig = host {
    aos.abilities.identity.operations.principal.effects.systemd-network.enable = false;
  };
  hostIdentityDisabled = hostSeed hostIdentityDisabledConfig;
  hostDbusDisabledConfig = host {aos.services.dbus.enable = false;};
  hostDbusRuntimeOnlyConfig = host {aos.services.dbus.bootstrap = false;};
  hostDbusDisabled = hostSeed hostDbusDisabledConfig;
  hostDbusRuntimeOnly = hostSeed hostDbusRuntimeOnlyConfig;
  hostCases = {
    baseline = hostBaseline;
    disabled = hostDisabledConfig;
    overridden = hostOverriddenConfig;
    principal-disabled = hostIdentityDisabledConfig;
    dbus-disabled = hostDbusDisabledConfig;
    dbus-runtime-only = hostDbusRuntimeOnlyConfig;
  };
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
  archiveBuilder = builtins.head (builtins.filter (dependency: (dependency.name or "") == "aos-initrd-archive") builder.buildDeps);
  accountPhase = builtins.head (builtins.filter (phase: phase.name == "seed-accounts") archiveBuilder.phases);
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
    buildDeps = [pkgs.coreutils pkgs.gawk pkgs.systemd];
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

          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (caseName: config: let
              accounts = hostSeed config;
              root = "host-${caseName}";
            in ''
              mkdir -p ${root}/etc ${root}/usr/lib/sysusers.d
              ${lib.concatMapStringsSep "\n" (name: ''
                cp ${pkgs.writeTextFile {
                  name = "expected-${caseName}-${name}";
                  text = accounts.${name}.text;
                }} ${root}/etc/${name}
                cp ${root}/etc/${name} "$TMPDIR/before-${caseName}-${name}"
              '') ["passwd" "group" "shadow"]}
              chmod 600 ${root}/etc/shadow
              cp ${pkgs.systemd}/lib/sysusers.d/systemd*.conf ${root}/usr/lib/sysusers.d/
              ${pkgs.systemd}/bin/systemd-sysusers --root="$PWD/${root}" \
                systemd-network.conf systemd-resolve.conf
                ${lib.optionalString (caseName != "principal-disabled") (lib.concatMapStringsSep "\n" (name: ''
                cmp ${root}/etc/${name} "$TMPDIR/before-${caseName}-${name}"
              '') ["passwd" "group" "shadow"])}

              # Check every vendor-created fixed principal against native policy;
              # absent vendor accounts remain native-created during activation.
              ${pkgs.systemd}/bin/systemd-sysusers --root="$PWD/${root}"
              awk -F: 'FNR == NR { expected[$1] = $0; next }
                $1 in expected && $0 != expected[$1] { exit 1 }' \
                ${pkgs.writeTextFile {
                name = "expected-native-${caseName}-accounts";
                text = (nativeHostRows config).passwd;
              }} \
                  ${root}/etc/passwd
                awk -F: 'FNR == NR { expected[$1] = $3; next }
                  $1 in expected && $3 != expected[$1] { exit 1 }' \
                  ${pkgs.writeTextFile {
                name = "expected-native-${caseName}-groups";
                text = (nativeHostRows config).group;
              }} \
                  ${root}/etc/group
            '')
            hostCases)}
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  };
  checks = {
    completeNetworkRow = row "systemd-network" baselineSeed.passwd == [(expected "systemd-network")];
    completeResolverRow = row "systemd-resolve" baselineSeed.passwd == [(expected "systemd-resolve")];
    masterAccountDescriptionsPreserved = baseline.aos.abilities.identity.operations.principal.effects.systemd-network.input.description == "systemd Network Management" && baseline.aos.abilities.identity.operations.principal.effects.systemd-resolve.input.description == "systemd Resolver";
    hostAndInitrdEarlyIdentitiesMatch = builtins.all (name:
      row name hostAccounts.passwd.text
      == row name baselineSeed.passwd
      && row name hostAccounts.group.text == row name baselineSeed.group
      && row name hostAccounts.shadow.text == row name baselineSeed.shadow)
    ["systemd-network" "systemd-resolve"];
    hostSeedUsesExactPolicy = row "systemd-resolve" hostAccounts.passwd.text == [(expected "systemd-resolve")];
    earlyServiceUsesDeclaredPrincipal = row "messagebus" hostAccounts.passwd.text == ["messagebus:x:81:81:D-Bus Message Bus:/var/run/dbus:${shells.nologin}"] && row "messagebus" hostAccounts.group.text == ["messagebus:x:81:"];
    disabledEarlyServiceHasNoSeed = row "messagebus" hostDbusDisabled.passwd.text == [] && row "messagebus" hostDbusDisabled.group.text == [];
    runtimeOnlyServiceHasNoSeed = row "messagebus" hostDbusRuntimeOnly.passwd.text == [] && row "messagebus" hostDbusRuntimeOnly.group.text == [];
    networkRequestDoesNotControlEarlyServices = row "messagebus" hostDisabled.passwd.text == row "messagebus" hostAccounts.passwd.text;
    hostRequestOverridePreservesManagerIdentities = row "systemd-network" hostOverridden.passwd.text == [(expected "systemd-network")] && row "systemd-resolve" hostOverridden.passwd.text == [(expected "systemd-resolve")];
    hostDisabledConfigurePreservesManagerIdentities = !hostDisabledConfig.aos.abilities.network.operations.configure.effects.host.enable && row "systemd-network" hostDisabled.passwd.text == [(expected "systemd-network")] && row "systemd-resolve" hostDisabled.passwd.text == [(expected "systemd-resolve")];
    hostDisabledIdentityIsNotSeeded = row "systemd-network" hostIdentityDisabled.passwd.text == [] && row "systemd-resolve" hostIdentityDisabled.passwd.text == [(expected "systemd-resolve")];
    hostEnabledGroupSurvivesDisabledPrincipal = hostIdentityDisabledConfig.aos.abilities.identity.operations.group.effects.systemd-network.enable && row "systemd-network" hostIdentityDisabled.group.text == row "systemd-network" hostAccounts.group.text;
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
