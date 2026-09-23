# Resolver-authenticated artifact-owner acceptance.
{
  pkgs,
  mkSystem,
  serverModule,
}: let
  packageModuleRoot = builtins.path {
    path = ../../tests/fixtures/config-provenance;
    name = "aos-config-provenance-package-modules";
  };
  packageModule = name: module: {
    inherit name;
    version = "1";
    configRoot = builtins.toString packageModuleRoot;
    module = "${packageModuleRoot}/${module}";
    outputs = {
      self = builtins.toString packageModuleRoot;
      dependencies = {};
    };
  };
  evaluated = mkSystem {
    modules = [
      serverModule
      {
        aos.packages.nginx = {
          package = pkgs.nginx;
          bundle = true;
        };
        aos.services.nginx = {
          enable = true;
          virtualHosts.default = {};
        };
      }
    ];
    packageModules = [(packageModule "provenance-demo" "provenance-demo.nix")];
    operatorModules = [
      {
        _file = "forged-package-name.nix";
        environment.etc."systemd/network/20-host.network".text = ''
          [Match]
          Name=eth0
        '';
      }
    ];
  };
  manifest = evaluated.config.system.build.configManifest;
  hostComposedManifest =
    (mkSystem {
      modules = [serverModule];
      operatorModules = [
        {
          aos.packages.aos-test-agent = {
            package = pkgs.aos-test-agent;
            bundle = true;
          };
        }
      ];
    })
    .config
    .system
    .build
    .configManifest;
  testAgentPath = builtins.unsafeDiscardStringContext (builtins.toString pkgs.aos-test-agent);
  selectedNginxAbilities = evaluated.config.aos.abilities;
  hostSessionManifest =
    (mkSystem {
      modules = [serverModule];
      operatorModules = [
        {
          environment.sessionVariables.PROVENANCE_TEST = "host";
        }
      ];
    })
    .config
    .system
    .build
    .configManifest;
  directHostLoginManifest =
    (mkSystem {
      modules = [serverModule];
      operatorModules = [
        ({lib, ...}: {
          environment.etc = {
            profile.text = lib.mkForce "host profile\n";
            "pam/environment".text = lib.mkForce "HOST_PAM=1\n";
          };
        })
      ];
    })
    .config
    .system
    .build
    .configManifest;
  packagePathContribution = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      packageModules = [(packageModule "path-contributor" "path-contributor.nix")];
    })
    .config
    .system
    .build
    .configManifest
    .ownership
    .etc));
  packageSessionContribution = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      packageModules = [(packageModule "session-contributor" "session-contributor.nix")];
    })
    .config
    .system
    .build
    .configManifest
    .ownership
    .etc));
  ancestorEtcCollision = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      operatorModules = [
        {
          environment.etc = {
            a.text = "ancestor";
            "a-escape".text = "interposed sort key";
            "a/child".text = "descendant";
          };
        }
      ];
    })
    .config
    .system
    .build
    .configManifest
    .etc));
  mixedUserGroupOwner = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      packageModules = [(packageModule "group-provider" "group-provider.nix")];
      operatorModules = [
        {
          aos.users.users.hostuser = {
            uid = 778;
            group = "pkgonly";
            home = "/";
            shell = "/bin/false";
            description = "host";
          };
        }
      ];
    })
    .config
    .system
    .build
    .configManifest
    .ownership
    .users));
in
  assert manifest.ownership.etc."systemd/network/20-host.network" == "@host";
  assert manifest.ownership.etc.profile == "@base";
  assert manifest.ownership.etc."pam/environment" == "@base";
  assert hostComposedManifest.ownership.etc.profile == "@host";
  assert hostComposedManifest.ownership.etc."pam/environment" == "@host";
  assert hostComposedManifest.ownership.storePaths.${testAgentPath} == "@host";
  assert selectedNginxAbilities.instances ? "nginx:nginx";
  assert selectedNginxAbilities.requests ? "nginx:main-lifecycle";
  assert selectedNginxAbilities.requests ? "nginx:server-configuration";
  assert hostSessionManifest.ownership.etc.profile == "@base";
  assert hostSessionManifest.ownership.etc."pam/environment" == "@host";
  assert directHostLoginManifest.ownership.etc.profile == "@host";
  assert directHostLoginManifest.ownership.etc."pam/environment" == "@host";
  assert !packagePathContribution.success;
  assert !packageSessionContribution.success;
  assert manifest.ownership.etc."provenance-demo.conf" == "provenance-demo";
  assert !ancestorEtcCollision.success;
  assert !mixedUserGroupOwner.success;
    pkgs.mkDerivation {
      pname = "config-provenance-check";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p $out
            echo PASS > $out/result
          '';
        }
      ];
    }
