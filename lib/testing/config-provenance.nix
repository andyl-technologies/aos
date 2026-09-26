# Resolver-authenticated artifact-owner acceptance.
{
  pkgs,
  mkSystem,
  serverModule,
}: let
  mkCheck = name: valid:
    if !valid
    then throw "config-provenance ${name} failed"
    else
      pkgs.mkDerivation {
        pname = "config-provenance-${name}-check";
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
      };

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

  suites = {
    config-provenance-base = mkCheck "base" (
      manifest.ownership.etc."systemd/network/20-host.network"
      == "@host"
      && manifest.ownership.etc.profile == "@base"
      && manifest.ownership.etc."pam/environment" == "@base"
      && manifest.ownership.etc."provenance-demo.conf" == "provenance-demo"
      && selectedNginxAbilities.instances ? "nginx:nginx"
      && selectedNginxAbilities.requests ? "nginx:main-lifecycle"
      && selectedNginxAbilities.requests ? "nginx:server-configuration"
    );

    config-provenance-host-package = mkCheck "host-package" (
      hostComposedManifest.ownership.etc.profile
      == "@host"
      && hostComposedManifest.ownership.etc."pam/environment" == "@host"
      && hostComposedManifest.ownership.storePaths.${testAgentPath} == "@host"
    );

    config-provenance-host-etc = mkCheck "host-etc" (
      hostSessionManifest.ownership.etc.profile
      == "@base"
      && hostSessionManifest.ownership.etc."pam/environment" == "@host"
      && directHostLoginManifest.ownership.etc.profile == "@host"
      && directHostLoginManifest.ownership.etc."pam/environment" == "@host"
    );

    config-provenance-package-rejections = mkCheck "package-rejections" (
      !packagePathContribution.success
      && !packageSessionContribution.success
    );

    config-provenance-collision-rejections = mkCheck "collision-rejections" (
      !ancestorEtcCollision.success
      && !mixedUserGroupOwner.success
    );
  };
in {
  inherit suites;

  all = pkgs.mkDerivation {
    pname = "config-provenance-check";
    version = "0";
    src = null;
    buildDeps = builtins.attrValues suites;
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p $out
          echo PASS > $out/result
        '';
      }
    ];
  };
}
