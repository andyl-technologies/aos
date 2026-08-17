# Resolver-authenticated artifact-owner acceptance.
{
  pkgs,
  mkSystem,
  serverModule,
}: let
  evaluated = mkSystem {
    modules = [serverModule];
    packageModules = [
      {
        name = "provenance-demo";
        authorization = {
          owns = ["environment" "systemd"];
          contributes = {};
        };
        module = {
          environment.etc."provenance-demo.conf".text = "package-owned\n";
          systemd.services.provenance-demo = {
            description = "configuration provenance fixture";
            wantedBy = ["multi-user.target"];
            script = "echo provenance-demo";
          };
        };
      }
    ];
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
          environment.systemPackages = [pkgs.aos-test-agent];
        }
      ];
    })
    .config
    .system
    .build
    .configManifest;
  testAgentPath = builtins.unsafeDiscardStringContext (builtins.toString pkgs.aos-test-agent);
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
      packageModules = [
        {
          name = "path-contributor";
          authorization = {
            owns = ["environment"];
            contributes = {};
          };
          module.environment.systemPackages = [pkgs.aos-test-agent];
        }
      ];
    })
    .config
    .system
    .build
    .configManifest
    .ownership
    .etc));
  packageSessionContribution = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      packageModules = [
        {
          name = "session-contributor";
          authorization = {
            owns = ["environment"];
            contributes = {};
          };
          module.environment.sessionVariables.PROVENANCE_TEST = "package";
        }
      ];
    })
    .config
    .system
    .build
    .configManifest
    .ownership
    .etc));
  jobKeys =
    builtins.filter
    (key: builtins.match "provenance-demo\\.service:.*" key != null)
    (builtins.attrNames manifest.jobScripts);
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
      packageModules = [
        {
          name = "group-provider";
          authorization = {
            owns = ["aos"];
            contributes = {};
          };
          module.aos.users.groups.pkgonly = {
            gid = 778;
            members = [];
          };
        }
      ];
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
  assert hostSessionManifest.ownership.etc.profile == "@base";
  assert hostSessionManifest.ownership.etc."pam/environment" == "@host";
  assert directHostLoginManifest.ownership.etc.profile == "@host";
  assert directHostLoginManifest.ownership.etc."pam/environment" == "@host";
  assert !packagePathContribution.success;
  assert !packageSessionContribution.success;
  assert manifest.ownership.etc."provenance-demo.conf" == "provenance-demo";
  assert manifest.ownership.etc."systemd/system/provenance-demo.service" == "provenance-demo";
  assert manifest.ownership.units."provenance-demo.service" == "provenance-demo";
  assert manifest.units."provenance-demo.service".action == "restart";
  assert manifest.units."provenance-demo.service".enable;
  assert builtins.length jobKeys == 1;
  assert manifest.ownership.jobScripts.${builtins.head jobKeys} == "provenance-demo";
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
