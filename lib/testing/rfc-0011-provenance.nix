# lib/testing/rfc-0011-provenance.nix — resolver-authenticated artifact owners.
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
  jobKeys = builtins.filter
    (key: builtins.match "provenance-demo\\.service:.*" key != null)
    (builtins.attrNames manifest.jobScripts);
  ancestorEtcCollision = builtins.tryEval (builtins.toJSON ((mkSystem {
    modules = [serverModule];
    operatorModules = [{
      environment.etc = {
        a.text = "ancestor";
        "a-escape".text = "interposed sort key";
        "a/child".text = "descendant";
      };
    }];
  }).config.system.build.configManifest.etc));
  mixedUserGroupOwner = builtins.tryEval (builtins.toJSON ((mkSystem {
    modules = [serverModule];
    packageModules = [{
      name = "group-provider";
      authorization = {owns = ["aos"]; contributes = {};};
      module.aos.users.groups.pkgonly = {gid = 778; members = [];};
    }];
    operatorModules = [{
      aos.users.users.hostuser = {
        uid = 778;
        group = "pkgonly";
        home = "/";
        shell = "/bin/false";
        description = "host";
      };
    }];
  }).config.system.build.configManifest.ownership.users));
in
  assert manifest.ownership.etc."systemd/network/20-host.network" == "@host";
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
      pname = "rfc-0011-provenance-check";
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
