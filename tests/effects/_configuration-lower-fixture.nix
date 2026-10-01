##! Produces checked native lower inputs from the retained owning package module.
{
  lib,
  pkgs,
}: let
  tree = builtins.path {
    path = ./fixtures/inert-payload;
    name = "configuration-tree-fixture";
  };
  evaluated = lib.evalPackageModules {
    scope = ["profile" "configuration-lower-test"];
    packages = [pkgs.aos-configuration-lower pkgs.systemd];
    operatorModules = [
      ../../pkgs/system/_aos-host-policy/configuration-lower.nix
      {
        aos.abilities.configuration.operations.file.effects.materialized.input = {
          path = "/etc/runtime-config/materialized.conf";
          content = "host-owned\n";
          mode = "0644";
        };
        aos.filesystems.etcTrees = [
          {
            target = "package-tree";
            source = tree;
          }
        ];
        aos.configurationLower = {
          enable = true;
          files = {
            "package-tree/identity.txt" = {
              kind = "text";
              text = "operator-override\n";
              mode = "0640";
            };
            "systemd/system/fixture.service" = {
              kind = "text";
              text = "[Service]\nExecStart=#aos-jobscript:start#\n";
            };
            "systemd/system/multi-user.target.wants/fixture.service" = {
              kind = "symlink";
              target = "../fixture.service";
            };
          };
          jobScripts.start = {
            text = "#!${pkgs.bash}/bin/bash\nexit 0\n";
            mode = "0755";
          };
          ownership = {
            files = builtins.listToAttrs (map (path: {
                name = path;
                value = "@environment";
              }) [
                "package-tree/identity.txt"
                "systemd/system/fixture.service"
                "systemd/system/multi-user.target.wants/fixture.service"
              ]);
            jobScripts.start = "@environment";
          };
          baselinePaths = ["runtime-config/materialized.conf"];
          # The selected systemd defaults also materialize the native CA bundle.
          storePaths = [(toString tree) (toString pkgs.bash) (toString pkgs.ca-certificates)];
        };
      }
    ];
  };
  graph = evaluated.deployment.graph.nodes;
  id = builtins.head (builtins.filter (id: builtins.elem "configurationLower" graph.${id}.identity && builtins.elem "ensure" graph.${id}.identity) (builtins.attrNames graph));
  node = graph.${id};
in {
  inherit evaluated node tree;
  invocation = {
    inherit id;
    effect = node;
    input = node.input;
    revision = node.revision;
    action = "apply";
    previous = null;
  };
}
