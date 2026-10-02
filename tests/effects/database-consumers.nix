##! Checks enabled database, export, synchronization, and hardware consumers.
let
  root = ../..;
  lib = import (root + /lib) {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (fixturePayload name);
    outputs.out = toString (fixturePayload name);
    mainProgram = name;
  };
  record = name: dir: let
    source = builtins.path {
      path = root + dir;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString source;
    module = "${source}/module.nix";
    artifacts = {
      package = artifact name;
      dependencies = {};
    };
  };
  eval = lib.evalPackageModules {
    scope = ["test" "daemons"];
    packageModules = [
      (record "aos-runtime-checks" /pkgs/system/_aos-runtime-checks)
      (record "service-management" /pkgs/system/_service-management)
      (record "filesystem" /pkgs/filesystem/_aos-filesystem-provider)
      ((record "postgresql" /pkgs/storage/_postgresql)
        // {
          artifacts = {
            package = artifact "postgresql";
            dependencies = builtins.listToAttrs (map (name: {
              inherit name;
              value = artifact name;
            }) ["bash" "coreutils"]);
          };
        })
      ((record "mariadb" /pkgs/storage/_mariadb)
        // {
          artifacts = {
            package = artifact "mariadb";
            dependencies = builtins.listToAttrs (map (name: {
              inherit name;
              value = artifact name;
            }) ["bash" "coreutils" "sed"]);
          };
        })
      (record "rsync" /pkgs/tools/_rsyncd)
      (record "conntrack-tools" /pkgs/tools/_conntrackd)
      (record "garage" /pkgs/storage/_garage-config)
      (record "storage-interface" /pkgs/system/_storage-interface)
      (record "smartmontools" /pkgs/tools/_smartmontools)
    ];
    operatorModules = [
      {
        aos.postgresql = {
          enable = true;
          topology = "standby";
          replication = {
            primary.host = "db.example.test";
            passfile.name = "pg-passfile";
          };
          tls = {
            enable = true;
            certificate.name = "pg-cert";
            privateKey.name = "pg-key";
            ca.name = "pg-ca";
          };
        };
        aos.mariadb = {
          enable = true;
          tls = {
            enable = true;
            certificate.name = "maria-cert";
            privateKey.name = "maria-key";
            ca.name = "maria-ca";
          };
          bootstrap = {
            adminSql.name = "maria-admin";
            replicationSql.name = "maria-repl";
          };
        };
        aos.rsyncd = {
          enable = true;
          modules.public.authUsers = ["exporter"];
          secrets.name = "rsync-secret";
        };
        aos.conntrackd.enable = true;
        aos.garage = {
          enable = true;
          rpc.secret.name = "garage-rpc";
        };
        aos.monitoring.hardware.enable = true;
        aos.abilities = builtins.listToAttrs (map (ability: {
            name = ability.name;
            value.operations = builtins.listToAttrs (map (op: {
                name = op;
                value.handler.program = (import (root + /lib/packages/artifacts.nix) {}).value (artifact "${ability.name}-handler");
              })
              ability.ops);
          }) [
            {
              name = "serviceManagement";
              ops = ["realize"];
            }
            {
              name = "identity";
              ops = ["group" "principal"];
            }
            {
              name = "network";
              ops = ["ready"];
            }
            {
              name = "configuration";
              ops = ["file"];
            }
            {
              name = "credential";
              ops = ["deliver"];
            }
            {
              name = "managerWatchdog";
              ops = ["ensure"];
            }
          ]);
      }
    ];
  };
  nodes = builtins.attrValues eval.deployment.graph.nodes;
  services = builtins.filter (node: builtins.elem "serviceManagement" node.identity) nodes;
  files = eval.config.aos.abilities.configuration.operations.file.effects;
in {
  exposeProfilesReturnPermissionDenied = assert builtins.all (node: node.input.policy.hardening.denied_operation_action == "return-permission-denied") (builtins.filter (node: node.input.policy != null && node.input.policy.hardening != null && node.input.policy.hardening.operation_profile == "system-service") services); true;
  sharedManager = assert builtins.length services == 8; assert builtins.all (node: node.owner == "service-management") services; true;
  protectedBootstrap = assert files.mariadb-bootstrap.input.mode == "0600"; assert builtins.length (builtins.filter builtins.isAttrs files.mariadb-bootstrap.input.fragments) == 2; true;
  deferredToml = assert files.garage.input.format == "toml"; assert (files.garage.input.value.metadata_dir._type or null) != null; true;
  conditionalCredentials = assert builtins.length (builtins.attrNames eval.config.aos.abilities.credential.operations.deliver.effects) == 11; true;
  independentWatchdog = assert eval.config.aos.abilities.managerWatchdog.operations.ensure.effects.smartmontools.input.runtime_timeout_millis == 30000; true;
}
