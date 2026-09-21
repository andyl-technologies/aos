##! Evaluates the exact staged role companion with its staged module engine.
{
  baseRoot,
  configRoot,
  outputRoot,
  package,
  mode,
}: let
  base = import (builtins.toPath baseRoot);
  metadata = builtins.fromJSON (builtins.readFile "${configRoot}/config-meta.json");
  worker = package == "k3s-worker";
  valid = mode == "primary";
  evaluated = base.lib.evalModules {
    # The focused evaluator must declare the shared assertion sink; otherwise
    # undeclared writes are omitted before operational constraints are checked.
    modules = [
      {
        options.assertions = base.lib.mkOption {
          type = base.lib.types.listOf base.lib.types.attrs;
          default = [];
        };
      }
    ];
    operatorModules = [
      {
        k3s =
          {
            enable = true;
            node.name = "qualification-node";
            node.labels."aos.example/role" = "qualified";
          }
          // base.lib.optionalAttrs (valid || worker) {
            token.ref = "system-credential:k3s-qualification-token";
          }
          // base.lib.optionalAttrs (valid && worker) {
            serverUrl = "https://control.example:6443";
          };
      }
    ];
    packageModules = [
      {
        name = package;
        module = /. + "${configRoot}/module.nix";
        configRoot = /. + configRoot;
        authorization = {
          owns = map (entry: entry.root) metadata.owns_roots;
          contributes = {};
        };
        outputs = {
          self = outputRoot;
          dependencies = {};
        };
      }
    ];
  };
  failures = builtins.filter (entry: !entry.assertion) evaluated.assertions;
  projected = evaluated.config.${package};
in
  if failures != []
  then throw (base.lib.concatStringsSep "\n" (map (entry: entry.message) failures))
  else {
    role = evaluated.config.k3s.role;
    environment = projected.config.env;
    credential = projected.credentials.token.ref;
    resourceSchema = projected.config.addons.schema;
  }
