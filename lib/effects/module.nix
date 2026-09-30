##! Recursive operation contracts and handler modules for deferred host effects.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption types;
  projectType = import ../type-schema.nix {inherit lib;};
  activation = config.aos.activation;

  operationModule = abilityName: {
    config,
    name,
    ...
  }: let
    operation = config;
    operationName = name;
    inputDeclarations = lib.submoduleOptionDeclarations (types.submodule operation.input) [];
    inputDocumentation = builtins.listToAttrs (builtins.map (declaration: {
        name = builtins.concatStringsSep "." declaration.path;
        value = {
          inherit (declaration) description type;
        };
      }) (builtins.filter (declaration:
        builtins.head declaration.path != "_module")
      inputDeclarations));

    effectModule = {
      config,
      name,
      ...
    }: let
      effect = config;
      identity = activation.scope ++ [abilityName operationName name];
      handlerModules = lib.optional (operation.handler != null) operation.handler;
      executionType = types.submodule (
        [
          ({...}: {
            _module.args.input = effect.input;
            _module.args.outputs = effect.outputs;
            _module.args.children = effect.children;
          })
          ./execution.nix
        ]
        ++ handlerModules
      );
    in {
      _module.strict = true;

      options = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Whether this invocation participates in activation.";
        };
        input = mkOption {
          type = types.submodule [{_module.strict = true;} operation.input];
          default = {};
          description = "Arguments checked by the operation's merged input module.";
        };
        after = mkOption {
          type = types.listOf types.effectOutput;
          default = [];
          description = "Deferred outputs that must be available before this effect.";
        };
        lifetime = mkOption {
          type = types.enum ["transaction" "instance" "persistent"];
          default = "instance";
          description = "Retention of established state after the effect's transaction.";
        };
        timeoutMs = mkOption {
          type = types.addCheck types.int (value: value > 0 && value <= 3600000);
          default = 60000;
          description = "Maximum duration of one handler invocation in milliseconds.";
        };
        execution = mkOption {
          type = executionType;
          default = {};
          description = "The selected handler's merged interpretation of this invocation.";
        };
        outputs = mkOption {
          type = types.attrs;
          readOnly = true;
          description = "Typed deferred results; reading these does not execute the handler.";
        };
        contract = mkOption {
          type = types.attrs;
          readOnly = true;
          internal = true;
          description = "Declaration-derived operation identity and result types.";
        };
        children = mkOption {
          type = types.attrs;
          readOnly = true;
          internal = true;
          description = "Child modules evaluated in their own typed operation scopes.";
        };
      };

      config = {
        outputs =
          builtins.mapAttrs (output: type: {
            _type = "aos-effect-output";
            inherit identity output;
            schema = projectType type;
          })
          operation.results;

        contract = {
          inherit identity;
          handled = operation.handler != null;
          inputs = inputDocumentation;
          input_type = projectType (types.submodule operation.input);
          results = builtins.mapAttrs (_: type: projectType type) operation.results;
        };
        children = builtins.mapAttrs (childName: module:
          (lib.evalModules {
            inherit lib;
            modules = [module];
            specialArgs.name = builtins.hashString "sha256" (builtins.toJSON (identity ++ [childName]));
          }).config)
        effect.execution.children;
      };
    };
  in {
    _module.strict = true;

    options = {
      input = mkOption {
        type = types.deferredModule;
        default = {};
        description = "Mergeable module declaring the operation's argument options.";
      };
      results = mkOption {
        type = types.attrsOf types.optionType;
        default = {};
        description = "Portable option types for the operation's named results.";
      };
      handler = mkOption {
        type = types.nullOr types.deferredModule;
        default = null;
        description = "Host-selected module interpreting the operation.";
      };
      effects = mkOption {
        type = types.attrsOf (types.submodule effectModule);
        default = {};
        description = "Invocations configured through the operation's input module.";
      };
      module = mkOption {
        type = types.deferredModule;
        readOnly = true;
        internal = true;
        description = "The same typed invocation scope for use in composed handlers.";
      };
    };

    config.module = effectModule;
  };

  abilityModule = {name, ...}: {
    _module.strict = true;
    options.operations = mkOption {
      type = types.attrsOf (types.submodule (operationModule name));
      default = {};
      description = "Operation contracts and their host-selected interpretations.";
    };
  };
in {
  options.aos = {
    abilities = mkOption {
      type = types.attrsOf (types.submodule abilityModule);
      default = {};
      extensible = true;
      description = "Module-composed abilities; each owns its operations, handlers, and effects.";
    };
    activation.graph = mkOption {
      type = types.attrs;
      readOnly = true;
      description = "Bound deferred effect graph derived from the final module configuration.";
    };
    activation.scope = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Deployment and stage scope for logical activation identities.";
    };
  };

  config.aos.activation.graph = import ./plan.nix {
    inherit lib;
    abilities = config.aos.abilities;
  };
}
