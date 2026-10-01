##! Recursive operation contracts and handler modules for deferred host effects.
{
  config,
  lib,
  provenance,
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
    inputType = types.submodule operation.input;
    resultType = types.submodule operation.result;
    resultSchema = (projectType resultType).fields;
    documentation = import ./documentation.nix {inherit lib;};
    inputDocumentation = documentation.options inputType;

    effectModule = {
      config,
      name,
      ...
    }: let
      effect = config;
      definitions =
        provenance.definitionsOfNestedAttr ["aos" "abilities"]
        [abilityName "operations" operationName "effects" name];
      owners =
        lib.unique (builtins.map (definition: definition.owner)
          (builtins.filter (definition: !(lib.hasPrefix "@" definition.owner)) definitions));
      owner =
        if owners == []
        then "@environment"
        else if builtins.length owners == 1
        then builtins.head owners
        else throw "Effect '${abilityName}.${operationName}.${name}' has multiple package owners; derive shared operations in the managing package.";
      identity = activation.scope ++ [owner abilityName operationName name];
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
          builtins.mapAttrs (output: schema: {
            _type = "aos-effect-output";
            inherit identity output;
            inherit schema;
          })
          resultSchema;

        contract = {
          inherit identity;
          handled = operation.handler != null;
          inputs = inputDocumentation;
          input_type = projectType (types.submodule operation.input);
          results = resultSchema;
          inherit owner;
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
      result = mkOption {
        type = types.deferredModule;
        default = {};
        description = "Mergeable module declaring the operation's returned value options.";
      };
      documentation = mkOption {
        type = types.attrs;
        readOnly = true;
        description = "Interface documentation derived from the operation's native option declarations.";
      };
      handler = mkOption {
        type = types.nullOr types.deferredModule;
        default = null;
        description = "Environment-selected module interpreting the operation.";
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

    config = {
      module = effectModule;
      documentation = {
        input = inputDocumentation;
        result = documentation.options resultType;
        inputType = projectType inputType;
        inputDefaults =
          map (declaration: declaration.path)
          (builtins.filter (declaration: declaration.hasDefault && builtins.head declaration.path != "_module")
            (lib.submoduleOptionDeclarations inputType []));
        resultType = projectType resultType;
        handlerAvailable = operation.handler != null;
        configuredEffects = builtins.attrNames operation.effects;
        sources = builtins.listToAttrs (builtins.map (field: {
          name = field;
          value =
            provenance.definitionsOfNestedAttr ["aos" "abilities"]
            [abilityName "operations" operationName field];
        }) ["input" "result" "handler" "effects"]);
      };
    };
  };

  abilityModule = {name, ...}: {
    _module.strict = true;
    options.operations = mkOption {
      type = types.lazyAttrsOf (types.submodule (operationModule name));
      default = {};
      description = "Operation contracts and their selected interpretations.";
    };
  };
in {
  imports = [../modules/checks.nix];

  options.aos = {
    abilities = mkOption {
      type = types.lazyAttrsOf (types.submodule abilityModule);
      default = {};
      extensible = true;
      description = "Module-composed abilities; each owns its operations, handlers, and effects.";
    };
    activation.graph = mkOption {
      type = types.attrs;
      readOnly = true;
      description = "Bound deferred effect graph derived from the final module configuration.";
    };
    activation.retire = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Exact retained effect identities explicitly released by this deployment; configured effects cannot be retired.";
    };
    activation.scope = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Deployment and stage scope for logical activation identities.";
    };
  };

  config.aos.activation.graph = let
    failed = builtins.filter (check: !check.assertion) config.assertions;
    checked =
      if failed == []
      then true
      else throw "Failed configuration assertions:\n${builtins.concatStringsSep "\n" (builtins.map (check: check.message) failed)}";
    warnings = builtins.foldl' (value: warning: builtins.trace "warning: ${warning}" value) true config.warnings;
  in
    builtins.seq checked (builtins.seq warnings (import ./plan.nix {
      inherit lib;
      abilities = config.aos.abilities;
    }));
}
