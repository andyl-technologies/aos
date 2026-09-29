##! Pure module contracts, merging, and handler expansion without a host image.
let
  lib = import ../../lib {system = "x86_64-linux";};
  program = {
    type = "derivation";
    name = "effect-fixture";
    outPath = "/nix/store/00000000000000000000000000000000-effect-fixture";
    meta.mainProgram = "effect-fixture";
  };
  evaluate = modules:
    lib.evalModules {
      inherit lib;
      modules = [../../lib/effects/module.nix] ++ modules;
    };
  declaration = {
    aos.abilities.kernel.operations.apply.input = {lib, ...}: {
      _module.strict = true;
      options.values = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = {};
      };
    };
  };
  extension = {
    aos.abilities.kernel.operations.apply.input = {lib, ...}: {
      options.verify = lib.mkOption {
        type = lib.types.bool;
        default = true;
      };
    };
  };
  handler = {
    aos.abilities.kernel.operations.apply.handler = {
      inherit program;
    };
  };
  first = {
    aos.abilities.kernel.operations.apply.effects.host.input.values.first = "1";
  };
  second = {
    aos.abilities.kernel.operations.apply.effects.host.input.values.second = "2";
  };
  merged = evaluate [declaration extension handler first second];
  effect = merged.config.aos.abilities.kernel.operations.apply.effects.host;
  graph = merged.config.aos.activation.graph;
  rejected = modules:
    !(builtins.tryEval (builtins.deepSeq (evaluate modules).config.aos.activation.graph true)).success;
  producer = {
    aos.abilities.files.operations.create = {
      results.path = lib.types.str;
      handler.program = program;
      effects.state = {};
    };
  };
  consumer = {
    config,
    lib,
    ...
  }: {
    aos.abilities.files.operations.use = {
      input = {
        _module.strict = true;
        options.path = lib.mkOption {
          type = lib.types.deferred lib.types.str;
        };
      };
      handler.program = program;
      effects.reader.input.path = config.aos.abilities.files.operations.create.effects.state.outputs.path;
    };
  };
  connected = (evaluate [producer consumer]).config.aos.activation.graph;
  composition = {config, ...}: let
    create = config.aos.abilities.files.operations.create;
  in {
    aos.abilities.files.operations.prepare = {
      results.path = lib.types.str;
      handler = {children, ...}: {
        children.directory.imports = [create.module];
        exports.path = children.directory.outputs.path;
      };
      effects.database = {};
    };
  };
  composed = (evaluate [producer composition]).config.aos.activation.graph;
in {
  mergedInput = assert effect.input.values
  == {
    first = "1";
    second = "2";
  }; true;
  mergedSchema = assert effect.input.verify; true;
  terminal = assert builtins.length (builtins.attrNames graph.nodes) == 1; true;
  unhandled = assert rejected [declaration first]; true;
  wrongType = assert rejected [
    declaration
    handler
    {
      aos.abilities.kernel.operations.apply.effects.host.input.values.first = 1;
    }
  ]; true;
  disabled = assert (evaluate [
    declaration
    first
    {
      aos.abilities.kernel.operations.apply.effects.host.enable = false;
    }
  ]).config.aos.activation.graph.nodes
  == {}; true;
  dependencies = assert builtins.length connected.order == 2;
  assert (builtins.elemAt connected.order 0) == builtins.head connected.nodes.${builtins.elemAt connected.order 1}.dependencies; true;
  composed = assert builtins.length composed.order == 3; true;
  disabledProducer = assert rejected [
    producer
    consumer
    {
      aos.abilities.files.operations.create.effects.state.enable = false;
    }
  ]; true;
  wrongOutputType = assert rejected [
    producer
    consumer
    {
      aos.abilities.files.operations.create.results.path = lib.types.int;
    }
  ]; true;
  cycle = assert rejected [
    producer
    consumer
    ({config, ...}: {
      aos.abilities.files.operations.use.results.done = lib.types.bool;
      aos.abilities.files.operations.create.effects.state.after = [
        config.aos.abilities.files.operations.use.effects.reader.outputs.done
      ];
    })
  ]; true;
  handlerOverride = assert (evaluate [
    declaration
    first
    handler
    {
      aos.abilities.kernel.operations.apply.handler = lib.mkForce {
        program = program // {outPath = "/nix/store/11111111111111111111111111111111-alternative";};
      };
    }
  ]).config.aos.abilities.kernel.operations.apply.effects.host.execution.program.outPath
  == "/nix/store/11111111111111111111111111111111-alternative"; true;
  undeclaredInput = assert rejected [
    declaration
    handler
    {
      aos.abilities.kernel.operations.apply.effects.host.input.typo = true;
    }
  ]; true;
  recursiveHandler = assert rejected [
    ({config, ...}: {
      aos.abilities.recursive.operations.loop = {
        handler.children.again.imports = [config.aos.abilities.recursive.operations.loop.module];
        effects.root = {};
      };
    })
  ]; true;
  handlerExtension = assert (evaluate [
    declaration
    first
    {
      aos.abilities.kernel.operations.apply.handler = {lib, ...}: {
        options.settings.verify = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
      };
    }
    {
      aos.abilities.kernel.operations.apply.handler = {config, ...}: {
        program =
          if config.settings.verify
          then program
          else null;
      };
    }
  ]).config.aos.abilities.kernel.operations.apply.effects.host.execution.settings.verify; true;
}
