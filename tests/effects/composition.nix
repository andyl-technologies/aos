##! Package-owned shared schemas extend through the recursive module fixed point.
let
  lib = import ../../lib {system = "x86_64-linux";};
  evaluate = packageModules:
    lib.evalModules {
      inherit lib packageModules;
      modules = [];
    };
  owner = {
    name = "domain";
    module = {
      options.instances = lib.mkOption {
        extensible = true;
        default = {};
        type = lib.types.lazyAttrsOf (lib.types.submodule {
          options.enable = lib.mkEnableOption "instance";
          options.message = lib.mkOption {
            type = lib.types.str;
            default = "default";
          };
        });
      };
      options.private = lib.mkOption {
        type = lib.types.str;
        default = "owned";
      };
    };
  };
  extension = {
    name = "extension";
    module.options.instances = lib.mkOption {
      default = {};
      type = lib.types.lazyAttrsOf (lib.types.submodule {
        options.verify = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
      });
    };
  };
  consumer = {
    name = "consumer";
    module.instances.main = {
      enable = true;
      message = "configured";
    };
  };
  rejects = packages: !(builtins.tryEval (builtins.deepSeq (evaluate packages).config true)).success;
  expected = {
    enable = true;
    message = "configured";
    verify = true;
  };
in {
  strictChecksLeaveDeclaredValuesLazy = let
    evaluated = evaluate [
      {
        name = "strict-module";
        module = {
          config,
          lib,
          ...
        }: {
          _module.strict = true;
          options.enable = lib.mkEnableOption "recursive guard";
          options.value = lib.mkOption {
            type = lib.types.str;
            default = "disabled";
          };
          config.value = lib.mkIf config.enable "enabled";
        };
      }
    ];
  in
    assert !evaluated.config.enable;
    assert evaluated.config.value == "disabled"; true;
  recursiveDefaults = assert (evaluate [
    {
      name = "recursive-defaults";
      module = {
        config,
        lib,
        ...
      }: {
        options.first = lib.mkOption {
          type = lib.types.str;
          default = "source";
        };
        options.second = lib.mkOption {
          type = lib.types.str;
          default = config.first;
        };
      };
    }
  ]).config.second
  == "source"; true;
  sharedSchema = assert (evaluate [owner extension consumer]).config.instances.main == expected; true;
  orderIndependent = assert (evaluate [extension consumer owner]).config.instances.main == expected; true;
  privateOption = assert rejects [
    owner
    {
      name = "other";
      module.private = "changed";
    }
  ]; true;
  incompatibleExtension = assert rejects [
    owner
    {
      name = "other";
      module.options.instances = lib.mkOption {
        type = lib.types.str;
        default = "bad";
      };
    }
  ]; true;
}
