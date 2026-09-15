{lib}: let
  evaluated = lib.evalModules {
    modules = [
      {
        options.test = {
          base = lib.mkOption {type = lib.types.bool;};
          binding = lib.mkOption {type = lib.types.bool;};
          operator = lib.mkOption {type = lib.types.bool;};
          package = lib.mkOption {
            type = lib.types.bool;
            contributable = true;
          };
          provider = lib.mkOption {
            type = lib.types.str;
            contributable = true;
          };
        };

        config.test.base = true;
      }
    ];
    packageModules = [
      {
        name = "consumer";
        module = {
          config.test.package = true;
        };
      }
    ];
    selectedProviderModules = [
      {
        name = "provider";
        packageVersion = "1.0.0";
        configRoot = ./provider-module-fixture;
        module = ./provider-module-fixture/module.nix;
        outputs = {
          self = "/nix/store/00000000000000000000000000000000-provider";
          dependencies.helper = "/nix/store/11111111111111111111111111111111-helper";
        };
        artifactLocators = {};
      }
    ];
    operatorModules = [{test.operator = true;}];
    runtimeModules = [{test.binding = true;}];
  };
in
  assert evaluated.config.test
  == {
    base = true;
    binding = true;
    operator = true;
    package = true;
    provider = "1.0.0:/nix/store/00000000000000000000000000000000-provider:/nix/store/11111111111111111111111111111111-helper";
  }; true
