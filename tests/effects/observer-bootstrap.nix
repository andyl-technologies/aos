##! Verifies pre-dispatch observer seeding and forwarding order.
let
  lib = import ../../lib {system = "x86_64-linux";};
  service = name: {
    service = name;
    enable = true;
    activationOwner = "manager";
    lifecycle.pre_start = [];
    dependencies = {
      after = [];
      requires = [];
    };
  };
  config.aos = {
    execution.observer.socketPath = "/run/aos-instrumentation/controller.sock";
    abilityCrucible = {
      enable = true;
      activationOwner = "manager";
      bootstrap = {
        serviceKey = "ability-crucible.adapter";
        directories = [
          {
            path = "/run/aos/ability-crucible";
            mode = "0700";
            owner = "root";
            group = "root";
          }
        ];
        files = [
          {
            path = "/run/aos/ability-crucible.json";
            content = "{}";
            mode = "0400";
          }
        ];
      };
    };
    tests.executionObserver = {
      enable = true;
      mode = "managed-service";
      activationOwner = "manager";
      forwardSocketPath = "/run/aos/ability-crucible/controller.sock";
      bootstrap = {
        serviceKey = "boundary-observer.controller";
        directories = [];
        files = [];
      };
    };
    services = {
      "ability-crucible.adapter" = service "aos-ability-crucible";
      "boundary-observer.controller" = service "aos-ability-boundary-controller";
      controller = (service "aos-ability-host-controller") // {activationOwner = "image";};
      daemon = (service "example") // {activationOwner = "ability";};
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    specialArgs.dependencies = {
      coreutils = toString ((import ./_fixture-payload.nix) "coreutils");
      bash = toString ((import ./_fixture-payload.nix) "bash");
    };
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/module.nix
      ../../pkgs/system/_aos-host-policy/observer-bootstrap.nix
      ({lib, ...}: {
        options.aos.abilityCrucible = lib.mkOption {type = lib.types.attrs;};
        options.aos.tests.executionObserver = lib.mkOption {type = lib.types.attrs;};
        config.aos = builtins.removeAttrs config.aos ["services"];
      })
      {
        aos.services = {
          "ability-crucible.adapter" = {
            enable = false;
            activationOwner = "manager";
            service = "aos-ability-crucible";
          };
          "boundary-observer.controller" = {
            enable = false;
            activationOwner = "manager";
            service = "aos-ability-boundary-controller";
          };
          controller = {
            enable = false;
            activationOwner = "image";
            service = "aos-ability-host-controller";
          };
        };
      }
    ];
  };
  projected = import ../../pkgs/system/_systemd-abilities/observer-bootstrap.nix {
    config = evaluated.config;
    inherit lib;
    pkgs = {};
  };
in
  assert builtins.length projected."observer.bootstrap".lifecycle.start == 2;
  assert evaluated.config.aos.services."ability-crucible.adapter".dependencies.requires == ["aos-native-observer-bootstrap.service"];
  assert projected."observer.bootstrap".isolation.filesystem == "host";
  assert lib.sort builtins.lessThan evaluated.config.aos.services."boundary-observer.controller".dependencies.requires == ["aos-ability-boundary-controller.socket" "aos-ability-crucible.service" "aos-native-observer-bootstrap.service"];
  assert evaluated.config.aos.services."boot-preparations.aos-ability-host-controller".dependencies.requires == ["aos-ability-crucible.service" "aos-ability-boundary-controller.service"];
  assert !(projected ? daemon); true
