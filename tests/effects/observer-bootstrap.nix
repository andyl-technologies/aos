##! Verifies pre-dispatch observer seeding and forwarding order.
let
  lib = import ../../lib {system = "x86_64-linux";};
  service = name: {
    service = name;
    enable = true;
    activationOwner = "manager";
    lifecycle = {
      description = "Bootstrap ${name}";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${import ./_fixture-payload.nix "observer"}/bin/controller";
            arguments = [];
          };
          ignore_failure = false;
        }
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "never";
      restart_delay_millis = 0;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
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
  evaluate = controllerKey:
    lib.evalModules {
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
          options.aos.boot = {
            stage = lib.mkOption {
              type = lib.types.str;
              default = "host";
            };
            hostActivatorService = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = controllerKey;
            };
            substrateServices.handoffEnabled = lib.mkOption {
              type = lib.types.bool;
              default = controllerKey != null;
            };
          };
          options.aos.abilityCrucible = lib.mkOption {type = lib.types.attrs;};
          options.aos.tests.executionObserver = lib.mkOption {type = lib.types.attrs;};
          config.aos = builtins.removeAttrs config.aos ["services"];
        })
        {
          aos.services =
            {
              "early.daemon" =
                (service "early")
                // {
                  bootstrap = true;
                  activationOwner = "ability";
                };
              "early.disabled" =
                (service "disabled")
                // {
                  bootstrap = true;
                  enable = false;
                  activationOwner = "ability";
                };
              daemon = (service "example") // {activationOwner = "ability";};
              "ability-crucible.adapter" = (service "aos-ability-crucible") // {autoStart = false;};
              "boundary-observer.controller" = (service "aos-ability-boundary-controller") // {autoStart = false;};
            }
            // lib.optionalAttrs (controllerKey != null) {
              ${controllerKey} =
                (service (
                  if controllerKey == "control-plane.aos-activate"
                  then "aos-activate"
                  else "aos-ability-host-controller"
                ))
                // {activationOwner = "image";};
            };
        }
      ];
    };
  evaluated = evaluate "boot-preparations.aos-ability-host-controller";
  canonical = evaluate "control-plane.aos-activate";
  custom = evaluate "custom.activator";
  absent = evaluate null;
  projected = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
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
  assert canonical.config.aos.services."control-plane.aos-activate".dependencies.requires == ["aos-ability-crucible.service" "aos-ability-boundary-controller.service"];
  assert custom.config.aos.services."custom.activator".dependencies.requires == ["aos-ability-crucible.service" "aos-ability-boundary-controller.service"];
  assert !(custom.config.aos.services ? "control-plane.aos-activate");
  assert !(custom.config.aos.services ? "boot-preparations.aos-ability-host-controller");
  assert !(canonical.config.aos.services ? "boot-preparations.aos-ability-host-controller");
  assert !(evaluated.config.aos.services ? "control-plane.aos-activate");
  assert !(absent.config.aos.services ? "control-plane.aos-activate");
  assert !(absent.config.aos.services ? "boot-preparations.aos-ability-host-controller");
  assert projected."early.daemon".activation_owner == "ability";
  assert builtins.all (name:
    projected.${name}
    == evaluated.config.aos.abilities.serviceManagement.operations.realize.effects.${name}.input
    && projected.${name}.activation_owner == "manager"
    && projected.${name}.enabled
    && !projected.${name}.auto_start)
  ["ability-crucible.adapter" "boundary-observer.controller"];
  assert !(projected ? "early.disabled");
  assert !(projected ? daemon); true
