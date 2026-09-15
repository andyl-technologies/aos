##! Fixed-point checks for the package-owned fleet observation controller.
{
  lib,
  pkgs,
}: let
  package = pkgs.aos-ability-boundary-observer;
  cruciblePackage = pkgs.aos-ability-crucible;
  packageModule = name: package: {
    inherit name;
    version = package.version;
    module = package.module + "/module.nix";
    outputs = {
      self = builtins.toString package;
      dependencies = {};
    };
  };
  evaluate = module:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "boundary-observer";
            stage = "host";
          };
          aos.services.abilityCrucible.enable = false;
        }
        module
      ];
      packageModules = [
        (packageModule "aos-ability-boundary-observer" package)
        (packageModule "aos-ability-crucible" cruciblePackage)
      ];
    };
  managed = evaluate {};
  external = evaluate {
    aos.tests.executionObserver.mode = "external-test-mount";
  };
  forwarded = evaluate {
    aos.tests.executionObserver.forwardToSelectedEndpoint = true;
  };
  disabled = evaluate {
    aos.tests.executionObserver.enable = false;
  };
  abilities = managed.config.aos.abilities;
  requests = abilities.requests;
  endpoint = requests."aos-ability-boundary-observer:endpoint";
  lifecycle = requests."aos-ability-boundary-observer:controller-lifecycle".parameters;
  socketActivation = requests."aos-ability-boundary-observer:controller-socket_activation".parameters;
  implementation = abilities.implementations."aos-ability-boundary-observer:execution-observer-endpoint";
  providerInstance = abilities.instanceIdentities."aos-ability-boundary-observer:boundary-observer";
  provide = implementation.provide;
  provided = provide {
    instance.id = providerInstance;
    requests."aos-ability-boundary-observer:endpoint" = endpoint;
    bindings.observer = {
      request = "aos-ability-boundary-observer:endpoint";
      slot = "observer";
    };
  };
  outputReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  forwardedAbilities = forwarded.config.aos.abilities;
  forwardReference = outputReference "aos-ability-boundary-observer:forward-endpoint";
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert disabled.config.aos.abilities.requests == {};
  assert builtins.attrNames disabled.config.aos.abilities.interfaces == builtins.attrNames abilities.interfaces;
  assert builtins.attrNames disabled.config.aos.abilities.implementations == builtins.attrNames abilities.implementations;
  assert endpoint.parameters
  == {
    hosting = "managed-service";
    service_resource = outputReference "aos-ability-boundary-observer:controller-lifecycle" "service-resource";
    socket_path = "/run/aos-instrumentation/controller.sock";
  };
  assert external.config.aos.abilities.requests."aos-ability-boundary-observer:endpoint".parameters
  == {
    hosting = "external-test-mount";
    service_resource = null;
    socket_path = "/run/aos-instrumentation/controller.sock";
  };
  assert !(external.config.aos.abilities.requests ? "aos-ability-boundary-observer:controller-lifecycle");
  assert forwardedAbilities.requirementTemplates."aos-ability-boundary-observer:forward-endpoint"
  == {
    description = "Discovers the selected protected execution observer endpoint.";
    interface = "aos.execution.observation-endpoint";
    abi = 1;
    descriptor = null;
    methods = ["observe"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  assert forwardedAbilities.requests."aos-ability-boundary-observer:forward-endpoint".parameters
  == {endpoint = "default";};
  assert forwardedAbilities.requests."aos-ability-boundary-observer:controller-dependencies".parameters.after
  == [(forwardReference "retained-resource")];
  assert forwardedAbilities.requests."aos-ability-boundary-observer:controller-dependencies".parameters.requires
  == [(forwardReference "retained-resource")];
  assert forwardedAbilities.requests."aos-ability-boundary-observer:controller-environment".parameters.variables.AOS_ABILITY_FORWARD_SOCKET
  == forwardReference "socket-path";
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-ability-boundary-observer";};
        entry_point = "bin/aos-ability-boundary-controller";
        arguments = ["serve" "--socket" "/run/aos-instrumentation/controller.sock"];
      };
      ignore_failure = false;
    }
  ];
  assert lifecycle.restart == "on-failure";
  assert lifecycle.restart_delay_millis == 1000;
  assert socketActivation.sockets
  == [
    {
      name = "observer";
      manager_name = "aos-ability-boundary-controller";
      enabled = true;
      endpoints = [
        {
          kind = "unix";
          path = "/run/aos-instrumentation/controller.sock";
        }
      ];
      mode = "0600";
      remove_on_stop = true;
      prerequisites = [
        (outputReference "aos-ability-boundary-observer:runtime-storage" "retained-resource")
      ];
    }
  ];
  assert implementation.artifact == lib.abilities.packageOutput {package = "aos-ability-boundary-observer";};
  assert implementation.providerModule
  == {
    artifact = lib.abilities.packageOutput {package = "aos-ability-boundary-observer";};
    path = "share/aos/providers/ability-boundary-observer-endpoint.nix";
  };
  assert provided.resourceFragments == {};
  assert provided.outputs."aos-ability-boundary-observer:endpoint".socket-path == "/run/aos-instrumentation/controller.sock";
  assert provided.outputs."aos-ability-boundary-observer:endpoint".retained-resource.operations == ["observe"];
  assert portableOptionTree managed.options.aos.tests.executionObserver;
  assert !(managed.config ? systemd); true
