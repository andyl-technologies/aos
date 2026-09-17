##! Fixed-point checks for the package-owned Ability Crucible service.
{
  lib,
  pkgs,
}: let
  packageModule = {
    name = "aos-ability-crucible";
    version = pkgs.aos-ability-crucible.version;
    module = pkgs.aos-ability-crucible.module + "/module.nix";
    outputs = {
      self = builtins.toString pkgs.aos-ability-crucible;
      dependencies = {};
    };
  };
  evaluate = enabled:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "ability-crucible";
            stage = "host";
          };
          aos.services.abilityCrucible.enable = enabled;
        }
      ];
      packageModules = [packageModule];
    };
  disabled = evaluate false;
  enabled = evaluate true;
  abilities = enabled.config.aos.abilities;
  requests = abilities.requests;
  endpoint = requests."aos-ability-crucible:observer-endpoint";
  lifecycle = requests."aos-ability-crucible:adapter-lifecycle".parameters;
  command = builtins.head lifecycle.start;
  configuration = requests."aos-ability-crucible:configuration-file".parameters;
  endpointDeclaration = abilities.interfaces."aos-ability-crucible:execution-observer-endpoint";
  provide = abilities.implementations."aos-ability-crucible:execution-observer-endpoint".provide;
  outputReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  runtimePath = "/run/aos/ability-crucible/controller.sock";
  providerInstance =
    enabled.config.aos.abilities.instanceIdentities."aos-ability-crucible:ability-crucible";
  provided = provide {
    instance.id = providerInstance;
    requests."aos-ability-crucible:observer-endpoint" = endpoint;
    bindings.endpoint = {
      request = "aos-ability-crucible:observer-endpoint";
      slot = "observer";
    };
  };
  composed = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "ability-crucible";
            stage = "host";
          };
          bindings."test:observer-endpoint" = {
            request = "aos-ability-crucible:observer-endpoint";
            implementation = "aos-ability-crucible:execution-observer-endpoint";
            providerInstance = "aos-ability-crucible:ability-crucible";
            slot = "observer";
          };
          executionObserver = {
            request = "aos-ability-crucible:observer-endpoint";
            resourceOutput = "retained-resource";
            socketOutput = "socket-path";
          };
        };
      }
    ];
    packageModules = [packageModule];
  };
  composedAbilities = composed.config.aos.abilities;
  resolvedResources = builtins.attrValues composedAbilities.resolvedResources;
  endpointReference = {
    _type = "aos-resource-reference";
    interface = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration endpointDeclaration
    );
    resource = {
      provider = providerInstance;
      key = "observer";
    };
    operations = ["observe"];
    lifetime = "instance";
  };
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
  assert abilities.instances ? "aos-ability-crucible:ability-crucible";
  assert endpoint.parameters == {endpoint = "default";};
  assert endpointDeclaration.lifecycle.persistentDeleteMethod == null;
  assert endpointDeclaration.methods.observe.semantics
  == {
    requiredTargetAccess = "read";
    stopsProvider = false;
  };
  assert endpointDeclaration.outputs.retained-resource.description == "References the endpoint and authorizes only observation.";
  assert endpointDeclaration.outputs.retained-resource.lifetime == "instance";
  assert endpointDeclaration.outputs.retained-resource.phase == "planning";
  assert endpointDeclaration.outputs.retained-resource.schema._abilitySchema == lib.abilities.schemas.resourceReference;
  assert endpointDeclaration.outputs.retained-resource.visibility == "protected";
  assert endpointDeclaration.outputs.socket-path.schema._abilitySchema == lib.abilities.types.executionPath._abilitySchema;
  assert provided.outputs."aos-ability-crucible:observer-endpoint"
  == {
    retained-resource = endpointReference;
    socket-path = runtimePath;
  };
  assert provided.resourceFragments == {};
  assert composedAbilities.resolvedExecutionObserver
  == {
    request = "aos-ability-crucible:observer-endpoint";
    resource = builtins.removeAttrs endpointReference ["_type"];
    socket = runtimePath;
  };
  assert builtins.length resolvedResources == 1;
  assert (builtins.head resolvedResources).controller == null;
  assert command
  == {
    executable = {
      artifact = lib.abilities.packageOutput {package = "aos-ability-crucible";};
      entry_point = "bin/aos-ability-crucible";
      arguments = [
        "--config"
        (outputReference "aos-ability-crucible:configuration-file" "planned-path")
      ];
    };
    ignore_failure = false;
  };
  assert lifecycle.restart == "on-failure";
  assert lifecycle.restart_delay_millis == 1000;
  assert lifecycle.start_timeout_millis == 30000;
  assert lifecycle.post_start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "aos-ability-crucible";};
        entry_point = "bin/aos-ability-crucible";
        arguments = ["--wait-ready" runtimePath];
      };
      ignore_failure = false;
    }
  ];
  assert configuration.mode == "0400";
  assert configuration.source.fragments
  == [
    {
      kind = "literal";
      text = ''{"required_instruction_abi":1,"required_marker_kinds":["assertion","coverage","event","lifecycle"],"schema":"aos.ability-crucible-adapter/v1","socket":"'';
    }
    {
      kind = "execution-path";
      value = runtimePath;
    }
    {
      kind = "literal";
      text = ''"}'';
    }
  ];
  assert requests."aos-ability-crucible:adapter-dependencies".parameters.prerequisites
  == [
    (outputReference "aos-ability-crucible:configuration-file" "retained-resource")
    (outputReference "aos-ability-crucible:runtime-storage" "retained-resource")
  ];
  assert requests."aos-ability-crucible:adapter-supervision".parameters.notification_access == "none";
  assert requests."aos-ability-crucible:adapter-readiness".parameters.mechanism == "process-running";
  assert requests."aos-ability-crucible:adapter-readiness".parameters.timeout_millis == lifecycle.start_timeout_millis;
  assert requests."aos-ability-crucible:adapter-identity".parameters.file_creation_mask == "0077";
  assert requests."aos-ability-crucible:adapter-isolation".parameters.filesystem == "read-only-system";
  assert portableOptionTree enabled.options.aos.services.abilityCrucible;
  assert !(enabled.config ? systemd); true
