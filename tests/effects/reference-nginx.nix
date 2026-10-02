##! Native reference bindings retain exact service and endpoint dependencies.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifacts = import ../../lib/packages/artifacts.nix {};
  payload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = payload name;
    outputs.out = payload name;
    mainProgram = "aos-reference-binding";
  };
  record = name: source: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name;
      dependencies = {};
    };
  };
  source = ../abilities/reference-nginx/modules;
  evaluated = lib.evalPackageModules {
    scope = ["test" "reference-nginx"];
    packageModules = [
      (record "service-management" ../../pkgs/system/_service-management)
      (record "reference-runtime" (source + /runtime-services))
      (record "reference-consumer" (source + /consumer))
      (record "reference-backend-registry" (source + /backend-registry))
      (record "reference-backend-consumer" (source + /backend-consumer))
    ];
    operatorModules = [
      ({config, ...}: {
        aos.abilities.serviceManagement.operations.realize.handler.program = artifacts.value ((artifact "systemd") // {mainProgram = "aos-service-handler";});
        aos.referenceHttpBackend = {
          enable = true;
          endpoints.app-a = {
            address = "127.0.0.1";
            port = 19001;
            transport = "tcp";
          };
        };
        aos.referenceNginxConsumers.main = {
          enable = true;
          service = config.aos.abilities.serviceManagement.operations.realize.effects."runtime-services.nginx-main".outputs.resource;
        };
        aos.referenceBackendConsumers.main = {
          enable = true;
          service = config.aos.abilities.serviceManagement.operations.realize.effects."runtime-services.nginx-main".outputs.resource;
          endpoints = config.aos.abilities.referenceHttpBackend.operations.publish.effects.registry.outputs.endpoints;
        };
      })
    ];
  };
  nodes = builtins.attrValues evaluated.deployment.graph.nodes;
  node = ability: operation: name: builtins.head (builtins.filter (value: builtins.elem ability value.identity && builtins.elem operation value.identity && builtins.elem name value.identity) nodes);
  setup = node "serviceManagement" "realize" "runtime-services.setup";
  service = node "serviceManagement" "realize" "runtime-services.nginx-main";
  foreign = node "serviceManagement" "realize" "runtime-services.aos-matrix-foreign";
  consumer = node "referenceNginx" "bind" "main";
  backendConsumer = node "referenceHttpBackend" "bind" "main";
  registry = node "referenceHttpBackend" "publish" "registry";
  id = value: builtins.hashString "sha256" (builtins.toJSON value.identity);
  rejectsEndpoints = endpoints:
    !(builtins.tryEval (builtins.deepSeq
      (lib.evalPackageModules {
        scope = ["test" "invalid-reference-endpoints"];
        packageModules = [(record "reference-backend-registry" (source + /backend-registry))];
        operatorModules = [
          {
            aos.referenceHttpBackend = {
              enable = true;
              inherit endpoints;
            };
          }
        ];
      }).deployment.graph
      true)).success;
in {
  retainedServices = assert builtins.length nodes == 13; true;
  setupReadiness = assert service.dependencies == [(id setup)]; true;
  checkedServiceBinding = assert consumer.dependencies == [(id service)]; assert consumer.input.service.identity == service.identity; true;
  checkedBackendBinding = assert builtins.sort builtins.lessThan backendConsumer.dependencies == builtins.sort builtins.lessThan [(id service) (id registry)]; true;
  typedEndpointPublication = assert registry.input.endpoints.app-a.port == 19001; assert registry.results.endpoints.kind == "nullable"; true;
  nativeHandlerArtifacts = assert consumer.handler.executable == "${(artifact "reference-consumer").path}/bin/aos-reference-binding"; true;
  foreignServiceIsolation = assert !(builtins.elem (id consumer) foreign.dependencies); assert foreign.input.manager_identity.name == "aos-matrix-foreign"; true;
  nativeReload = assert (builtins.head service.input.reload.commands).executable.arguments == ["nginx-main"]; assert service.input.lifecycle.configuration_change_action == "reload"; true;
  rejectsInvalidEndpointSlots = assert rejectsEndpoints {
    "foreign/slot" = {
      address = "127.0.0.1";
      port = 19001;
      transport = "tcp";
    };
  }; true;
  rejectsPrivilegedBackendPorts = assert rejectsEndpoints {
    app-a = {
      address = "127.0.0.1";
      port = 80;
      transport = "tcp";
    };
  }; true;
}
