##! Checks native Hub service policy and typed identity/storage/credential ordering.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifactLib = import ../../lib/packages/artifacts.nix {};
  artifact = name: {
    inherit name;
    version = "1";
    path = "/nix/store/00000000000000000000000000000000-${name}";
    outputs.out = "/nix/store/00000000000000000000000000000000-${name}";
    mainProgram = name;
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
  evaluated = lib.evalPackageModules {
    scope = ["test" "native-hub"];
    packageModules = [
      (record "service-management" ../../pkgs/system/_service-management)
      (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider)
      (record "aos-hub" ../../pkgs/tools/aos-hub/_aos-hub)
    ];
    operatorModules = [
      {
        aos.registry-hub = {
          enable = true;
          credentials = {
            routeReservationKeys = "hub-route-keys";
            domainProbeSignerManifest = "hub-probe-manifest";
          };
        };
        aos.abilities = builtins.listToAttrs (builtins.map (ability: {
            name = ability.name;
            value.operations = builtins.listToAttrs (builtins.map (operation: {
                name = operation;
                value.handler.program = artifactLib.value (artifact "${ability.name}-handler");
              })
              ability.operations);
          }) [
            {
              name = "serviceManagement";
              operations = ["realize"];
            }
            {
              name = "identity";
              operations = ["group" "principal"];
            }
            {
              name = "network";
              operations = ["ready"];
            }
            {
              name = "credential";
              operations = ["deliver"];
            }
          ]);
      }
    ];
  };
  nodes = builtins.attrValues evaluated.config.aos.activation.graph.nodes;
  service = builtins.head (builtins.filter (node: node.input ? service && node.input.service == "hub") nodes);
  allocations = builtins.filter (node: node.input ? path && node.input.path == "/var/lib/aos-hub") nodes;
  credentials = builtins.filter (node: node.identity == ["test" "native-hub" "aos-hub" "credential" "deliver" "hub-routeReservationKeys"] || node.identity == ["test" "native-hub" "aos-hub" "credential" "deliver" "hub-domainProbeSignerManifest"]) nodes;
  checks = {
    hubUsesNativeService = evaluated.config.aos.services.hub.enable && service.owner == "service-management";
    hubRetainsPersistentStorage = builtins.length allocations == 1 && (builtins.head allocations).lifetime == "persistent";
    hubUsesExactPayload = (builtins.head service.input.lifecycle.start).executable.path == "/nix/store/00000000000000000000000000000000-aos-hub/bin/aos-hub";
    hubKeepsPrivateIdentity = service.input.isolation.privilege == "unprivileged" && service.input.identity.principal._type == "aos-effect-output";
    hubHasTypedCredentials = builtins.length credentials == 2 && builtins.length service.input.credentials.views == 2;
    hubOrdersPrerequisites = builtins.length service.dependencies >= 4;
  };
in
  assert builtins.all (value: value) (builtins.attrValues checks); checks
