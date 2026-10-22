##! Checks image manager addresses against the actual enabled producer contracts.
let
  lib = import ../../lib {system = "x86_64-linux";};
  evaluate = settings:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ({config, ...}: {
          aos.services.producer = {
            enable = true;
            lifecycle = {
              description = "Image address producer";
              execution_model = "oneshot";
              start = [
                {
                  executable = {
                    path = "/nix/store/fixture/bin/producer";
                    arguments = [];
                  };
                  ignore_failure = false;
                }
              ];
            };
            manager_identity = {
              name = "declared-producer";
              aliases = [];
            };
          };
          aos.abilities.network.operations.ready.effects.link.input.required = true;
          aos.abilities.configuration.operations.file.effects.policy.input = {
            path = "/etc/declared-policy.conf";
            content = "literal policy\n";
          };
          aos.abilities.identity.operations.group.effects.account.input.name = "declared-account";
          aos.abilities.identity.operations.principal.effects.account.input.name = "declared-account";
          aos.services.consumer = {
            enable = true;
            bootstrap = true;
            lifecycle = {
              description = "Image address consumer";
              execution_model = "oneshot";
              start = [
                {
                  executable = {
                    path = "/nix/store/fixture/bin/consumer";
                    arguments = [config.aos.abilities.configuration.operations.file.effects.policy.outputs.path];
                  };
                  ignore_failure = false;
                }
              ];
            };
            dependencies = {
              after = [config.aos.abilities.serviceManagement.operations.realize.effects.producer.outputs.resource];
              prerequisites = [config.aos.abilities.configuration.operations.file.effects.policy.outputs.resource];
            };
          };
        })
        settings
      ];
    };
  original = evaluate {};
  projected = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit lib;
    inherit (original) config;
    pkgs = {};
  };
  service = evaluation: evaluation.config.aos.abilities.serviceManagement.operations.realize.effects.producer;
  network = evaluation: evaluation.config.aos.abilities.network.operations.ready.effects.link;
  project = evaluation:
    import ../../pkgs/system/_systemd-abilities/bootstrap-resource-reference.nix {
      inherit lib;
      inherit (evaluation) config;
    };
  rejects = evaluation: reference: !(builtins.tryEval (builtins.deepSeq ((project evaluation) reference) true)).success;
  altered = change: rejects original (change (service original).outputs.resource);
in {
  literalUnitUnchanged = (project original) "local-fs.target" == "local-fs.target";
  configurationPathUsesDeclaredAddress = (builtins.head projected.consumer.lifecycle.start).executable.arguments == ["/etc/declared-policy.conf"];
  runtimePrerequisitesStayDeferred = projected.consumer.dependencies.prerequisites == original.config.aos.services.consumer.dependencies.prerequisites;
  accountNamesUseDeclaredAddresses =
    builtins.all (operation:
      (project original) original.config.aos.abilities.identity.operations.${operation}.effects.account.outputs.name == "declared-account") ["group" "principal"];
  fileResourceCannotSubstituteForPath = rejects original original.config.aos.abilities.configuration.operations.file.effects.policy.outputs.resource;
  serviceUsesDeclaredManagerIdentity = ((project original) (service original).outputs.resource).image_service_identity.manager_identity.name == "declared-producer";
  requiredNetworkUsesManagerAddress = (project original) (network original).outputs.resource == "systemd-networkd.service";
  optionalNetworkUsesBootTarget = let
    optional = evaluate {aos.abilities.network.operations.ready.effects.link.input.required = lib.mkForce false;};
  in
    (project optional) (network optional).outputs.resource == "sysinit.target";
  producerNamespaceCannotBeSubstituted = altered (reference: reference // {identity = ["foreign"] ++ lib.drop 1 reference.identity;});
  wrongOutputRejected = altered (reference: reference // {output = "path";});
  wrongSchemaRejected = altered (reference: reference // {schema = {kind = "bool";};});
  absentProducerRejected = altered (reference: reference // {identity = lib.init reference.identity ++ ["absent"];});
  unsupportedOperationRejected = altered (reference: reference // {identity = lib.init (lib.init reference.identity) ++ ["resourceGroup" "producer"];});
  malformedReferenceRejected = rejects original {identity = [];};
  disabledProducerRejected = let
    disabled = evaluate {aos.abilities.serviceManagement.operations.realize.effects.producer.enable = lib.mkForce false;};
  in
    rejects disabled (service original).outputs.resource;
}
