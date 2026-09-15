##! Verifies canonical provider-neutral Kubernetes object-management contracts.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kubernetes = lib.abilities.interfaces.kubernetesObjectManagement;
  object = {
    key = "fixture";
    api_version = "testing.aos/v1";
    kind = "Fixture";
    namespace = null;
    name = "fixture";
    content = builtins.toJSON {
      apiVersion = "testing.aos/v1";
      kind = "Fixture";
      metadata.name = "fixture";
      spec.enabled = true;
    };
  };
  contribution = serviceManagement.forProducer {
    consumerInstance = "integration";
    key = "objects";
    interface = kubernetes.contribution;
    parameters = {
      objects = [object];
      prerequisites = [];
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities.environment = {
          authority = "test";
          key = "kubernetes-object-management-core";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "object-consumer";
        version = "1.0.0";
        module.config.aos.abilities = lib.mkMerge [
          {instances.integration = {};}
          contribution
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  request = abilities.requests."object-consumer:objects";
in
  assert abilities.interfaces.kubernetes-object-set.name == "aos.kubernetes.object-set";
  assert abilities.interfaces.kubernetes-objects.name == "aos.kubernetes.objects";
  assert kubernetes.controller.declaration.lifecycle.releasesEphemeralOnDisable;
  assert !kubernetes.contribution.declaration.lifecycle.releasesEphemeralOnDisable;
  assert kubernetes.controller.declaration.methods.release.semantics
  == {
    requiredTargetAccess = "exclusive-write";
    stopsProvider = true;
  };
  assert builtins.attrNames kubernetes.controller.declaration.outputs
  == [
    "cluster-readiness-resource"
    "kubeconfig-resource"
    "readiness-resource"
  ];
  assert request.parameters.objects == [object];
  assert request.parameters.prerequisites == [];
  assert abilities.requirementTemplates."object-consumer:kubernetes-objects".interface
  == kubernetes.contribution.identity.name; true
