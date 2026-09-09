##! tests/abilities/interface.nix - Canonical interface-document fixture.
{abilities}: let
  inherit (abilities) schemas;

  guarantee = abilities.guarantee {
    name = "aos.guarantee.readiness";
    version = 1;
    descriptor = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
  };

  interface = abilities.define {
    interface = "aos.test.echo";
    abi = 1;
    requestSchema = schemas.record {
      fields = {
        enabled = schemas.boolean;
        label = schemas.string {
          maxLength = 64;
          syntax = null;
        };
      };
      optional = ["label"];
    };
    outputs = {
      endpoint = {
        schema = schemas.resourceReference;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
    };
    methods = {
      observe = {
        operationFamily = {kind = "observe-readiness";};
        parameters = schemas.record {
          fields = {};
          optional = [];
        };
        targetResource = "aos.test.echo";
        outputs = {
          ready = {
            schema = schemas.boolean;
            phase = "observation";
            visibility = "protected";
            lifetime = "attempt";
          };
        };
        permittedOperations = ["observe"];
        guarantees = [guarantee];
        outcome = {
          completionEvidence = schemas.boolean;
          observationEvidence = schemas.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
    };
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = true;
      retainsPersistentByDefault = true;
      persistentDeleteMethod = null;
    };
    guarantees = [guarantee];
    aggregation = {
      scope = "provider-instance";
      key = "authorized-slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "echo";
    };
    requires = {};
    ownsResourceKinds = ["aos.resource.service"];
    handler = "echo-handler";
    provide = {instance, ...}: {
      requests = {};
      outputs.endpoint = abilities.resourceReference {
        interface = {
          name = "aos.test.echo";
          abi = 1;
          descriptor = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        };
        resource = {
          provider = instance.id;
          key = "endpoint";
        };
        operations = ["observe"];
        lifetime = "instance";
      };
      resources = [];
      conditionalRequirements = [];
    };
  };
in
  abilities.interfaceDocument ["abilities-v1"] interface
