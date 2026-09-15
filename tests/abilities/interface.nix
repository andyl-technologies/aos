##! tests/abilities/interface.nix - Canonical interface-document fixture.
{abilities}: let
  inherit (abilities) types;

  guarantee = abilities.guarantee {
    name = "aos.guarantee.readiness";
    version = 1;
    semantics = "the provider reports readiness for the requested revision";
    description = "Reports readiness for the requested revision.";
  };

  interface = abilities.define {
    interface = "aos.test.echo";
    abi = 1;
    requestSchema = types.record {
      fields = {
        enabled = types.boolean;
        label = types.string {
          maxLength = 64;
          syntax = null;
        };
      };
      optional = ["label"];
    };
    outputs = {
      endpoint = {
        schema = types.resourceReference;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
    };
    methods = {
      observe = {
        semantics = {
          requiredTargetAccess = "read";
          stopsProvider = false;
        };
        parameters = types.record {
          fields = {};
          optional = [];
        };
        targetResource = "aos.test.echo";
        outputs = {
          ready = {
            schema = types.boolean;
            phase = "observation";
            visibility = "protected";
            lifetime = "attempt";
          };
        };
        permittedOperations = ["observe"];
        guarantees = [guarantee];
        outcome = {
          completionEvidence = types.boolean;
          observationEvidence = types.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
    };
    lifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = false;
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
