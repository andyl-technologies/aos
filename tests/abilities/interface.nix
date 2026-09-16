##! tests/abilities/interface.nix - Canonical interface-document fixture.
{abilities}: let
  inherit (abilities) types;

  guarantee = abilities.guarantee {
    name = "aos.guarantee.readiness";
    version = 1;
    semantics = "the provider reports readiness for the requested revision";
    description = "Reports readiness for the requested revision.";
  };

  interface = abilities.declareInterface {
    name = "aos.test.echo";
    abi = 1;
    description = "Ability interface aos.test.echo.";
    requestType = types.record {
      fields = {
        enabled = types.boolean;
        label = types.string {
          maxLength = 64;
          syntax = null;
        };
      };
      optional = ["label"];
    };
    configurationType = null;
    outputs = {
      endpoint = {
        description = "Identifies the endpoint resource produced by the test interface.";
        schema = types.resourceReference;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
    };
    methods = {
      observe = {
        description = "Observes the current test interface state.";
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
            description = "Reports whether the test resource is ready.";
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
    requiredFeatures = ["abilities-v1"];
  };
in
  abilities.interfaceDocumentFromDeclaration interface
