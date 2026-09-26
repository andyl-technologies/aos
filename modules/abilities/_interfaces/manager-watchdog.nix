##! Canonical provider-neutral system-manager watchdog interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "manager-watchdog";
  interfaceName = "aos.system.manager-watchdog";
  fields = {
    enabled = types.boolean;
    runtime_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 86400000;
    };
    reboot_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 172800000;
    };
    kexec_timeout_millis = types.integer {
      minimum = 1000;
      maximum = 172800000;
    };
  };
  requestType = types.record {inherit fields;};
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.manager-watchdog-observation/v1"];
      expected = requestType;
      observed = {
        type = types.optional requestType;
        optional = true;
      };
      state = types.enum ["absent" "configured" "divergent" "unknown"];
      manager_incarnation_changed = types.boolean;
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 16;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  observationOutput = phase:
    output phase "attempt" "Reports the exact manager watchdog configuration and reload state." observationType;
  method = name: description: access: stopsProvider: retained: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = requestType;
    targetResource = interfaceName;
    outputs =
      {
        observation = observationOutput (
          if name == "observe"
          then "observation"
          else "runtime"
        );
      }
      // (
        if retained
        then {
          retained-resource =
            output "runtime" "instance" "References the retained manager watchdog configuration." types.resourceReference;
        }
        else {}
      );
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methods = {
    apply = method "apply" "Applies manager watchdog configuration." "exclusive-write" false true;
    observe = method "observe" "Observes exact manager watchdog configuration." "read" false false;
    remove = method "remove" "Removes owned manager watchdog configuration." "exclusive-write" true false;
  };
  lifecycle.persistentDeleteMethod = null;
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Controls a system manager's hardware-watchdog policy without exposing its backend.";
    abi = 1;
    inherit requestType methods lifecycle aggregation;
    outputs = {};
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
  readView = {
    interface = {
      inherit alias interfaceName declaration document identity fields requestType observationType;
      methods = builtins.attrNames methods;
      name = interfaceName;
    };
    declarations.${alias} = declaration;
  };
in {
  name = "managerWatchdog";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
