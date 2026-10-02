##! Native durable provisioning primitives and the authorized evaluation contract.
{
  lib,
  package,
  dependencies,
  ...
}: let
  types = import ./types.nix {inherit lib;};
  field = type: description: lib.mkOption {inherit type description;};
  markerProgram = package // {meta = (package.meta or {}) // {mainProgram = "aos-storage-provisioning-marker-observer";};};
  commitProgram = package // {meta = (package.meta or {}) // {mainProgram = "aos-storage-provisioning-provider";};};
  evaluationRuntime = dependencies.aos.packageRuntime;
  evaluationProgram = evaluationRuntime // {meta = (evaluationRuntime.meta or {}) // {mainProgram = "aos-provisioning-configuration-evaluator";};};
in {
  imports = [./configuration.nix ./prepare.nix ./topology.nix];
  aos.abilities = {
    provisioningMarker.operations.observe = {
      input.options = {
        root_device = field lib.types.str "Root filesystem partition identifying the target disk.";
        lsblk = field lib.types.str "Exact retained block-device inspection executable.";
      };
      result.options.marker = field types.marker "Typed durable marker observation.";
      handler.program = markerProgram;
    };
    provisioningEvaluation.operations.evaluate = {
      handler.program = evaluationProgram;
      input.options = {
        evaluation_context = field (lib.types.deferred lib.types.str) "Admitted immutable pre-evaluation source descriptor.";
        request = field types.request "Fixed one-time provisioning intent.";
        authorized_input = field (lib.types.deferred lib.types.str) "Committed immutable authorization object path.";
        authorized_input_sha256 = field (lib.types.deferred lib.types.str) "Exact authorized object content digest.";
        marker = field (lib.types.deferred types.marker) "Durable marker observed on the selected disk.";
      };
      result.options = {
        provisioning_plan = field types.plan "Validated plan from the authorized native module fixed point.";
        canonical_plan = field lib.types.str "Canonical bytes of the validated provisioning plan from the same authored sources.";
      };
    };
    storageProvisioning.operations.commit = {
      input.options = {
        request = field types.request "Fixed one-time provisioning intent.";
        plan = field (lib.types.deferred types.plan) "Exact evaluated and validated partition plan.";
        tools = field types.tools "Retained native block-device tools.";
      };
      result.options = {
        source = field (lib.types.enum ["operator" "fallback"]) "Committed configuration source.";
        marker_uuid = field lib.types.str "Verified durable provisioning marker UUID.";
        resource = field lib.types.str "Logical durable transaction resource identity.";
      };
      handler.program = commitProgram;
    };
  };
}
