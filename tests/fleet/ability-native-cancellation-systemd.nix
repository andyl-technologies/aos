##! Runs host service and account durability flights through native admission.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  reference = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
    effectQualification = true;
  };
  controlled = import ./_native-reference-service-configuration.nix {
    inherit (pkgs) bash coreutils;
  };
  fixture = reference // {
    runtimeModules = reference.runtimeModules ++ [controlled];
    qualificationSetupBody = lib.replaceStrings
      ["imports = [ ${./_reference-native-configuration.nix} ];"]
      [''imports = [ ${./_reference-native-configuration.nix}
        (import ${./_native-reference-service-configuration.nix} {
          bash = ${pkgs.bash}; coreutils = ${pkgs.coreutils};
        }) ];'']
      reference.qualificationSetupBody;
  };
in
  import ./_native-operation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-cancellation-systemd";
    requiredOperations = [
      {ability = "serviceManagement"; name = "realize";}
      {ability = "identity"; name = "group";}
      {ability = "identity"; name = "principal";}
      {ability = "identity"; name = "membership";}
    ];
    scenarioIds = [
      "interrupt-after-durable-intent"
      "lose-external-result"
      "interrupt-after-durable-outcome"
    ];
    domainScript = ''
      PYTHON = "${pkgs.python3}/bin/python3"
      SERVICE_FLIGHTS = types.ModuleType("native_reference_service_flights")
      SERVICE_FLIGHTS.__dict__.update(globals())
      exec(compile(${builtins.toJSON (builtins.readFile ./native-reference-service-flights.py)},
          "native-reference-service-flights.py", "exec"), SERVICE_FLIGHTS.__dict__)
      original = write_reference_worktree("/var/lib/aos/native-service-admission", extra_module=OBSERVER_HOST_MODULE)
      apply_reference(original, "native-service-admission")
      selected_graph = current_reference_graph()
      cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      adapters = {adapter["adapter"]: adapter for adapter in MATRIX_SPEC["surface"]["adapters"]}
      for cell_id in COHORT_CELLS:
          cell = cells[cell_id]
          adapter = adapters[cell["adapter"]]
          if not SERVICE_FLIGHTS.supports(cell, adapter, selected_graph):
              raise RuntimeError("selected service/account cell has no concrete native proof")
          SERVICE_FLIGHTS.run_cell(cell, adapter, selected_graph)
    '';
  }
