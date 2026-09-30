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
  controlled = import ../abilities/native-service-qualification/package.nix {
    inherit (pkgs) mkDerivation bash coreutils service-management aos-filesystem-provider;
  };
  interceptor = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.systemd;
    backendExecutable = "bin/aos-systemd-native-resources";
  };
  serviceInterceptor = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.systemd;
    backendExecutable = "bin/aos-service-handler";
    pname = "native-handler-interception-systemd-service";
  };
  dependencyMarker = import ../abilities/native-dependency-barrier/package.nix {
    inherit (pkgs) mkDerivation python3;
  };
  fixture =
    reference
    // {
      scenarioSources = [./_reference-native-configuration.nix ./_native-service-interception.nix ./_native-service-dependency.nix];
      baselineSources = [./_native-service-baseline.nix];
      runtimeModules =
        reference.runtimeModules
        ++ [
          {
            aos.packages = {
              native-service-qualification = {
                package = controlled;
                bundle = true;
              };
              native-handler-interception-systemd = {
                package = interceptor;
                bundle = true;
              };
              native-handler-interception-systemd-service = {
                package = serviceInterceptor;
                bundle = true;
              };
              native-dependency-barrier = {
                package = dependencyMarker;
                bundle = true;
              };
            };
          }
        ];
      extraClosures = reference.extraClosures ++ [controlled controlled.deploymentArtifact interceptor interceptor.deploymentArtifact serviceInterceptor serviceInterceptor.deploymentArtifact dependencyMarker dependencyMarker.deploymentArtifact];
      qualificationExtraClosures = reference.qualificationExtraClosures ++ [controlled controlled.deploymentArtifact interceptor interceptor.deploymentArtifact serviceInterceptor serviceInterceptor.deploymentArtifact dependencyMarker dependencyMarker.deploymentArtifact];
    };
in
  import ./_native-operation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "ability-native-cancellation-systemd";
    requiredOperations = [
      {
        ability = "serviceManagement";
        name = "realize";
      }
      {
        ability = "identity";
        name = "group";
      }
      {
        ability = "identity";
        name = "principal";
      }
      {
        ability = "identity";
        name = "membership";
      }
    ];
    domainScript = ''
      PYTHON = "${pkgs.python3}/bin/python3"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      UMOUNT = "${pkgs.util-linux}/bin/umount"
      SERVICE_RENDERER = "${pkgs.systemd}/bin/aos-service-handler"
      SERVICE_FLIGHTS = types.ModuleType("native_reference_service_flights")
      SERVICE_FLIGHTS.__dict__.update(globals())
      exec(compile(${builtins.toJSON (builtins.readFile ./native-reference-service-flights.py)},
          "native-reference-service-flights.py", "exec"), SERVICE_FLIGHTS.__dict__)
      original = write_reference_worktree("/var/lib/aos/native-service-admission",
          {"aos": {"nativeServiceQualification": {"enabled": {"deadline": False, "deadlineRemove": False}}}},
          extra_module=OBSERVER_HOST_MODULE)
      apply_reference(original, "native-service-admission")
      selected_graph = SELECTED_EVALUATION_GRAPH
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
