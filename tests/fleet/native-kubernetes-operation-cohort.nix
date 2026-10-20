##! Qualifies actual Kubernetes objects and K3s configuration with live oracles.
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
  controlledSource = ./_native-kubernetes-configuration.nix;
  interception = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.k3s-combined;
    backendExecutable = "bin/aos-kubernetes-provider";
  };
  dependencyBarrier = import ../abilities/native-dependency-barrier/package.nix {
    inherit (pkgs) mkDerivation python3;
  };
  predecessorSource = pkgs.writeTextFile {
    name = "native-kubernetes-predecessor";
    destination = "/module.nix";
    text = builtins.readFile ./_native-kubernetes-predecessor.nix;
  };
  fixture =
    reference
    // {
      runtimeModules =
        reference.runtimeModules
        ++ [
          {
            aos.packages.native-dependency-barrier = {
              package = dependencyBarrier;
              bundle = true;
            };
            aos.packages.native-handler-interception-k3s-combined = {
              package = interception;
              bundle = true;
            };
            aos.packages.k3s-combined = {
              package = pkgs.k3s-combined;
              bundle = true;
            };
          }
        ];
      scenarioSources = [./_reference-native-configuration.nix controlledSource];
      # The exact fixture bundle supplies package selection and retained sources
      # before operator worktrees are evaluated by the native profile.
      qualificationSetupBody = "";
      qualificationExtraClosures = reference.qualificationExtraClosures ++ [pkgs.k3s-combined pkgs.k3s-combined.deploymentArtifact pkgs.k3s-combined.documentationArtifact pkgs.kubectl interception dependencyBarrier predecessorSource];
      extraClosures = reference.extraClosures ++ [pkgs.k3s-combined pkgs.kubectl interception dependencyBarrier predecessorSource];
    };
in
  import ./_native-operation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "native-kubernetes-operation-cohort";
    requiredOperations = [
      {
        ability = "kubernetes";
        name = "ensure";
      }
      {
        ability = "k3sConfiguration";
        name = "ensure";
      }
    ];
    guestOracleSource = builtins.readFile ./native-kubernetes-oracle.py;
    domainScript = ''
      PYTHON = "${pkgs.python3}/bin/python3"
      NATIVE_KUBERNETES_PREDECESSOR_SOURCE = "${predecessorSource}/module.nix"
      KUBERNETES_ORACLE_SOURCE = NATIVE_FILESYSTEM_ORACLE_SOURCE
      KUBERNETES_FLIGHTS = types.ModuleType("native_reference_kubernetes_flights")
      KUBERNETES_FLIGHTS.__dict__.update(globals())
      exec(compile(${builtins.toJSON (builtins.readFile ./native-reference-kubernetes-flights.py)},
          "native-reference-kubernetes-flights.py", "exec"), KUBERNETES_FLIGHTS.__dict__)
      original = write_reference_worktree("/var/lib/aos/native-kubernetes-admission", extra_module=OBSERVER_HOST_MODULE)
      apply_reference(original, "native-kubernetes-admission")
      runtime.wait_until_succeeds(f"{KUBECTL} --kubeconfig /etc/rancher/k3s/k3s.yaml get --raw=/readyz", timeout=900)
      selected_graph = current_reference_graph()
      cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      adapters = {adapter["adapter"]: adapter for adapter in MATRIX_SPEC["surface"]["adapters"]}
      for cell_id in COHORT_CELLS:
          cell = cells[cell_id]
          adapter = adapters[cell["adapter"]]
          if not KUBERNETES_FLIGHTS.supports(cell, adapter, selected_graph):
              raise RuntimeError("selected Kubernetes cell has no implemented native proof")
          KUBERNETES_FLIGHTS.run_cell(cell, adapter, selected_graph)
    '';
  }
