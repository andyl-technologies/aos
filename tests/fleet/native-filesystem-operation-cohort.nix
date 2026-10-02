##! Qualifies actual filesystem, configuration, and firewall terminal operations.
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
  controlledSource = ./_native-reference-filesystem-configuration.nix;
  interceptionSource = ./_native-reference-firewall-interception.nix;
  dependencySource = ./_native-reference-domain-dependencies.nix;
  dependencyMarkers = import ../abilities/native-dependency-barrier/package.nix {
    inherit (pkgs) mkDerivation python3;
  };
  filesystemInterception = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.aos-filesystem-provider;
    backendExecutable = "bin/aos-filesystem-provider";
  };
  configurationInterception = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.systemd;
    backendExecutable = "bin/aos-service-handler";
  };
  firewallInterception = import ../abilities/native-handler-interception/package.nix {
    inherit (pkgs) mkDerivation python3;
    backend = pkgs.aos-network-ruleset-provider;
    backendExecutable = "bin/aos-network-ruleset-provider";
  };
  fixturePackages = [firewallInterception filesystemInterception configurationInterception dependencyMarkers];
  fixture =
    reference
    // {
      scenarioSources = [./_reference-native-configuration.nix controlledSource interceptionSource dependencySource];
      runtimeModules =
        reference.runtimeModules
        ++ [
          {
            aos.packages = lib.listToAttrs (map (package: {
                name = package.pname;
                value = {
                  inherit package;
                  bundle = true;
                };
              })
              fixturePackages);
          }
        ];
      extraClosures = reference.extraClosures ++ fixturePackages;
      qualificationExtraClosures = reference.qualificationExtraClosures ++ fixturePackages;
    };
in
  import ./_native-operation-cohort.nix {
    inherit lib mkSystem pkgs fixture;
    name = "native-filesystem-operation-cohort";
    requiredOperations = [
      {
        ability = "filesystem";
        name = "directory";
      }
      {
        ability = "filesystem";
        name = "allocate";
      }
      {
        ability = "filesystem";
        name = "persistentAllocate";
      }
      {
        ability = "filesystem";
        name = "entry";
      }
      {
        ability = "configuration";
        name = "file";
      }
      {
        ability = "networkPolicy";
        name = "ruleset";
      }
    ];
    guestOracleSource = builtins.readFile ./native-filesystem-firewall-oracles.py;
    domainScript = ''
      FILESYSTEM_FLIGHTS = types.ModuleType("native_reference_filesystem_flights")
      FILESYSTEM_FLIGHTS.__dict__.update(globals())
      exec(compile(${builtins.toJSON (builtins.readFile ./native-reference-filesystem-flights.py)},
          "native-reference-filesystem-flights.py", "exec"), FILESYSTEM_FLIGHTS.__dict__)
      original = write_reference_worktree("/var/lib/aos/native-filesystem-admission", extra_module=OBSERVER_HOST_MODULE)
      apply_reference(original, "native-filesystem-admission")
      selected_graph = SELECTED_EVALUATION_GRAPH
      if current_reference_graph() != selected_graph:
          raise RuntimeError("filesystem baseline differs from authenticated selected graph")
      cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
      adapters = {adapter["adapter"]: adapter for adapter in MATRIX_SPEC["surface"]["adapters"]}
      for cell_id in COHORT_CELLS:
          cell = cells[cell_id]
          adapter = adapters[cell["adapter"]]
          if not FILESYSTEM_FLIGHTS.supports(cell, adapter, selected_graph):
              raise RuntimeError("selected filesystem/firewall cell has no concrete native proof")
          FILESYSTEM_FLIGHTS.run_cell(cell, adapter, selected_graph)
    '';
  }
