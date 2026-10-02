##! Projects conditional role requirements before admitting workload modules.
let
  lib = import ../../lib {system = "x86_64-linux";};
  evaluate = configuration:
    (lib.evalModules {
      inherit lib;
      enforceRuntimeDeclarations = false;
      modules = [
        {
          options.aos.boot.stage = lib.mkOption {
            type = lib.types.enum ["host" "initrd"];
            default = "host";
          };
        }
        ../../pkgs/system/_aos-host-policy/package-selection.nix
        ../../pkgs/system/_aos-host-policy/role-server.nix
        ../../pkgs/system/_aos-host-policy/role-edge.nix
        configuration
      ];
    }).config.aos.apm.desiredPackages;
  expected = ["openssh" "chrony"];
in {
  disabledRolesDoNotAdmitWorkloads = evaluate {} == [];
  serverRequiresOriginalServices = evaluate {aos.roles.server.enable = true;} == expected;
  edgeRequiresOriginalServices = evaluate {aos.roles.edge.enable = true;} == expected;
  roleRequirementsPreserveOperatorSelection =
    evaluate {
      aos.roles.server.enable = true;
      aos.apm.desiredPackages = ["nginx"];
    }
    == ["nginx"] ++ expected;
  explicitSelectionReplacement =
    evaluate ({lib, ...}: {
      aos.roles.server.enable = true;
      aos.apm.desiredPackages = lib.mkForce ["nginx"];
    })
    == ["nginx"];
  initrdDoesNotSelectHostWorkloads =
    evaluate {
      aos.roles.server.enable = true;
      aos.roles.edge.enable = true;
      aos.boot.stage = "initrd";
    }
    == [];
}
