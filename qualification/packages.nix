##! Roles supplement the existing complete platform inventory.
{packageNames}: let
  integrityRoots = [
    "aos"
    "bash"
    "coreutils"
    "systemd"
    "linux"
    "nix"
    "openssl"
    "openssh"
    "chrony"
    "e2fsprogs"
    "cryptsetup"
    "tpm2-tools"
  ];
  workloadRoots = ["nginx" "containerd" "runc"];
in
  map (name: {
    inherit name;
    role =
      if builtins.elem name integrityRoots
      then "system-integrity"
      else if builtins.elem name workloadRoots
      then "qualified-workload"
      else "general-catalog";
    # General catalog is a defined baseline rule, not a skip. Every published
    # package/platform still needs a meaningful functional observation. Closure
    # membership raises obligations for dependencies of integrity/workload roots.
    inherit_dependency_obligations = true;
  }) (builtins.sort builtins.lessThan packageNames)
