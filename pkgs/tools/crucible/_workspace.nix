##! Keep every Crucible Cargo consumer on the same closed workspace member set.
{lib}: let
  packages = import ./_packages.nix;
  selection = import ../aos/_workspace-slice.nix {
    inherit lib;
    cargoFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") packages);
  };
in
  selection.cargoWorkspaceMembers
