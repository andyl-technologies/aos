##! Native option documents retain package ownership and authored policy sources.
{
  pkgs,
  lib,
}: let
  package = pkgs.aos-zfs-provider;
  declarations =
    (lib.evalPackageModules {
      scope = ["test" "option-provenance"];
      packages = [package];
    }).documentation.options;
  maintenanceOptions =
    builtins.filter
    (declaration:
      builtins.length declaration.path
      >= 4
      && builtins.elemAt declaration.path 0 == "aos"
      && builtins.elemAt declaration.path 1 == "filesystems"
      && builtins.elemAt declaration.path 2 == "zfs"
      && builtins.elemAt declaration.path 3 == "maintenance")
    declarations;
  paths = builtins.map (declaration: builtins.toJSON declaration.path) declarations;
in
  assert maintenanceOptions != [];
  assert builtins.readFile "${package.module}/maintenance.nix" == builtins.readFile ../../pkgs/filesystem/_aos-zfs-provider/maintenance.nix;
  assert builtins.all
  (declaration: declaration.owner == "aos-zfs-provider")
  maintenanceOptions;
  assert builtins.length paths
  == builtins.length (builtins.attrNames (builtins.listToAttrs (
    builtins.map (path: {
      name = path;
      value = true;
    })
    paths
  ))); true
