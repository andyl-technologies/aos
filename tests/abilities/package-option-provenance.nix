##! Checks that package option documents retain their owning source file.
{pkgs}: let
  declarations = pkgs."aos-zfs-provider".contract.value.option_declarations;
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
  assert builtins.all
  (declaration: declaration.source.path == "maintenance.nix")
  maintenanceOptions;
  assert builtins.length paths
  == builtins.length (builtins.attrNames (builtins.listToAttrs (
    builtins.map (path: {
      name = path;
      value = true;
    })
    paths
  ))); true
