##! Checks that nested service option documents retain their owning source file.
{pkgs}: let
  declarations = pkgs."aos-zfs-provider".contract.value.option_declarations;
  serviceOptions =
    builtins.filter
    (declaration:
      builtins.length declaration.path
      >= 3
      && builtins.elemAt declaration.path 0 == "aos"
      && builtins.elemAt declaration.path 1 == "services"
      && builtins.elemAt declaration.path 2 == "zfsMaintenance")
    declarations;
  paths = builtins.map (declaration: builtins.toJSON declaration.path) declarations;
in
  assert serviceOptions != [];
  assert builtins.all
  (declaration: declaration.source.path == "maintenance.nix")
  serviceOptions;
  assert builtins.length paths
  == builtins.length (builtins.attrNames (builtins.listToAttrs (
    builtins.map (path: {
      name = path;
      value = true;
    })
    paths
  ))); true
