##! Declaration-derived interface documentation independent of handler execution.
{lib}: {
  options = type:
    builtins.listToAttrs (builtins.map (declaration: {
        name = builtins.concatStringsSep "." declaration.path;
        value = {inherit (declaration) description type;};
      }) (builtins.filter (declaration: builtins.head declaration.path != "_module")
        (lib.submoduleOptionDeclarations type [])));
  abilities = abilities:
    builtins.mapAttrs (_: ability:
      builtins.mapAttrs (_: operation: operation.documentation) ability.operations)
    abilities;
}
