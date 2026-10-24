# Development-only image recipes. Ordinary builds keep immutable derivations.
# A recipe retains closures, tools, and exact builder phases, never a staged tree.
{
  pkgs,
  lib,
}: {dependencies ? []}: attrs: let
  ordinary = pkgs.mkDerivation attrs;
  environment = builtins.mapAttrs (_: value: builtins.toString value) (
    builtins.removeAttrs ordinary.drvAttrs [
      "args"
      "builder"
      "name"
      "system"
      "outputs"
      "exportReferencesGraph"
      "passAsFile"
      "__aosBuildScript"
      "disallowedReferences"
      "disallowedRequisites"
      "allowedReferences"
      "allowedRequisites"
      "outputChecks"
      "__structuredAttrs"
    ]
  );
  recipe = {
    schema = 1;
    cache = pkgs.sharedImageCacheDir;
    inherit environment;
    shell = ordinary.builder;
    dependencies = map builtins.toString dependencies;
    # Replay the full generated builder, including stdenv setup and fixups.
    # Both the implementation and its tool paths participate in recipe identity.
    script = ordinary.drvAttrs.__aosBuildScript or (builtins.elemAt ordinary.args 1);
    system = ordinary.system;
  };
in
  assert !(attrs ? exportReferencesGraph);
  assert !(attrs ? passAsFile);
    pkgs.writeTextFile {
      name = "${attrs.pname}-recipe";
      destination = "/image-recipe.json";
      text = builtins.toJSON recipe;
    }
