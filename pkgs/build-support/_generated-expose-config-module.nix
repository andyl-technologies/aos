##! Registry entry point for a generated expose configuration module.
let
  schema = builtins.fromJSON (builtins.readFile ./expose-config.json);
in
  import ./expose-config-projection-module.nix {inherit schema;}
