# Renders the flake's public consumer settings for legacy Nix commands without
# evaluating any package outputs. Flake nixConfig must itself be a literal set.
let
  settings = (import ../../flake.nix).nixConfig;
in {
  inherit settings;

  # Legacy nix-build commands do not read flake nixConfig. The shell and the
  # standalone script append the same settings to their inherited NIX_CONFIG.
  text = ''
    extra-substituters = ${builtins.concatStringsSep " " settings.extra-substituters}
    extra-trusted-public-keys = ${builtins.concatStringsSep " " settings.extra-trusted-public-keys}
    fallback = ${
      if settings.fallback
      then "true"
      else "false"
    }
  '';
}
