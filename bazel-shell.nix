# Resolve only the source-built Bazel development tools and offline repositories.
let
  aos = import ./default.nix {};
in
  aos.pkgs.mkAosBazelShell {}
