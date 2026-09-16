##! Semantic input for the Nix-to-Rust release inventory boundary check.
{releasePlatforms}: let
  lib = import ../../../lib {
    system = builtins.head releasePlatforms;
  };
  policy = import ../../../pkgs/_target-policy.nix {
    inherit lib releasePlatforms;
    packages.public-fixture.platformSupport = {
      build = [];
      host = [];
      target = [];
      role = "public-package";
    };
  };
in
  policy.releaseInventory ["public-fixture"]
