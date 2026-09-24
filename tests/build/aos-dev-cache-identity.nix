{
  pkgs,
  system,
  crossSystem,
}: let
  plain = import ../.. {inherit system crossSystem;};
  shared = import ../.. {
    inherit system crossSystem;
    sharedBuildCache = true;
  };
in
  assert plain.stdenv.cc.drvPath == shared.stdenv.cc.drvPath;
  assert plain.pkgs.zlib.drvPath != shared.pkgs.zlib.drvPath;
  assert !(plain.pkgs.zlib ? AOS_SHARED_BUILD_CACHE);
  assert shared.pkgs.zlib ? AOS_SHARED_BUILD_CACHE;
    pkgs.mkDerivation {
      pname = "aos-dev-cache-identity-check";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
