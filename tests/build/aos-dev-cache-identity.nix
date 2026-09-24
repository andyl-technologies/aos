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
  assert plain.pkgs.rust.drvPath != shared.pkgs.rust.drvPath;
  assert !(plain.pkgs.rust ? AOS_SHARED_BUILD_CACHE);
  assert !(plain.pkgs.rust ? RUSTC_WRAPPER);
  assert shared.pkgs.rust ? AOS_SHARED_BUILD_CACHE;
  assert builtins.match ".*/bin/sccache" shared.pkgs.rust.RUSTC_WRAPPER != null;
  assert shared.pkgs."rust-1_75" ? AOS_SHARED_BUILD_CACHE;
  assert !(shared.pkgs."rust-1_74" ? AOS_SHARED_BUILD_CACHE);
  assert shared.pkgs.llvm ? AOS_SHARED_BUILD_CACHE;
  assert !(plain.pkgs.go ? AOS_SHARED_BUILD_CACHE);
  assert !(plain.pkgs.go ? GOCACHE);
  assert shared.pkgs.go ? AOS_SHARED_BUILD_CACHE;
  assert shared.pkgs.go.GOCACHE == "/aos-build-cache/go";
  assert shared.pkgs.bazel ? AOS_SHARED_BUILD_CACHE;
  assert shared.pkgs.openjdk ? AOS_SHARED_BUILD_CACHE;
  assert !(shared.pkgs.sccache ? AOS_SHARED_BUILD_CACHE);
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
