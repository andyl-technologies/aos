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
  crossPlain = import ../.. {
    inherit system;
    crossSystem = "aarch64-linux";
  };
  crossShared = import ../.. {
    inherit system;
    crossSystem = "aarch64-linux";
    sharedBuildCache = true;
  };
in
  assert plain.stdenv.cc.drvPath == shared.stdenv.cc.drvPath;
  assert plain.pkgs.zlib.drvPath != shared.pkgs.zlib.drvPath;
  assert !(plain.pkgs.zlib ? AOS_SHARED_BUILD_CACHE);
  assert shared.pkgs.zlib ? AOS_SHARED_BUILD_CACHE;
  assert shared.pkgs.zlib.AOS_SHARED_BUILD_CACHE == "/aos-build-cache";
  assert plain.pkgs.rust.drvPath == shared.pkgs.rust.drvPath;
  assert !(plain.pkgs.rust ? AOS_SHARED_BUILD_CACHE);
  assert !(plain.pkgs.rust ? RUSTC_WRAPPER);
  assert !(shared.pkgs.rust ? AOS_SHARED_BUILD_CACHE);
  assert plain.pkgs."rust-1_75".drvPath == shared.pkgs."rust-1_75".drvPath;
  assert !(shared.pkgs."rust-1_74" ? AOS_SHARED_BUILD_CACHE);
  assert plain.pkgs.llvm.drvPath == shared.pkgs.llvm.drvPath;
  assert !(shared.pkgs.llvm ? AOS_SHARED_BUILD_CACHE);
  assert !(plain.pkgs.go ? AOS_SHARED_BUILD_CACHE);
  assert !(plain.pkgs.go ? GOCACHE);
  assert plain.pkgs.go.drvPath == shared.pkgs.go.drvPath;
  assert !(shared.pkgs.go ? GOCACHE);
  assert plain.pkgs.bazel.drvPath == shared.pkgs.bazel.drvPath;
  assert !(shared.pkgs.bazel ? AOS_SHARED_BUILD_CACHE);
  assert plain.pkgs.openjdk.drvPath == shared.pkgs.openjdk.drvPath;
  assert !(shared.pkgs.openjdk ? AOS_SHARED_BUILD_CACHE);
  assert plain.pkgs.sccache.drvPath == shared.pkgs.sccache.drvPath;
  assert !(shared.pkgs.sccache ? AOS_SHARED_BUILD_CACHE);
  assert shared.pkgs.aos ? RUSTC_WRAPPER;
  assert builtins.match ".*/bin/sccache" shared.pkgs.aos.RUSTC_WRAPPER != null;
  assert shared.pkgs.gopls.GOCACHE == "/aos-build-cache/go";
  assert shared.pkgs.envoy.AOS_BAZEL_DISK_CACHE == "/aos-build-cache/bazel";
  assert crossPlain.pkgs.rust.drvPath == crossShared.pkgs.rust.drvPath;
  assert crossPlain.pkgs.go.drvPath == crossShared.pkgs.go.drvPath;
  assert crossPlain.pkgs.llvm.drvPath == crossShared.pkgs.llvm.drvPath;
  assert crossPlain.pkgs.zlib.drvPath != crossShared.pkgs.zlib.drvPath;
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
