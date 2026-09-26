{
  pkgs,
  system,
  crossSystem,
}: let
  plain = import ../.. {inherit system crossSystem;};
  shared = import ../.. {
    inherit system crossSystem;
    sharedGoCacheDir = "/aos-build-cache/go";
    sharedBazelCacheDir = "/aos-build-cache/bazel";
  };
  rustShared = import ../.. {
    inherit system crossSystem;
    sharedRustTargetDir = "/aos-build-cache/rust";
    sharedRustIncremental = true;
  };
  rustIncrementalOnly = import ../.. {
    inherit system crossSystem;
    sharedRustIncremental = true;
  };
  goOnly = import ../.. {
    inherit system crossSystem;
    sharedGoCacheDir = "/custom/go-cache";
  };
  bazelOnly = import ../.. {
    inherit system crossSystem;
    sharedBazelCacheDir = "/custom/bazel-cache";
  };
  rustTargetOnly = import ../.. {
    inherit system crossSystem;
    sharedRustTargetDir = "/custom/rust-cache";
  };
  crossPlain = import ../.. {
    inherit system;
    crossSystem = "aarch64-linux";
  };
  crossShared = import ../.. {
    inherit system;
    crossSystem = "aarch64-linux";
    sharedGoCacheDir = "/aos-build-cache/go";
    sharedBazelCacheDir = "/aos-build-cache/bazel";
  };
  cacheMountProbe = import ../../dev/cache-mount-smoke.nix {
    goCacheDir = "/aos-build-cache/go";
    bazelCacheDir = "/aos-build-cache/bazel";
    rustCacheDir = "/aos-build-cache/rust";
  };
in
  assert cacheMountProbe.builder == "${plain.stdenv.bootstrap.bash}/bin/bash";
  assert plain.stdenv.cc.drvPath == shared.stdenv.cc.drvPath;
  assert plain.pkgs.gcc-libs.drvPath == shared.pkgs.gcc-libs.drvPath;
  assert !(shared.pkgs.gcc-libs ? GOCACHE);
  assert plain.pkgs.zlib.drvPath == shared.pkgs.zlib.drvPath;
  assert !(plain.pkgs.zlib ? GOCACHE);
  assert !(shared.pkgs.zlib ? GOCACHE);
  assert plain.pkgs.rust.drvPath == shared.pkgs.rust.drvPath;
  assert !(plain.pkgs.rust ? GOCACHE);
  assert !(plain.pkgs.rust ? RUSTC_WRAPPER);
  assert !(shared.pkgs.rust ? GOCACHE);
  assert plain.pkgs."rust-1_75".drvPath == shared.pkgs."rust-1_75".drvPath;
  assert !(shared.pkgs."rust-1_74" ? GOCACHE);
  assert plain.pkgs.llvm.drvPath == shared.pkgs.llvm.drvPath;
  assert !(shared.pkgs.llvm ? GOCACHE);
  assert !(plain.pkgs.go ? GOCACHE);
  assert plain.pkgs.go.drvPath == shared.pkgs.go.drvPath;
  assert !(shared.pkgs.go ? GOCACHE);
  assert plain.pkgs.bazel.drvPath == shared.pkgs.bazel.drvPath;
  assert !(shared.pkgs.bazel ? AOS_BAZEL_DISK_CACHE);
  assert plain.pkgs.openjdk.drvPath == shared.pkgs.openjdk.drvPath;
  assert !(shared.pkgs.openjdk ? GOCACHE);
  assert !(shared.pkgs.aos ? RUSTC_WRAPPER);
  assert !(shared.pkgs.aos ? CARGO_TARGET_DIR);
  assert !(shared.pkgs.aos ? CARGO_INCREMENTAL);
  assert shared.pkgs.gopls.GOCACHE == "/aos-build-cache/go";
  assert shared.pkgs.envoy.AOS_BAZEL_DISK_CACHE == "/aos-build-cache/bazel";
  assert goOnly.pkgs.gopls.GOCACHE == "/custom/go-cache";
  assert !(goOnly.pkgs.envoy ? AOS_BAZEL_DISK_CACHE);
  assert bazelOnly.pkgs.envoy.AOS_BAZEL_DISK_CACHE == "/custom/bazel-cache";
  assert !(bazelOnly.pkgs.gopls ? GOCACHE);
  assert builtins.match "/custom/rust-cache/aos-[0-9a-f]+" rustTargetOnly.pkgs.aos.CARGO_TARGET_DIR != null;
  assert !(rustTargetOnly.pkgs.aos ? CARGO_INCREMENTAL);
  assert plain.pkgs.rust.drvPath == rustShared.pkgs.rust.drvPath;
  assert plain.pkgs.go.drvPath == rustShared.pkgs.go.drvPath;
  assert plain.pkgs.llvm.drvPath == rustShared.pkgs.llvm.drvPath;
  assert plain.pkgs.gcc-libs.drvPath == rustShared.pkgs.gcc-libs.drvPath;
  assert plain.pkgs.openjdk.drvPath == rustShared.pkgs.openjdk.drvPath;
  assert plain.pkgs.aos.drvPath != rustShared.pkgs.aos.drvPath;
  assert plain.pkgs.aos.passthru.cargoArtifacts.drvPath == rustShared.pkgs.aos.passthru.cargoArtifacts.drvPath;
  assert !(rustShared.pkgs.aos ? RUSTC_WRAPPER);
  assert builtins.match "/aos-build-cache/rust/aos-[0-9a-f]+" rustShared.pkgs.aos.CARGO_TARGET_DIR != null;
  assert rustShared.pkgs.aos.CARGO_INCREMENTAL == "1";
  assert !(rustIncrementalOnly.pkgs.aos ? CARGO_TARGET_DIR);
  assert rustIncrementalOnly.pkgs.aos.CARGO_INCREMENTAL == "1";
  assert crossPlain.pkgs.rust.drvPath == crossShared.pkgs.rust.drvPath;
  assert crossPlain.pkgs.go.drvPath == crossShared.pkgs.go.drvPath;
  assert crossPlain.pkgs.llvm.drvPath == crossShared.pkgs.llvm.drvPath;
  assert crossPlain.pkgs.gcc-libs.drvPath == crossShared.pkgs.gcc-libs.drvPath;
  assert crossPlain.pkgs.zlib.drvPath == crossShared.pkgs.zlib.drvPath;
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
