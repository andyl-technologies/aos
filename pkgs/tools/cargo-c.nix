##! Build and install Rust libraries with a C ABI.
{
  mkCargoPackage,
  lib,
  callPackage,
  buildPackages,
  stdenv,
  openssl,
  curl,
  libgit2,
  libssh2,
  zlib,
}: let
  sources = callPackage ./_cargo-c-sources.nix {};
  manifest = ''
    [package]
    name = "aos_c_probe"
    version = "0.1.0"
    edition = "2021"

    [lib]
    crate-type = ["cdylib", "staticlib"]

    [package.metadata.capi]
  '';
  librarySource = ''
    #[no_mangle]
    pub extern "C" fn aos_add(left: i32, right: i32) -> i32 {
        left + right
    }
  '';
  probeScript = ''
    import ctypes
    import os
    import pathlib
    import subprocess
    import sys

    rustc = "@rustc@"
    environment = os.environ.copy()
    environment["PATH"] = str(pathlib.Path(rustc).parent) + os.pathsep + environment["PATH"]
    environment["RUSTC"] = rustc
    environment["RUSTFLAGS"] = "-C linker=@cc@"
    environment["CARGO_NET_OFFLINE"] = "true"
    environment["CARGO_BUILD_JOBS"] = "2"

    result = subprocess.run(
        [
            "@out@/bin/cargo-cbuild",
            "cbuild",
            "--manifest-path", str(pathlib.Path("Cargo.toml").resolve()),
            "--offline",
            "--target-dir", "target",
        ],
        env=environment,
        capture_output=True,
        text=True,
    )

    if sys.argv[1] == "primary":
        assert result.returncode == 0, result.stderr
        header = next(pathlib.Path("target").rglob("aos_c_probe.h"))
        pkgconfig = next(pathlib.Path("target").rglob("aos_c_probe.pc"))
        suffix = ".dylib" if environment["AOS_QUALIFICATION_PLATFORM"].endswith("-darwin") else ".so"
        library = next(pathlib.Path("target").rglob("libaos_c_probe" + suffix))
        assert "aos_add" in header.read_text()
        assert "aos_c_probe" in pkgconfig.read_text()

        loaded = ctypes.CDLL(str(library.resolve()))
        loaded.aos_add.argtypes = [ctypes.c_int, ctypes.c_int]
        loaded.aos_add.restype = ctypes.c_int
        assert loaded.aos_add(19, 23) == 42
        print("built and called C ABI library")
    elif sys.argv[1] == "bad-input":
        assert result.returncode != 0
        assert "does not contain this feature: capi" in result.stderr
        print("rejected crate without capi feature")
    else:
        raise ValueError("unknown qualification operation")
  '';
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "cargo-c";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A dependency-free Rust crate exporting one C function.";
        operation = "Build its C ABI and inspect the library, header, and pkg-config file.";
        expected = "The exported function returns 42 when called through the generated library.";
        artifacts = [];
        files = {
          "Cargo.toml" =
            manifest
            + ''
              [features]
              capi = []
            '';
          "src/lib.rs" = librarySource;
          "probe.py" = probeScript;
        };
        steps = [
          {
            argv = ["@python@" "probe.py" "primary"];
            exit_code = 0;
            stdout.exact = "built and called C ABI library\n";
            stderr.exact = "";
            timeout_seconds = 180;
          }
        ];
      };
      badInput = {
        input = "The same crate without cargo-c's required capi feature.";
        operation = "Request a C ABI build from the incomplete crate manifest.";
        expected = "Cargo-c rejects the crate before compilation.";
        artifacts = [];
        files = {
          "Cargo.toml" = manifest;
          "src/lib.rs" = librarySource;
          "probe.py" = probeScript;
        };
        steps = [
          {
            argv = ["@python@" "probe.py" "bad-input"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "rejected crate without capi feature\n";
            stderr.exact = "";
            timeout_seconds = 180;
          }
        ];
      };
    };
    inherit (sources) version src cargoDeps;
    passthru.evidenceSources = [sources.archive sources.lockfile sources.cargoDeps];
    buildDeps = [buildPackages.pkg-config buildPackages.cmake];
    runtimeDeps = [openssl curl libgit2 libssh2 zlib];
    doCheck = !stdenv.isCross;
    cargoEnv = {
      OPENSSL_NO_VENDOR = "1";
      LIBSSH2_SYS_USE_PKG_CONFIG = "1";
      LIBGIT2_NO_VENDOR = "1";
    };
    postInstall = ''
      mkdir -p "$out/share/licenses/cargo-c"
      cp LICENSE "$out/share/licenses/cargo-c/"
    '';
    meta = {
      description = "Cargo helpers for building and installing C ABI libraries";
      homepage = "https://github.com/lu-zero/cargo-c";
      license = "MIT";
      mainProgram = "cargo-cbuild";
    };
  }
