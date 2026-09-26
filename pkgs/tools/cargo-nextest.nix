##! cargo-nextest — process-per-test Rust test runner.
{
  lib,
  stdenv,
  buildPackages,
  mkDerivation,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  patch,
  pkg-config,
  openssl,
}: let
  version = "0.9.143";
  src = fetchurl {
    urls = [
      "https://github.com/nextest-rs/nextest/archive/refs/tags/cargo-nextest-${version}.tar.gz"
    ];
    hash = "sha256-StXb6eJm/XMDw5QTxWEMTKA/PBtw+NWcgSZqRFLlk2E=";
  };
  unpatchedCargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-TMIaRjGV+qooWVMKL0dWfcC1EJcNlHnllHIIB5AgkqA=";
  };
  cargoDeps = mkDerivation {
    pname = "cargo-nextest-cargo-deps";
    inherit version;
    src = unpatchedCargoDeps;
    buildDeps = [patch];
    phases = [
      {
        name = "install";
        script = ''
          cp -R "$src"/. "$out"/
          chmod -R u+w "$out"
          patch -d "$out/usdt-impl" -p1 < ${./cargo-nextest-usdt-cross-arch.patch}
          sed -i \
            's|4d58f89e90a902be940ee23dd2e572ea88e6a4e4cf71fe61e53f6e70a239c3e6|aae4b570192f395d4edc90973d831774af8d9e68dda40e5e1f40983cbf8691c7|' \
            "$out/usdt-impl/.cargo-checksum.json"
          sed -i \
            's|3c64ecebf7996061243ce3809f99c2c60105abe25684ddc979440e603d4573c6|c01790a56d0c2918186e3050c9a1e463d049a8e2abbcda0cc68433b1e034db4e|' \
            "$out/usdt-impl/.cargo-checksum.json"
          sed -i \
            's|d223014ffc59d798cc5e53605942204056beb0ef2e75484b45942aae742fc233|577b977d8431056c0e0839ccd74328eb0a1dec6b6202317cd078e912df2e9d82|' \
            "$out/usdt-impl/.cargo-checksum.json"
        '';
      }
    ];
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "cargo-nextest";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cargo-nextest returns success and identifies its executable.";
        "files" = {};
        "input" = "The packaged nextest runner's release identity.";
        "operation" = "Request its version without reading a Cargo workspace.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/cargo-nextest\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"cargo-nextest\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"cargo-nextest operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cargo-nextest operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cargo-nextest rejects the unsupported operation.";
        "files" = {};
        "input" = "A cargo-nextest invocation naming an unknown operation.";
        "operation" = "Parse the unknown operation without reading a workspace.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/cargo-nextest\", \"aos-invalid-operation\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"cargo-nextest rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cargo-nextest rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    inherit cargoDeps;
    cargoFlags = "-p cargo-nextest --bin cargo-nextest";
    cargoEnv =
      {USDT_TARGET = stdenv.hostPlatform.config;}
      // (
        if stdenv.hostPlatform.system == "aarch64-darwin"
        then {
          CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER = "${buildPackages.darwinCctoolsLinker}/bin/aarch64-apple-darwin-ld";
        }
        else {}
      );
    doCheck = false;
    buildDeps =
      [pkg-config openssl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.darwinDtraceCompiler]
        else []
      );
    runtimeDeps = [openssl];
    OPENSSL_DIR = "${openssl}";
    OPENSSL_NO_VENDOR = "1";

    meta = {
      description = "Next-generation test runner for Rust projects";
      homepage = "https://nexte.st";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-nextest";
    };
  }
