##! aos-recovery — bounded console application for the signed recovery initrd
{
  lib,
  mkDerivation,
  rust,
  stdenv,
}: let
  identitySource = ../../crates/aos-boot-identity;
  recoverySource = ../../crates/aos-recovery;

  # The build compiler carries the target standard library; rustc still needs
  # an explicit target and linker because these recipes do not use Cargo.
  buildRust =
    if stdenv.isCross
    then rust.passthru.buildTool
    else rust;
  rustcCommand =
    if stdenv.isCross
    then "${buildRust}/bin/rustc --target ${stdenv.hostPlatform.config} -C linker=${stdenv.cc}/bin/cc"
    else "rustc";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "aos-recovery";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The package contains the recovery console executable used by the boot scenario.";
        "files" = {};
        "input" = "The staged recovery executable.";
        "operation" = "Verify its executable format and bounded console identity.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nbinary = pathlib.Path(\"@out@/bin/aos-recovery\").read_bytes()\nassert binary.startswith(bytes([0x7f]) + b\"ELF\")\nassert b\"AOS signed recovery environment\" in binary\nprint(\"aos-recovery identity passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-recovery identity passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The package exposes only its declared recovery executable.";
        "files" = {};
        "input" = "A request for an undeclared recovery helper.";
        "operation" = "Resolve the absent helper beneath the staged output.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/bin/aos-recovery-shell\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"undeclared recovery helper rejected\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "undeclared recovery helper rejected\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0.1.0";
    src = recoverySource;

    buildDeps = [buildRust];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          ${rustcCommand} --edition=2024 \
            --crate-name aos_boot_identity \
            --crate-type rlib \
            ${identitySource}/src/lib.rs \
            -o libaos_boot_identity.rlib
          ${rustcCommand} --edition=2024 \
            --crate-name aos_recovery \
            --crate-type rlib \
            ${recoverySource}/src/lib.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o libaos_recovery.rlib
          ${rustcCommand} --edition=2024 \
            ${recoverySource}/src/main.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            --extern aos_recovery=libaos_recovery.rlib \
            -o aos-recovery
          ${rustcCommand} --edition=2024 --test ${recoverySource}/src/lib.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o aos-recovery-tests
          ./aos-recovery-tests
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-recovery $out/bin/
        '';
      }
    ];

    meta = {
      description = "Run the bounded AOS signed-recovery console";
      license = "Apache-2.0";
    };
  }
