##! aos-boot-identity — fail-closed normal boot command-line validator
{
  lib,
  mkDerivation,
  bash,
  coreutils,
  rust,
  util-linux,
  stdenv,
}: let
  source = ../../crates/aos-boot-identity;

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
    pname = "aos-boot-identity";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser accepts the complete fail-closed normal-boot identity.";
        "files" = {
          "cmdline" = "root=/dev/mapper/root roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef systemd.verity_root_data=/dev/disk/by-partlabel/root-a systemd.verity_root_hash=/dev/disk/by-partlabel/root-a-hash systemd.verity=yes rd.luks=0\n";
        };
        "input" = "A normal-boot command line with a matching root hash and root-a verity devices.";
        "operation" = "Validate the command line through the packaged boot-identity parser.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-boot-identity\", \"cmdline\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nprint(\"aos-boot-identity operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-boot-identity operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The parser rejects the mismatched data and hash devices.";
        "files" = {
          "cmdline" = "root=/dev/mapper/root roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef systemd.verity_root_data=/dev/disk/by-partlabel/root-a systemd.verity_root_hash=/dev/disk/by-partlabel/root-b-hash systemd.verity=yes rd.luks=0\n";
        };
        "input" = "A normal-boot command line whose hash device belongs to the other slot.";
        "operation" = "Validate the inconsistent slot identity.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-boot-identity\", \"cmdline\"], capture_output=True, text=True)\nassert result.returncode == 1 and \"rejected normal boot\" in result.stderr, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-boot-identity rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-boot-identity rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0.1.0";
    src = source;

    buildDeps = [buildRust];
    runtimeDeps = [bash coreutils util-linux];
    propagatedDeps = [];
    abilities = ./_aos-boot-identity;

    phases = [
      {
        name = "build";
        script = ''
          ${rustcCommand} --edition=2024 \
            --crate-name aos_boot_identity \
            --crate-type rlib \
            ${source}/src/lib.rs \
            -o libaos_boot_identity.rlib
          ${rustcCommand} --edition=2024 \
            ${source}/src/main.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o aos-boot-identity
          ${rustcCommand} --edition=2024 --test ${source}/src/lib.rs -o aos-boot-identity-tests
          ./aos-boot-identity-tests
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-boot-identity $out/bin/
          for source in ${./_aos-boot-identity}/*.sh; do
            destination="$out/bin/$(basename "$source" .sh)"
            sed 's|@bash@|${bash}|g' "$source" > "$destination"
            chmod 0555 "$destination"
          done
        '';
      }
    ];

    meta = {
      description = "Validate the AOS normal-boot identity tuple";
      license = "Apache-2.0";
    };
  }
