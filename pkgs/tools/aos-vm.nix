##! aos-vm — host CLI closure with local QEMU/UEFI runtime tools.
##!
##! The base `aos` package stays suitable for inclusion in AOS guest images.
##! This opt-in host wrapper adds the emulator, firmware, and GPT tooling used
##! by `aos vm run` without pulling them into every system root filesystem.
{
  lib,
  mkDerivation,
  aos,
  edk2,
  gptfdisk,
  qemu,
  stdenv,
}: let
  firmwareSedExpressions = builtins.concatStringsSep " \\\n            " (
    if stdenv.hostPlatform.isAarch64
    then [
      ''-e '/^exec /i export AOS_OVMF_CODE="${edk2}/FV/AAVMF_CODE.fd"' ''
      ''-e '/^exec /i export AOS_QEMU="${qemu}/bin/qemu-system-aarch64"' ''
    ]
    else [
      ''-e '/^exec /i export AOS_OVMF_CODE="${edk2}/FV/OVMF_CODE.fd"' ''
      ''-e '/^exec /i export AOS_OVMF_VARS="${edk2}/FV/OVMF_VARS.fd"' ''
      ''-e '/^exec /i export AOS_QEMU="${qemu}/bin/qemu-system-x86_64"' ''
    ]
  );
in
  mkDerivation {
    pname = "aos-vm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The wrapper returns success and describes its VM operations.";
        "files" = {};
        "input" = "The host VM wrapper's command-line interface.";
        "operation" = "Request VM subcommand help without starting an emulator.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos\", \"vm\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Usage\" in result.stdout\nprint(\"aos-vm operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-vm operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The wrapper rejects the operation before starting QEMU.";
        "files" = {};
        "input" = "A VM wrapper invocation containing an unknown operation.";
        "operation" = "Parse the unknown operation.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos\", \"vm\", \"not-an-operation\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-vm rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-vm rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = aos.version;
    src = null;

    runtimeDeps = [aos aos.apr edk2 gptfdisk qemu];

    # This package copies the base CLI launcher so it can add the VM-specific
    # environment without another shell process. Preserve the launcher's
    # intentional references to the base CLI runtime closure.
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"

          sed \
            ${firmwareSedExpressions} \
            -e '/^exec /i export AOS_SGDISK="${gptfdisk}/sbin/sgdisk"' \
            "${aos}/bin/aos" > "$out/bin/aos"
          chmod +x "$out/bin/aos"
          ln -s "${aos.apr}/bin/apr" "$out/bin/apr"
        '';
      }
    ];

    passthru.evidenceSources = [./aos-vm.nix];

    meta = {
      description = "AOS CLI with QEMU, UEFI firmware, and GPT tools for local virtual machines";
      homepage = "https://github.com/andyl-technologies/aos";
      license = "MIT";
    };
  }
