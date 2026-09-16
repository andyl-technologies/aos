##! efibootmgr — EFI boot entry manager
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  efivar,
  popt,
}: let
  version = "18";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "efibootmgr";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Efibootmgr identifies version 18 and returns success.";
        "files" = {};
        "input" = "The packaged EFI boot-entry manager executable.";
        "operation" = "Request the tool's version without accessing EFI variables.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/efibootmgr\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"18\" in result.stdout\nprint(\"efibootmgr data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "efibootmgr data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Efibootmgr rejects the malformed identifier before accessing firmware state.";
        "files" = {};
        "input" = "A boot-entry number containing non-hexadecimal characters.";
        "operation" = "Parse the invalid boot-number argument.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/efibootmgr\", \"--bootnum\", \"not-hex\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"efibootmgr rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "efibootmgr rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/rhboot/efibootmgr/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-RChn0S+FJQNKQE/IrzA226jh/JcJmK8khsO5QN+tCHQ=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [efivar popt];
    propagatedDeps = [];

    makeFlags = "EFIDIR=aos PKG_CONFIG=pkg-config";
    installFlags = "EFIDIR=aos prefix=${builtins.placeholder "out"}";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-efibootmgr";
        tool = self;
        command = "efibootmgr --version";
      };
    };

    meta = {
      description = "Userspace manager for UEFI boot entries";
      homepage = "https://github.com/rhboot/efibootmgr";
      license = "GPL-2.0-only";
      mainProgram = "efibootmgr";
    };
  }
