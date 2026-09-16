##! passt — Userspace networking for virtual machines and namespaces
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
}: let
  version = "2026_07_28.f8df3f1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "passt";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents its invocation contract.";
        "files" = {};
        "input" = "The packaged passt command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/passt\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"usage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"passt operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "passt operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing external I/O.";
        "files" = {};
        "input" = "A passt invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without accessing a device or service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/passt\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"passt rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "passt rejected invalid input\n";
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
      urls = ["https://passt.top/passt/snapshot/passt-${version}.tar.gz"];
      hash = "sha256-Kz7/s9zR9rG0baOiQZwDdQjSS8OfkFE7u7Zg6OtlIOU=";
    };
    buildDeps = [gnumake buildPackages.glibc.bin];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd passt-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" seccomp.sh doc/demo.sh
          sed -i \
            's|PAGE_SIZE=$(shell getconf PAGE_SIZE)|PAGE_SIZE=$(shell ${buildPackages.glibc.bin}/bin/getconf PAGE_SIZE)|' \
            Makefile
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" VERSION=${version}'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out" VERSION=${version}
          "$out/bin/passt" --version 2>&1 | grep -q '${version}'
          test -x "$out/bin/pasta"
          test -x "$out/bin/passt-repair"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-passt";
        tool = self;
        command = "passt --version 2>&1 | grep -q '${version}' && pasta --version 2>&1 | grep -q '${version}'";
      };
    };
    meta = {
      description = "Provides unprivileged socket transport for virtual machines and network namespaces";
      homepage = "https://passt.top/passt/about/";
      license = "GPL-2.0-or-later AND BSD-3-Clause";
      mainProgram = "passt";
    };
  }
