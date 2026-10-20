##! fuse-overlayfs — Overlay filesystem implementation for FUSE
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  pkg-config,
  fuse3,
}: let
  version = "1.17";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "fuse-overlayfs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Fuse-overlayfs returns success and reports its version.";
        "files" = {};
        "input" = "The packaged fuse-overlayfs implementation's release identity.";
        "operation" = "Request its version without mounting a filesystem.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/fuse-overlayfs\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"fuse-overlayfs\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"fuse-overlayfs operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "fuse-overlayfs operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Fuse-overlayfs rejects the unsupported option.";
        "files" = {};
        "input" = "A fuse-overlayfs invocation containing an unknown option.";
        "operation" = "Parse the invalid option without mounting a filesystem.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/fuse-overlayfs\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"fuse-overlayfs rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "fuse-overlayfs rejected invalid input\n";
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
      urls = ["https://github.com/containers/fuse-overlayfs/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-zv/+z7sAGyeE8ZrzRPJ+rgezGk+qONNFtzivlrK+xZ4=";
    };

    buildDeps = [gnumake autoconf automake libtool pkg-config];
    runtimeDeps = [fuse3];
    propagatedDeps = [];

    preConfigure = ''
      export ACLOCAL_PATH="${pkg-config}/share/aclocal"
      autoreconf -fiv
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-fuse-overlayfs";
        tool = self;
        command = "fuse-overlayfs --version";
      };
    };

    meta = {
      description = "Overlay filesystem implementation for unprivileged containers";
      homepage = "https://github.com/containers/fuse-overlayfs";
      license = "GPL-3.0-only";
      mainProgram = "fuse-overlayfs";
    };
  }
