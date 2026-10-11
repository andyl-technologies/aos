##! semodule-utils — SELinux module utilities (semodule_package, etc.)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libsepol,
}: let
  version = "3.11";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "semodule-utils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The module package round trip preserves the complete compiled policy module.";
        "files" = {};
        "input" = "A compiled SELinux module with one process-signal allow rule.";
        "operation" = "Package the module, unpack it, and compare the recovered module bytes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import base64, pathlib, subprocess\nencoded = \"jf98+Q8AAABTRSBMaW51eCBNb2R1bGUCAAAAGAAAAAEAAAAIAAAAAAAAAA0AAABxdWFsaWZpY2F0aW9uAwAAADEuMEAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAHAAAAAAAAAAEAAAABAAAAAQAAAAAAAABwcm9jZXNzBgAAAAEAAABzaWduYWwBAAAAAQAAAAgAAAABAAAAAAAAAG9iamVjdF9yQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAABAAAAAQAAAAYAAAABAAAAAQAAAAEAAAAAAAAAQAAAAAAAAAAAAAAAaW5pdF90AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAQAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAQAAAAAEAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAQAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAEAAABAAAAAQAAAAAEAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABwAAAHByb2Nlc3MBAAAAAQAAAAEAAAABAAAACAAAAG9iamVjdF9yAgAAAAEAAAABAAAAAQAAAAYAAABpbml0X3QBAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"\nmodule = base64.b64decode(encoded)\npathlib.Path(\"qualification.mod\").write_bytes(module)\npackage = subprocess.run([\"@out@/bin/semodule_package\", \"-o\", \"qualification.pp\", \"-m\", \"qualification.mod\"], capture_output=True)\nassert package.returncode == 0, package.stderr\nunpack = subprocess.run([\"@out@/bin/semodule_unpackage\", \"qualification.pp\", \"unpacked.mod\"], capture_output=True)\nassert unpack.returncode == 0, unpack.stderr\nassert pathlib.Path(\"unpacked.mod\").read_bytes() == module\nprint(\"semodule-utils operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "semodule-utils operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Semodule-unpackage rejects the truncated header.";
        "files" = {
          "invalid.pp" = "bad";
        };
        "input" = "A truncated SELinux module package header.";
        "operation" = "Attempt to unpack the malformed module package.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/semodule_unpackage\", \"invalid.pp\", \"invalid.mod\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"truncated\" in result.stderr\n\nsys.stderr.write(\"semodule-utils rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "semodule-utils rejected invalid input\n";
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
      urls = [
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-a21Hqw81/hwJvaDGKCHI2XoMvn9ulASzON973gGCxPQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [libsepol];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/semodule-utils
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out BINDIR=$out/bin \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out BINDIR=$out/bin
        '';
      }
    ];

    meta = {
      description = "semodule-utils — SELinux module packaging and expansion tools";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "GPL-2.0-or-later";
    };
  }
