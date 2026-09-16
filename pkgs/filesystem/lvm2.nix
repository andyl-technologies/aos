##! lvm2 — Logical Volume Manager 2 tools
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libaio,
  util-linux,
  device-mapper,
}: let
  version = "2.03.42";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "lvm2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "LVM lists its configuration, physical-volume, volume-group, and logical-volume commands.";
        "files" = {};
        "input" = "The LVM command inventory.";
        "operation" = "Request help without scanning or changing block devices.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/lvm\"] + [\"help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"available lvm commands\" in result.stderr.lower() and \"pvcreate\" in result.stderr and \"lvcreate\" in result.stderr, (result.returncode, result.stdout, result.stderr)\nprint(\"lvm2 primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "lvm2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "LVM rejects the unknown command.";
        "files" = {};
        "input" = "An LVM invocation naming a command that does not exist.";
        "operation" = "Resolve the unsupported command without scanning block devices.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/lvm\"] + [\"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"no such command\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"lvm2 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "lvm2 rejected invalid input\n";
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
        "https://sourceware.org/ftp/lvm2/LVM2.${version}.tgz"
        "https://mirrors.kernel.org/sourceware/lvm2/LVM2.${version}.tgz"
      ];
      hash = "sha256-NScD71ty67ItTyUChKKbif5k1ASca/ZMaT+a9IbICB4=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libaio
      util-linux
      device-mapper
    ];
    propagatedDeps = [
      device-mapper
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd LVM2.${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=/ \
            --enable-pkgconfig \
            --enable-cmdlib \
            --enable-dmeventd=none \
            --with-thin=none \
            --with-cache=none \
            --disable-selinux \
            --disable-readline \
            --disable-editline
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install DESTDIR=$out
        '';
      }
    ];

    meta = {
      description = "Logical Volume Manager 2 tools";
      homepage = "https://sourceware.org/lvm2/";
      license = "GPL-2.0-only";
    };
  }
