##! ethtool — Utility for querying/controlling network device driver and hardware
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "7.1";
in
  mkDerivation {
    pname = "ethtool";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Ethtool identifies itself and returns success.";
        "files" = {};
        "input" = "The packaged network-device inspection executable.";
        "operation" = "Request the tool's version without changing a device.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/ethtool\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and result.stdout.startswith(\"ethtool version \")\nprint(\"ethtool data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ethtool data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ethtool rejects the unrecognized option.";
        "files" = {};
        "input" = "A command-line option that ethtool does not define.";
        "operation" = "Invoke ethtool with the unknown option.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/ethtool\", \"--aos-invalid-option\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"ethtool rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "ethtool rejected invalid input\n";
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
        "https://mirrors.kernel.org/pub/software/network/ethtool/ethtool-${version}.tar.xz"
      ];
      hash = "sha256-TXjCbtwCVbyS9LmVtf1mEI11/5Zu1GlPYCWm03C8JJY=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ethtool-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin
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
          make install
        '';
      }
    ];

    meta = {
      description = "ethtool — utility for controlling network drivers and hardware";
      homepage = "https://mirrors.edge.kernel.org/pub/software/network/ethtool/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-ethtool";
        tool = self;
        command = "ethtool --version";
      };
    };
  }
