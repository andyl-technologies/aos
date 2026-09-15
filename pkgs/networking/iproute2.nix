##! iproute2 — Linux networking utilities
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
  bison,
  flex,
}: let
  version = "7.2.0";
in
  mkDerivation {
    pname = "iproute2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Ss accepts the compound port filter and completes the local socket query.";
        "files" = {};
        "input" = "A socket query filtered by both source port 1 and destination port 2.";
        "operation" = "Parse and execute the filter through ss without printing headers.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/ss\", \"-H\", \"sport = :1 and dport = :2\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\nprint(\"iproute2 operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "iproute2 operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ss rejects the malformed address predicate.";
        "files" = {};
        "input" = "A socket filter containing an invalid address prefix.";
        "operation" = "Parse the malformed destination predicate.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/ss\", \"-H\", \"dst\", \"qualification\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"cannot parse\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"iproute2 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "iproute2 rejected invalid input\n";
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
        "https://mirrors.kernel.org/pub/linux/utils/net/iproute2/iproute2-${version}.tar.xz"
      ];
      hash = "sha256-TC+hJMLPCv18o00e6sumugSKVvY3Tiqrk9r729TuqcA=";
    };

    buildDeps = [
      gnumake
      pkg-config
      bison
      flex
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    # iproute2's netlink code uses [0]/[1] trailing-array idioms that
    # -fstrict-flex-arrays=3 narrows to a fixed size, so _FORTIFY_SOURCE
    # aborts `ss` at runtime ("buffer overflow detected"). Step this package
    # down to strict-flex-arrays=1 (nixpkgs' default level) — fortify3 stays on.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd iproute2-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SBINDIR=$out/sbin -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SBINDIR=$out/sbin
        '';
      }
    ];

    meta = {
      description = "iproute2 — Linux networking and traffic control utilities";
      homepage = "https://wiki.linuxfoundation.org/networking/iproute2";
      license = "GPL-2.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-iproute2";
        tool = self;
        command = "ip -V 2>&1";
      };
    };
  }
