##! conntrack-tools — Connection tracking userspace tools for netfilter
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnetfilter_cthelper,
  libnetfilter_cttimeout,
  libnetfilter_queue,
  libtirpc,
  service-management,
  aos-filesystem-provider,
}: let
  version = "1.4.9";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "conntrack-tools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Conntrack returns success and reports its userspace version.";
        "files" = {};
        "input" = "The packaged connection-tracking client's release identity.";
        "operation" = "Request its version without opening a netfilter socket.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([str(next(path for path in __import__(\"pathlib\").Path(\"@out@\").rglob(\"conntrack\") if path.is_file())), \"--version\"]\n, capture_output=True, text=True)\nassert result.returncode == 0 and \"conntrack\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"conntrack-tools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "conntrack-tools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Conntrack rejects the unsupported option.";
        "files" = {};
        "input" = "A conntrack invocation containing an unknown option.";
        "operation" = "Parse the invalid option without modifying kernel state.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([str(next(path for path in __import__(\"pathlib\").Path(\"@out@\").rglob(\"conntrack\") if path.is_file())), \"--aos-invalid-option\"]\n, capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"conntrack-tools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "conntrack-tools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-${version}.tar.xz"
      ];
      hash = "sha256-wVr+SIqNQIydbWHpfb0Z88WRlC9iwT32RTqWHKQjHK4=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
      libnetfilter_conntrack
      libnetfilter_cthelper
      libnetfilter_cttimeout
      libnetfilter_queue
      libtirpc
    ];
    propagatedDeps = [];

    module = ./_conntrackd;
    moduleDeps = [service-management aos-filesystem-provider];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd conntrack-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static
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
      description = "conntrack-tools — connection tracking userspace tools for netfilter";
      homepage = "https://www.netfilter.org/projects/conntrack-tools/";
      license = "GPL-2.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      evaluate = settings:
        lib.evalPackageModules {
          scope = ["package-check" "conntrackd"];
          packages = [self];
          operatorModules = [{aos.conntrackd = settings;}];
        };
      evaluated = evaluate {
        enable = true;
        mode = "sync";
        sync = {
          interface = "eth1";
          localAddress = "192.0.2.10";
          peerAddress = "192.0.2.11";
        };
      };
      disabled = evaluate {};
      invalidHashRange = evaluate {
        hashSize = 8192;
        hashLimit = 4096;
      };
      nativeTests = import ./_conntrackd/native-tests.nix {inherit lib evaluated disabled invalidHashRange;};
      contractHolds = builtins.all (value: value) (builtins.attrValues nativeTests);
    in {
      config =
        if contractHolds
        then
          pkgs.runCommand "conntrackd-native-module" {} ''
            test -x ${self}/sbin/conntrackd
            touch "$out"
          ''
        else throw "the conntrackd native module contract checks failed";
    };
  }
