##! pkgs/networking/ipset.nix — IP set framework userspace tool
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "7.24";
in
  mkDerivation {
    pname = "ipset";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "IpSet documents IPv4 and IPv6 hash entries and their create options.";
        "files" = {};
        "input" = "The built-in help request for the hash:ip set type.";
        "operation" = "Translate the request and inspect its type-specific grammar offline.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/ipset-translate\", \"help\", \"hash:ip\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"hash:ip type specific options\" in result.stdout and \"family inet|inet6\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"ipset operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ipset operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "IpSet rejects the unknown type without contacting the kernel.";
        "files" = {};
        "input" = "A help request naming an unknown set type.";
        "operation" = "Resolve the nonexistent set type through the translator.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/ipset-translate\", \"help\", \"unknown:type\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unknown\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"ipset rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "ipset rejected invalid input\n";
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
        "https://ipset.netfilter.org/ipset-${version}.tar.bz2"
      ];
      hash = "sha256-++NCTf8iLBy15cNNOLZFJLIhfOgCJsFP3LsTsp6jYRI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libmnl
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ipset-${version}
        '';
      }
      {
        name = "configure";
        # `--with-kmod=no` skips the in-tree kernel-module build —
        # ipset's tarball ships its own copy of the kernel modules
        # and would otherwise try to invoke a kbuild from here. We
        # get the modules from the AOS kernel package instead (see
        # pkgs/kernel/config/networking.config).
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static \
            --with-kmod=no
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
      description = "ipset — administration tool for IP sets";
      homepage = "https://ipset.netfilter.org/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-ipset";
        tool = self;
        # `ipset help` works without root and without kernel modules
        # loaded. We rely on the kernel-side check (kconfig in
        # pkgs/kernel/config/networking.config) to cover the `ipset
        # list / create` paths that need an ip_set kmod present.
        command = "ipset help";
      };
    };
  }
