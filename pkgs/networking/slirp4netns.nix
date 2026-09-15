##! slirp4netns — User-mode networking for unprivileged namespaces
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  pkg-config,
  glib,
  libcap,
  libseccomp,
  libslirp,
  stdenv,
  buildPackages,
}: let
  version = "1.3.5";
in
  mkDerivation {
    pname = "slirp4netns";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Slirp4netns reports its CIDR and port-forwarding controls.";
        "files" = {};
        "input" = "The userspace network namespace helper command-line contract.";
        "operation" = "Render supported namespace and network options without opening a namespace.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/slirp4netns\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"--cidr\" in result.stdout and \"--api-socket\" in result.stdout\nprint(\"slirp4netns operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "slirp4netns operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Slirp4netns rejects the malformed CIDR without opening a tap device.";
        "files" = {};
        "input" = "A malformed virtual-network CIDR.";
        "operation" = "Validate the CIDR before joining the named process namespace.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/slirp4netns\", \"--cidr\", \"qualification-invalid\", \"999999\", \"tap0\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"invalid CIDR\" in result.stderr\n\nsys.stderr.write(\"slirp4netns rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "slirp4netns rejected invalid input\n";
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
      urls = ["https://github.com/rootless-containers/slirp4netns/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-on7UxzEWFlFrVgFcx0+gbGQx9cjrra8zHA4IFQ0ahM4=";
    };

    buildDeps =
      if stdenv.isCross
      then [
        buildPackages.gnumake
        buildPackages.autoconf
        buildPackages.automake
        buildPackages.libtool
        buildPackages.pkg-config
      ]
      else [gnumake autoconf automake libtool pkg-config glib.dev];
    runtimeDeps = [glib libcap libseccomp libslirp];
    propagatedDeps = [];

    preConfigure = ''
      export ACLOCAL_PATH="${
        if stdenv.isCross
        then buildPackages.pkg-config
        else pkg-config
      }/share/aclocal"
      ${
        if stdenv.isCross
        then ''
          # Keep Autoconf and pkg-config native while resolving GLib headers
          # and linker names from the selected target outputs.
          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          export CFLAGS="''${CFLAGS:-} -I${glib.dev}/include/glib-2.0 -I${glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"
        ''
        else ""
      }
      autoreconf -fiv
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-slirp4netns";
        tool = self;
        command = "slirp4netns --version";
      };
    };

    meta = {
      description = "User-mode networking for unprivileged network namespaces";
      homepage = "https://github.com/rootless-containers/slirp4netns";
      license = "GPL-2.0-only";
      mainProgram = "slirp4netns";
    };
  }
