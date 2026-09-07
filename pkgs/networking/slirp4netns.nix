##! slirp4netns — User-mode networking for unprivileged namespaces
{
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
  version = "1.3.3";
in
  mkDerivation {
    pname = "slirp4netns";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/rootless-containers/slirp4netns/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-jSRTmWeFC62pRNVkWeuekWc1fVeznoZNle19bA3QKY0=";
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
