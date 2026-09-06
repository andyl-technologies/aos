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

    buildDeps = [gnumake autoconf automake libtool pkg-config glib.dev];
    runtimeDeps = [glib libcap libseccomp libslirp];
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
