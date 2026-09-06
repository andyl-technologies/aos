##! fuse-overlayfs — Overlay filesystem implementation for FUSE
{
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
    pname = "fuse-overlayfs";
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
