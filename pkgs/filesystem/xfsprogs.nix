##! xfsprogs — XFS filesystem utilities (mkfs.xfs, xfs_repair, xfs_info, etc.)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  inih,
  liburcu,
  util-linux,
}:
let
  version = "6.12.0";
in
mkDerivation {
  pname = "xfsprogs";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs/xfsprogs-${version}.tar.xz"
    ];
    hash = "sha256-CDJAckfbeRzHDe+W5+JUvW7fBD3ISoCmLzzNbj3/0yk=";
  };

  buildDeps = [
    gnumake
    pkg-config
    gettext
  ];
  runtimeDeps = [ util-linux inih liburcu ];
  propagatedDeps = [ util-linux inih liburcu ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd xfsprogs-${version}
        for f in install-sh libtool ltmain.sh config.guess config.sub depcomp missing compile; do
          if test -f "$f"; then
            sed -i '1s|^#! */bin/sh|#!'"$CONFIG_SHELL"'|; 1s|^#! */bin/bash|#!'"$CONFIG_SHELL"'|; 1s|^#! */usr/bin/env bash|#!'"$CONFIG_SHELL"'|' "$f"
          fi
        done
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-lib64=no \
          --disable-blkid
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES V=1
      '';
    }
    {
      name = "install";
      script = ''
        make install
        make install-dev
      '';
    }
  ];

  meta = {
    description = "XFS filesystem utilities (mkfs.xfs, xfs_repair, xfs_info, etc.)";
    homepage = "https://xfs.wiki.kernel.org/";
    license = "GPL-2.0-only";
  };
}
