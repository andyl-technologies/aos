# util-linux — Miscellaneous system utilities
{ mkDerivation, fetchurl, sources, versions, make, pkg-config }:

mkDerivation {
  name = "util-linux-${versions.init.util-linux}";
  version = versions.init.util-linux;

  src = fetchurl {
    inherit (sources.util-linux) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd util-linux-${versions.init.util-linux}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --disable-static \
          --enable-shared \
          --without-python \
          --without-systemd \
          --without-ncurses \
          --without-ncursesw \
          --without-readline \
          --without-tinfo \
          --without-slang \
          --without-utempter \
          --without-cap-ng \
          --without-btrfs \
          --without-selinux \
          --without-audit \
          --disable-wall \
          --disable-login \
          --disable-su \
          --disable-sulogin \
          --disable-nologin \
          --disable-runuser \
          --disable-chfn-chsh \
          --disable-newgrp \
          --disable-vipw \
          --disable-pg \
          --disable-write \
          --disable-mesg \
          --enable-libblkid \
          --enable-libmount \
          --enable-libfdisk \
          --enable-libuuid \
          --enable-libsmartcols \
          --enable-fsck \
          --enable-mount \
          --enable-losetup \
          --enable-blkid \
          --enable-lsblk \
          --enable-nsenter \
          --enable-unshare
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "util-linux — miscellaneous system utilities for Linux";
    homepage = "https://github.com/util-linux/util-linux";
    license = "GPL-2.0-or-later";
  };
}
