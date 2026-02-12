# util-linux — Miscellaneous system utilities
{ mkDerivation, fetchurl, make, pkg-config }:

let version = "2.40.2"; in
mkDerivation {
  pname = "util-linux";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-${version}.tar.xz"
    ];
    hash = "sha256-14s3pm9ZItcO3zvfsBprM9NO08PK/WYoIDsqK2fI6LM=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd util-linux-${version}
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
