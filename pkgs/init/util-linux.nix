##! util-linux — Miscellaneous system utilities
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  zlib,
  ncurses,
  libselinux,
  audit,
}: let
  version = "2.41";
in
  mkDerivation {
    pname = "util-linux";
    inherit version;

    src = fetchurl {
      urls = [
        "https://cdn.kernel.org/pub/linux/utils/util-linux/v2.41/util-linux-${version}.tar.xz"
      ];
      hash = "sha256-ge6Ts8/f6318QJDO3rode7zpFB/QtQG2hrP+R13cpMY=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [
      zlib
      ncurses
      libselinux
      audit
    ];
    propagatedDeps = [libselinux];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd util-linux-${version}
          # Fix shebangs: /bin/bash doesn't exist in Nix sandbox
          for f in tools/all_syscalls tools/all_errnos tools/config-gen tools/git-tp-sync tools/*.sh; do
            if [ -f "$f" ]; then
              sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-nls \
            --disable-static \
            --enable-shared \
            --without-python \
            --without-systemd \
            --without-ncurses \
            --with-ncursesw \
            --without-readline \
            --without-tinfo \
            --without-slang \
            --without-utempter \
            --without-cap-ng \
            --without-btrfs \
            --with-selinux \
            --with-audit \
            --without-udev \
            --without-cryptsetup \
            --without-econf \
            --disable-liblastlog2 \
            --disable-pylibmount \
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
            --enable-unshare \
            --disable-makeinstall-chown \
            --disable-makeinstall-setuid
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
      description = "util-linux — miscellaneous system utilities for Linux";
      homepage = "https://github.com/util-linux/util-linux";
      license = "GPL-2.0-or-later";
    };
  }
