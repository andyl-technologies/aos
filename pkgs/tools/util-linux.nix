##! util-linux — Miscellaneous system utilities
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  ncurses,
  libselinux,
  libxcrypt,
  audit,
  readline,
  libutempter,
  libcap-ng,
  gettext,
  python3,
  cython,
  linux-pam,
  sqlite,
}: let
  # 2.42.1 is the first stable release including
  # mount --beneath (commit cbf05f69 by Karel Zak, 2025-08-11; in-tree
  # at sys-utils/mount.c:562,720,989 and
  # libmount/src/hook_mount.c:547-548). Required by the apm-side
  # stage-2 /etc swap (spec v12 §7.1 Phase B).
  version = "2.42.1";
in
  mkDerivation {
    pname = "util-linux";
    inherit version;

    src = fetchurl {
      urls = [
        "https://cdn.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-${version}.tar.xz"
      ];
      hash = "sha256-gukVjrEqmwtWnYThaH/tndGP6JzNjvWsNCchinwNf38=";
    };

    buildDeps = [
      gnumake
      pkg-config
      gettext
      python3
      cython
    ];
    runtimeDeps = [
      zlib
      ncurses
      libselinux
      # sulogin calls crypt(3) to compare root's shadow hash with the
      # entered password; util-linux's configure fails with "required
      # crypt function not available" if libxcrypt (or glibc's bundled
      # libcrypt) isn't on the link line.
      libxcrypt
      audit
      readline
      libutempter
      libcap-ng
      gettext
      python3
      linux-pam
      sqlite
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
            --disable-static \
            --enable-shared \
            --with-python=3 \
            --without-systemd \
            --without-ncurses \
            --with-ncursesw \
            --with-readline \
            --without-slang \
            --with-utempter \
            --without-btrfs \
            --with-selinux \
            --with-audit \
            --without-udev \
            --without-cryptsetup \
            --without-econf \
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

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-util-linux";
        tool = self;
        command = "mount --version && su --version && lastlog2 --version && wall --version";
      };

      mount = testing.mkLinkCheck {
        pname = "link-libmount";
        library = self;
        libs = ["-lmount"];
        testSource = ''
          #include <libmount/libmount.h>

          int main(void) {
              struct libmnt_context *context = mnt_new_context();
              if (context == NULL) return 1;
              mnt_free_context(context);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "util-linux — miscellaneous system utilities for Linux";
      homepage = "https://github.com/util-linux/util-linux";
      license = "GPL-2.0-or-later";
    };
  }
