##! glusterfs-client — GlusterFS client libraries, translators, and mount tools
{
  mkDerivation,
  fetchurl,
  stdenv,
  automake,
  gnumake,
  pkg-config,
  gettext,
  bash,
  coreutils,
  file,
  flex,
  gawk,
  grep,
  sed,
  bison,
  python3,
  rpcsvc-proto,
  util-linux,
  openssl,
  acl,
  attr,
  zlib,
  libtirpc,
  libaio,
  liburing,
  liburcu,
  fuse3,
  readline,
  libxml2,
  curl,
  libunistring,
  libselinux,
  gperftools,
  xxhash,
}: let
  version = "11.1";
in
  mkDerivation {
    pname = "glusterfs-client";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gluster.org/pub/gluster/glusterfs/11/${version}/glusterfs-${version}.tar.gz"
      ];
      hash = "sha256-ajG4RQ0CzRL0f0VxwDHp1rhwUnmg6JcK6aBeHIff+3Y=";
    };

    buildDeps = [
      automake
      gnumake
      pkg-config
      gettext
      bash
      file
      flex
      bison
      python3
      rpcsvc-proto
    ];
    runtimeDeps = [
      bash
      coreutils
      gawk
      grep
      sed
      util-linux
      openssl
      acl
      attr
      zlib
      libtirpc
      libaio
      liburing
      liburcu
      fuse3
      readline
      libxml2
      curl
      libunistring
      libselinux
      gperftools
      xxhash
      python3
    ];
    # Consumers need libuuid's pkg-config metadata to resolve the public
    # glusterfs-api.pc `Requires: uuid` edge and select the current gfapi ABI.
    propagatedDeps = [util-linux];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd glusterfs-${version}

          # Gluster's release archive deliberately ships placeholders for
          # these GNU build-identity helpers. Use the audited AOS Automake
          # copies that match the hermetic toolchain.
          cp ${automake}/share/automake-*/config.guess config.guess
          cp ${automake}/share/automake-*/config.sub config.sub
          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure

          # The client mount helpers must invoke the exact AOS util-linux
          # programs rather than relying on a mutable FHS filesystem.
          sed -i 's|"/bin/umount"|"${util-linux}/bin/umount"|g' \
            libglusterfs/src/glusterfs/compat.h
          sed -i 's|"/bin/mount"|"${util-linux}/bin/mount"|g' \
            contrib/fuse-lib/mount-gluster-compat.h

          # Gluster ships an Automake py-compile helper that imports the
          # removed Python imp module. importlib provides the same cache-path
          # operation on current Python releases.
          sed -i \
            -e 's/import sys, os, py_compile, imp/import sys, os, py_compile, importlib.util/g' \
            -e "s/hasattr(imp, 'get_tag')/hasattr(importlib.util, 'cache_from_source')/g" \
            -e 's/imp\.cache_from_source/importlib.util.cache_from_source/g' \
            py-compile

          # Nix store outputs cannot carry privileged ownership or setuid
          # mode bits. Install the complete FUSE helper as an ordinary binary;
          # a system module can grant privileges through a controlled wrapper.
          sed -i \
            -e '/^-chown root .*fusermount-glusterfs$/d' \
            -e '/^\tchmod u+s .*fusermount-glusterfs$/d' \
            contrib/fuse-util/Makefile.in

          mkdir -p .aos-build-tools
          cat > .aos-build-tools/cpp <<'EOF'
          #!${bash}/bin/bash
          exec "$CC" -E -x c "$@"
          EOF
          chmod 0755 .aos-build-tools/cpp

          # curl's installed libtool archive still carries the placeholder
          # used while its libunistring input was constructed. Gluster links
          # its default cloud-sync plugin through libtool, so give that link a
          # writable copy whose dependency points at the final AOS package.
          mkdir -p .aos-build-tools/lib
          sed \
            's|/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-libunistring-1.4.2|${libunistring}|g' \
            ${curl}/lib/libcurl.la > .aos-build-tools/lib/libcurl.la

          # Generated Python entry points run from the immutable package
          # closure rather than through an FHS interpreter path.
          find . -type f -name '*.py' | while read file; do
            if head -n 1 "$file" | grep -Eq '^#! */usr/bin/(env +)?python'; then
              sed -i '1s|.*|#!${python3}/bin/python3|' "$file"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          export PATH="$PWD/.aos-build-tools:$PATH"
          export LDFLAGS="-L$PWD/.aos-build-tools/lib''${LDFLAGS:+ $LDFLAGS}"
          am_cv_python_version=$(${python3}/bin/python3 -c \
            'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
          export am_cv_python_version

          # The named client package keeps the complete libgfapi and FUSE
          # client surface while excluding Gluster's storage-server role.
          PYTHON=${python3}/bin/python3 \
            $CONFIG_SHELL ./configure \
              $configureFlags \
              --build=${stdenv.buildPlatform.config} \
              --host=${stdenv.hostPlatform.config} \
              --prefix="$out" \
              --sysconfdir="$out/etc" \
              --localstatedir="$out/var" \
              --with-mountutildir="$out/sbin" \
              --with-initdir="$out/etc/init.d" \
              --with-systemddir="$out/lib/systemd/system" \
              --without-server
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.aos-build-tools:$PATH"
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          make install

          # The mount helper invokes standard text and filesystem tools by
          # name. Give it an immutable runtime search path containing exactly
          # the AOS implementations it uses.
          sed -i \
            '2i export PATH=${coreutils}/bin:${gawk}/bin:${grep}/bin:${sed}/bin:${util-linux}/bin:${attr}/bin' \
            "$out/sbin/mount.glusterfs"

          find "$out" -type f | while read file; do
            [ "$(head -c 2 "$file")" = '#!' ] || continue

            firstLine=$(head -n 1 "$file")
            case "$firstLine" in
              '#!/bin/sh'*|'#!/bin/bash'*|'#!/usr/bin/env sh'*|'#!/usr/bin/env bash'*)
                sed -i '1s|.*|#!${bash}/bin/bash|' "$file"
                ;;
            esac
          done

          ! find "$out" -type f -exec \
            grep -aEl '(^|[^[:alnum:]_./-])(/bin/(sh|bash|mount|umount)|/usr/bin/env[[:space:]]+(sh|bash))' {} + \
            | grep .

          test -f "$out/lib/libgfapi.so"
          test -f "$out/lib/libgfchangelog.so"
          test -f "$out/lib/glusterfs/${version}/xlator/protocol/client.so"
          test -f "$out/lib/glusterfs/${version}/xlator/mount/fuse.so"
          test -f "$out/lib/pkgconfig/glusterfs-api.pc"
          test -x "$out/bin/fusermount-glusterfs"
          test -x "$out/sbin/mount.glusterfs"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      gfapi-link = testing.mkLinkCheck {
        pname = "lib-glusterfs-gfapi";
        library = self;
        libs = ["-lgfapi"];
        testSource = ''
          #include <glusterfs/api/glfs.h>

          int main(void) {
              ssize_t (*pread_fn)(glfs_fd_t *, void *, size_t, off_t, int,
                                  struct glfs_stat *) = glfs_pread;
              ssize_t (*pwrite_fn)(glfs_fd_t *, const void *, size_t, off_t, int,
                                   struct glfs_stat *, struct glfs_stat *) = glfs_pwrite;
              int (*fsync_fn)(glfs_fd_t *, struct glfs_stat *,
                              struct glfs_stat *) = glfs_fsync;
              int (*ftruncate_fn)(glfs_fd_t *, off_t, struct glfs_stat *,
                                  struct glfs_stat *) = glfs_ftruncate;

              return pread_fn == 0 || pwrite_fn == 0 || fsync_fn == 0 ||
                     ftruncate_fn == 0;
          }
        '';
      };
    };

    meta = {
      description = "GlusterFS client libraries, translators, and mount tools";
      homepage = "https://www.gluster.org/";
      license = "GPL-2.0-only OR LGPL-3.0-or-later";
    };
  }
