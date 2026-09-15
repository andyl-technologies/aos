##! ZFS — OpenZFS filesystem and volume manager
# OpenZFS is an out-of-tree module, so each release builds only against a
# bounded range of kernel versions (its META file's Linux-Minimum and
# Linux-Maximum). A release older than the pinned kernel fails deep in the
# kernel probe with a configure error rather than at evaluation, so the pin
# here has to move with pkgs/kernel/_source.nix.
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  util-linux,
  openssl,
  zlib,
  libtirpc,
  bash,
  perl,
  python3,
  kmod,
  elfutils,
  dwarves,
  kernel ? null,
}: let
  version = "2.4.4";
  kernelArch = stdenv.hostPlatform.linuxArch;
  # Kernel SDK helpers execute on the build machine, including while they
  # finalize modules for a cross target.
  buildElfutils =
    if stdenv.isCross
    then buildPackages.elfutils
    else elfutils;
  buildZlib =
    if stdenv.isCross
    then buildPackages.zlib
    else zlib;
in
  mkDerivation {
    pname = "zfs";
    inherit version;
    outputs = ["out" "dev"];

    src = fetchurl {
      urls = [
        "https://github.com/openzfs/zfs/releases/download/zfs-${version}/zfs-${version}.tar.gz"
      ];
      hash = "sha256-Kjxw1Vo3zHFhipWmDoGtZlMCAesRjTd0Hcku/PhIyLE=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if kernel == null
        then []
        else [bash perl python3 kmod elfutils dwarves]
      );
    runtimeDeps = [
      util-linux
      openssl
      zlib
      libtirpc
    ];
    propagatedDeps = [];
    disallowedReferences = lib.optional (kernel != null) kernel.dev;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd zfs-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Kbuild invokes the exact kernel tree's objtool while compiling
          # feature probes. objtool links against libelf, which is a build
          # dependency of the kernel SDK rather than part of its output.
          export LD_LIBRARY_PATH="${buildElfutils}/lib:${buildZlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export ARCH=${kernelArch}
          configure_args=(
            --prefix="$out"
            --sysconfdir="$out/etc"
            --with-config=${
            if kernel == null
            then "user"
            else "all"
          }
            --with-mounthelperdir="$out/sbin"
            --with-udevdir="$out/lib/udev"
            --with-systemdunitdir="$out/lib/systemd/system"
            --with-systemdpresetdir="$out/lib/systemd/system-preset"
            --enable-sysvinit=no
            --disable-static
          )
          ${
            if kernel == null
            then ""
            else ''
              configure_args+=(
                --with-linux=${kernel.dev}/lib/modules/${kernel.version}/build
                --with-linux-obj=${kernel.dev}/lib/modules/${kernel.version}/build
              )
            ''
          }
          if ! ./configure "''${configure_args[@]}"; then
            for probe_log in build/build.log*; do
              [ -f "$probe_log" ] || continue
              echo "OpenZFS kernel probe log: $probe_log" >&2
              cat "$probe_log" >&2
            done
            exit 1
          fi
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${buildElfutils}/lib:${buildZlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export ARCH=${kernelArch}
          ${
            if kernel == null
            then ""
            else ''
              export KCFLAGS="''${KCFLAGS:-} -ffile-prefix-map=${kernel.dev}=/build/kernel-sdk"
            ''
          }
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          export LD_LIBRARY_PATH="${buildElfutils}/lib:${buildZlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export ARCH=${kernelArch}

          # Override hardcoded paths that would install outside the store
          make install \
            ${
            if kernel == null
            then ""
            else ''INSTALL_MOD_PATH="$out"''
          } \
            ${
            if kernel == null
            then ""
            else ''INSTALL_MOD_STRIP=1''
          } \
            i_tdir=$out/share/initramfs-tools \
            initconfdir=$out/etc/default \
            dracutdir=$out/lib/dracut \
            bashcompletiondir=$out/share/bash-completion/completions

          # The upstream install target includes its full functional test
          # suite. It belongs in a dedicated test output, not on a production
          # host, and its compiled fixtures retain compiler paths.
          rm -rf "$out/share/zfs/zfs-tests"

          # Interactive kstat formatters written in Python. Keeping them would
          # put a Python interpreter in the runtime closure of every image that
          # carries ZFS, and their `/usr/bin/env` shebangs do not resolve in an
          # AOS root. Everything they report is read from
          # /proc/spl/kstat/zfs/arcstats, which is where the ARC metrics
          # service takes its figures.
          rm -f "$out/bin/dbufstat" "$out/bin/zarcstat" \
            "$out/bin/zarcsummary" "$out/bin/zilstat"
          rm -f "$out/share/man/man1/dbufstat.1" "$out/share/man/man1/zarcstat.1" \
            "$out/share/man/man1/zarcsummary.1" "$out/share/man/man1/zilstat.1"

          # Kernel and userspace development files are useful to downstream
          # builds, but production images need only the built modules, shared
          # libraries, commands, and service integration.
          mkdir -p "$dev/lib"
          mv "$out/include" "$dev/include"
          if [ -d "$out/src" ]; then
            mv "$out/src" "$dev/src"
          fi
          mv "$out/lib/pkgconfig" "$dev/lib/pkgconfig"
          for libtool_archive in "$out/lib/"*.la; do
            if [ -f "$libtool_archive" ]; then
              mv "$libtool_archive" "$dev/lib/"
            fi
          done
          sed -i \
            -e "s|^includedir=.*|includedir=$dev/include|" \
            "$dev/lib/pkgconfig/"*.pc
          sed -i \
            -e "s|^libdir=.*|libdir='$out/lib'|" \
            "$dev/lib/"*.la

          # zvol_id is installed below lib/udev rather than bin/libexec, so the
          # generic fixup pass does not recognize it as a runtime executable.
          # Remove its compile-time include paths explicitly.
          strip --strip-debug "$out/lib/udev/zvol_id"
        '';
      }
    ];

    meta = {
      description = "OpenZFS — advanced filesystem and volume manager";
      homepage = "https://openzfs.org";
      license = "CDDL-1.0";
    };

    passthru = {
      inherit kernel;
    };
  }
