##! e2fsprogs — Utilities for ext2/ext3/ext4 filesystems
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  util-linux,
  bash,
  coreutils,
  diffutils,
  gawk,
  grep,
  sed,
  stdenv,
  buildPackages,
}: let
  version = "1.47.4";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "e2fsprogs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/e2fsprogs/e2fsprogs-${version}.tar.gz"
      ];
      hash = "sha256-LOwF85wg7mIfFJJhlWZOZuYBcZCsjku9sW2GCC5Dxdo=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps =
      [
        bash
        coreutils
        diffutils
        gawk
        grep
        sed
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );
    propagatedDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [util-linux];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd e2fsprogs-${version}

          # This generator runs on the scheduler during cross builds.
          sed -i \
            's|/bin/echo|${buildPackages.coreutils}/bin/echo|g' \
            config/parse-types.sh
        '';
      }
      {
        name = "configure";
        # Binaries in $out/sbin link against libext2fs/libcom_err/libe2p
        # shipped in $out/lib. Without an explicit -rpath, the produced
        # binaries fall back on ld.so's default search path and fail with
        # "libe2p.so.2: cannot open shared object file" at runtime —
        # which manifests as systemd's "status=127/n/a" exit code because
        # the dynamic loader aborts before `main` runs.
        script = ''
          ${
            if isDarwinCross
            then ''
              # e2fsprogs builds subst and symlinks for the Linux build
              # machine. Keep their compiler clear of the target SDK and
              # arm64-only PAC hardening.
              native_cc=${buildPackages.cc}/bin/cc
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc-for-build <<EOF
              #!$CONFIG_SHELL
              native_hardening=
              for token in \$AOS_HARDENING_ENABLE; do
                case "\$token" in
                  pacret) ;;
                  *) native_hardening="\$native_hardening \$token" ;;
                esac
              done
              export AOS_HARDENING_ENABLE="\$native_hardening"
              unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc-for-build
              export BUILD_CC="$PWD/.aos-build-tools/cc-for-build"
              export BUILD_CFLAGS=
              export BUILD_LDFLAGS=
            ''
            else ""
          }
          export LDFLAGS="-Wl,-rpath,$out/lib ''${LDFLAGS:-}"
          ./configure \
            $configureFlags \
            --prefix=$out \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--enable-bsd-shlibs"
            else "--enable-elf-shlibs"
          } \
            ${
            if stdenv.hostPlatform.isDarwin
            then ""
            else "--disable-libblkid --disable-libuuid --disable-uuidd"
          } \
            --disable-fsck
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
          make install-libs

          # Upstream installs host-global shell paths that do not exist on AOS.
          for script in \
            "$out/bin/compile_et" \
            "$out/bin/mk_cmds" \
            "$out/sbin/e2scrub" \
            "$out/sbin/e2scrub_all"; do
            [ -f "$script" ] || continue
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$script"
          done

          # The installed source generators must work from this package's
          # closure instead of relying on ambient host utilities.
          sed -i \
            -e 's|^AWK=gawk$|AWK=${gawk}/bin/gawk|' \
            -e 's|^SED=sed$|SED=${sed}/bin/sed|' \
            -e 's| sed -e | ${sed}/bin/sed -e |' \
            -e 's|`basename |`${coreutils}/bin/basename |' \
            -e 's| cmp -s | ${diffutils}/bin/cmp -s |' \
            -e 's|grep "|${grep}/bin/grep "|' \
            -e 's|rm -f |${coreutils}/bin/rm -f |g' \
            -e 's|rm "|${coreutils}/bin/rm "|g' \
            -e 's|mv -f |${coreutils}/bin/mv -f |g' \
            -e 's|chmod a-w |${coreutils}/bin/chmod a-w |g' \
            "$out/bin/compile_et" \
            "$out/bin/mk_cmds"

          # e2initrd_helper embeds a build-time gcc store path — a text
          # reference that drags ~230 MB of compiler into e2fsprogs' closure.
          rm -f "$out/lib/e2initrd_helper"
        '';
      }
    ];

    meta = {
      description = "Utilities for ext2/ext3/ext4 filesystems";
      homepage = "http://e2fsprogs.sourceforge.net/";
      license = "GPL-2.0-only";
    };
  }
