##! e2fsprogs — Utilities for ext2/ext3/ext4 filesystems
{
  lib,
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
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "e2fsprogs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "E2fsprogs creates a consistent filesystem image.";
        "files" = {};
        "input" = "A request for a 4 MiB ext2 filesystem image.";
        "operation" = "Create the filesystem and check it read-only with e2fsck.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/mke2fs"
              "-q"
              "-t"
              "ext2"
              "-F"
              "filesystem.img"
              "4096"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/sbin/e2fsck"
              "-f"
              "-n"
              "filesystem.img"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mke2fs rejects the invalid geometry with status 1.";
        "files" = {};
        "input" = "A request for an ext2 filesystem containing only one block.";
        "operation" = "Attempt to construct the undersized filesystem.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/mke2fs"
              "-q"
              "-t"
              "ext2"
              "-F"
              "undersized.img"
              "1"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

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

          # Source generators and installation helpers execute in the build
          # sandbox, where host-global shell interpreters are unavailable.
          for script in \
            config/parse-types.sh config/config.guess config/config.sub \
            config/install-sh config/mkinstalldirs config/ltmain.sh \
            lib/et/compile_et.sh.in lib/ss/mk_cmds.sh.in \
            util/get-ver util/install-symlink.in; do
            sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$script"
          done
          test "$(grep -F -c ' /bin/sh $ac_aux_dir/parse-types.sh' configure)" -eq 2
          sed -i \
            's| /bin/sh $ac_aux_dir/parse-types.sh| "$CONFIG_SHELL" $ac_aux_dir/parse-types.sh|g' \
            configure
          test "$(grep -F -c 'INSTALL_SYMLINK = /bin/sh ' MCONFIG.in)" -eq 1
          sed -i 's|INSTALL_SYMLINK = /bin/sh |INSTALL_SYMLINK = $(SHELL) |' \
            MCONFIG.in

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
          "$CONFIG_SHELL" ./configure \
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
          make SHELL="$CONFIG_SHELL" -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" install
          make SHELL="$CONFIG_SHELL" install-libs

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
