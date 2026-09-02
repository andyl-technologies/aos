##! sbsigntools — UEFI Secure Boot signing tools
{
  mkDerivation,
  fetchurl,
  buildPackages,
  openssl,
  util-linux,
  gnu-efi,
  stdenv,
}: let
  version = "0.9.5";
  ccanSrc = fetchurl {
    urls = [
      "https://github.com/rustyrussell/ccan/archive/d3314691f2dca4ffe9353e371675cf01709a795b.tar.gz"
    ];
    hash = "sha256-6EoqS2dptFk1YksM8Ad7PRkDivhYm2nVEImX0iaXbwo=";
  };
  # CCAN modules needed by sbsigntools (direct + transitive deps)
  ccanModules = "talloc read_write_all build_assert array_size endian compiler typesafe_cb list str container_of check_type";
in
  mkDerivation {
    pname = "sbsigntools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/snapshot/sbsigntools-${version}.tar.gz"
      ];
      hash = "sha256-ojI+VL5tF/UM6zJTym7QYxcaW8tweb+llACM0q63/eo=";
    };

    buildDeps = [
      buildPackages.gnumake
      buildPackages.autoconf
      buildPackages.automake
      buildPackages.pkg-config
      buildPackages.binutils
      gnu-efi
    ];
    runtimeDeps =
      [openssl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd sbsigntools-${version}

          # Populate CCAN submodule from separate source tarball
          rm -rf lib/ccan.git
          tar xf ${ccanSrc}
          mv ccan-* lib/ccan.git
        '';
      }
      {
        name = "configure";
        script =
          ''
            # Manually set up CCAN build tree (create-ccan-tree requires git)
            mkdir -p lib/ccan
            for mod in ${ccanModules}; do
              if [ -d "lib/ccan.git/ccan/$mod" ]; then
                mkdir -p "lib/ccan/ccan/$mod"
                cp lib/ccan.git/ccan/$mod/*.[ch] "lib/ccan/ccan/$mod/" 2>/dev/null || true
                # Copy LICENSE symlink target if present
                if [ -L "lib/ccan.git/ccan/$mod/LICENSE" ]; then
                  target=$(readlink "lib/ccan.git/ccan/$mod/LICENSE")
                  cp "lib/ccan.git/licenses/$(basename "$target")" "lib/ccan/ccan/$mod/LICENSE" 2>/dev/null || true
                fi
              fi
            done

            # Generate Makefile.am for CCAN
            (
              echo "noinst_LIBRARIES = libccan.a"
              printf "libccan_a_SOURCES ="
              for f in $(find lib/ccan/ccan -maxdepth 2 -name '*.[ch]' | sort); do
                # Strip lib/ccan/ prefix since Makefile.am is in lib/ccan/
                relpath=$(echo "$f" | sed 's|^lib/ccan/||')
                printf " \\\\\n\t%s" "$relpath"
              done
              echo
            ) > lib/ccan/Makefile.am

            # Create required files for automake
            touch AUTHORS ChangeLog

            # Remove tests from SUBDIRS; remove docs (no help2man available)
            sed -i 's/SUBDIRS = .*/SUBDIRS = lib\/ccan src/' Makefile.am

            # Patch configure.ac to find gnu-efi in the Nix store
            sed -i \
              -e 's|for path in /lib /lib64 /usr/lib /usr/lib64 /usr/lib32 /lib/efi /lib64/efi /usr/lib/efi /usr/lib64/efi /usr/lib/gnuefi /usr/lib64/gnuefi|for path in ${gnu-efi}/lib /lib /lib64 /usr/lib /usr/lib64 /usr/lib32 /lib/efi /lib64/efi /usr/lib/efi /usr/lib64/efi /usr/lib/gnuefi /usr/lib64/gnuefi|' \
              configure.ac
            sed -i \
              -e 's|EFI_CPPFLAGS="-I/usr/include/efi -I/usr/include/efi/\$EFI_ARCH|EFI_CPPFLAGS="-I${gnu-efi}/include/efi -I${gnu-efi}/include/efi/\$EFI_ARCH|' \
              configure.ac
          ''
          + (
            if stdenv.hostPlatform.isDarwin
            then ''
              # Configure runs on Linux, so its uname cannot select the EFI
              # architecture for the Darwin target. Darwin's UUID API is in
              # libSystem rather than the Linux-only util-linux package.
              sed -i '/^EFI_ARCH=/cEFI_ARCH=${
                if stdenv.hostPlatform.isAarch64
                then "aarch64"
                else "x86_64"
              }' configure.ac
              sed -i \
                -e 's|#include <endian.h>|#include <machine/endian.h>|' \
                -e 's|__BYTE_ORDER|__DARWIN_BYTE_ORDER|g' \
                -e 's|__LITTLE_ENDIAN|__DARWIN_LITTLE_ENDIAN|g' \
                -e 's|__BIG_ENDIAN|__DARWIN_BIG_ENDIAN|g' \
                configure.ac

              # These user-space tools use GNU-EFI only for data structures;
              # they do not produce or link Mach-O firmware images. Use a
              # private header copy so GNU-EFI's firmware-toolchain guard stays
              # intact for actual EFI consumers.
              mkdir -p .aos-efi-include
              cp -R ${gnu-efi}/include/efi .aos-efi-include/efi
              chmod -R u+w .aos-efi-include
              sed -i '/#if defined(__APPLE__)/,/^#endif$/d' .aos-efi-include/efi/efi.h
              sed -i "s|${gnu-efi}/include/efi|$PWD/.aos-efi-include/efi|g" configure.ac
              export CPPFLAGS="-I$PWD/.aos-efi-include $CPPFLAGS"

              # Darwin exposes statfs through sys/mount.h and names the
              # filesystem rather than assigning Linux's numeric f_type.
              sed -i \
                -e 's|#include <sys/statfs.h>|#include <sys/mount.h>|' \
                -e '/^static struct statfs statfstype;$/d' \
                -e '/^#define PSTORE_FSTYPE/d' \
                -e '/^#define EFIVARS_FSTYPE/d' \
                -e '/#include <sys\/types.h>/a\
              #undef LIST_HEAD' \
                -e '/if (statbuf.f_type != EFIVARS_FSTYPE && statbuf.f_type != PSTORE_FSTYPE)/c\
              if (strcmp(statbuf.f_fstypename, "efivarfs") && strcmp(statbuf.f_fstypename, "pstore"))' \
                src/sbkeysync.c

              # Upstream intentionally uses a nested flexible-array structure,
              # and computes a debug-only byte count even in release builds.
              export CFLAGS="$CFLAGS -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-but-set-variable -Wno-uninitialized"
              export uuid_CFLAGS="-I$SDKROOT/usr/include"
              export uuid_LIBS="-lSystem"
            ''
            else ""
          )
          + ''

            # Run autotools (include pkg-config's m4 macros for PKG_CHECK_MODULES)
            aclocal -I ${buildPackages.pkg-config}/share/aclocal
            autoheader
            autoconf
            automake --add-missing -Wno-portability

            # Configure
            HELP2MAN=: \
            ./configure \
              $configureFlags \
              --prefix=$out
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
      description = "sbsigntools — UEFI Secure Boot signing tools";
      homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git";
      license = "GPL-3.0-only";
    };
  }
