##! sbsigntools — UEFI Secure Boot signing tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  pkg-config,
  openssl,
  util-linux,
  binutils,
  gnu-efi,
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
      gnumake
      autoconf
      automake
      pkg-config
      binutils
      gnu-efi
    ];
    runtimeDeps = [
      openssl
      util-linux
    ];
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
        script = ''
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

          # Run autotools (include pkg-config's m4 macros for PKG_CHECK_MODULES)
          aclocal -I ${pkg-config}/share/aclocal
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
