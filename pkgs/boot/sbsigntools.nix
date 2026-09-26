##! sbsigntools — UEFI Secure Boot signing tools
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  binutils,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "sbsigntools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Sbsiglist emits a nonempty signature list containing the DER certificate bytes.";
        "files" = {};
        "input" = "A freshly generated DER certificate and a fixed EFI signature owner GUID.";
        "operation" = "Convert the certificate into an EFI signature list with sbsiglist.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, shutil, subprocess\nopenssl = shutil.which(\"openssl\")\nassert openssl is not None\nrequest = subprocess.run([openssl, \"req\", \"-new\", \"-x509\", \"-newkey\", \"rsa:2048\", \"-nodes\", \"-sha256\", \"-days\", \"1\", \"-subj\", \"/CN=AOS Qualification/\", \"-keyout\", \"key.pem\", \"-out\", \"cert.pem\"], capture_output=True)\nassert request.returncode == 0, request.stderr\nconvert = subprocess.run([openssl, \"x509\", \"-in\", \"cert.pem\", \"-outform\", \"DER\", \"-out\", \"cert.der\"], capture_output=True)\nassert convert.returncode == 0, convert.stderr\nresult = subprocess.run([\"@out@/bin/sbsiglist\", \"--owner\", \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\", \"--type\", \"x509\", \"--output\", \"certificate.esl\", \"cert.der\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nassert pathlib.Path(\"certificate.esl\").stat().st_size > pathlib.Path(\"cert.der\").stat().st_size\nprint(\"sbsigntools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "sbsigntools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Sbsiglist rejects the type before writing an output list.";
        "files" = {
          "signature.bin" = "qualification\n";
        };
        "input" = "An unsupported EFI signature-list type.";
        "operation" = "Attempt to construct a signature list with the invalid type.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/sbsiglist\", \"--owner\", \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\", \"--type\", \"qualification-invalid\", \"--output\", \"invalid.esl\", \"signature.bin\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Invalid type\" in result.stderr\nassert not pathlib.Path(\"invalid.esl\").exists()\n\nsys.stderr.write(\"sbsigntools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "sbsigntools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/snapshot/sbsigntools-${version}.tar.gz"
      ];
      hash = "sha256-ojI+VL5tF/UM6zJTym7QYxcaW8tweb+llACM0q63/eo=";
    };
    patches = [./sbsigntools-openssl-4.patch];

    buildDeps = [
      buildPackages.gnumake
      buildPackages.autoconf
      buildPackages.automake
      buildPackages.pkg-config
      buildPackages.binutils
      binutils
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
            if stdenv.isCross
            then ''
              # configure derives the EFI architecture from the build
              # machine's uname, which is wrong for every cross build.
              sed -i '/^EFI_ARCH=/cEFI_ARCH=${
                if stdenv.hostPlatform.isAarch64
                then "aarch64"
                else "x86_64"
              }' configure.ac
            ''
            else ""
          )
          + (
            if stdenv.hostPlatform.isDarwin
            then ''
              # Configure runs on Linux, so its uname cannot select the EFI
              # architecture for the Darwin target. Darwin's UUID API is in
              # libSystem rather than the Linux-only util-linux package.
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
            # Darwin uses the private GNU-EFI header copy above. The original
            # header rejects Mach-O even for these user-space signing tools.
            export CPPFLAGS="-I${binutils}/include ${
              if stdenv.hostPlatform.isDarwin
              then ""
              else "-I${gnu-efi}/include"
            } ''${CPPFLAGS:-}"
            export LDFLAGS="-L${binutils}/lib ''${LDFLAGS:-}"
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
