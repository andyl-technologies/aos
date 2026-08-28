##! gettext — GNU internationalization and localization tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
  libxcrypt,
  bash,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "1.0";
  splitDarwinRuntime = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "gettext";
    inherit version;
    outputs =
      if splitDarwinRuntime
      then ["out" "lib"]
      else ["out"];

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/gettext/gettext-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/gettext/gettext-${version}.tar.gz"
      ];
      hash = "sha256-hdmbecmBpASHTALgNCF2z3XHaY4rUf5BAxz2Um2XTxo=";
    };

    buildDeps =
      [
        gnumake
        bash
        python3
      ]
      ++ (
        if stdenv.isCross
        then [buildPackages.gettext]
        else []
      );
    runtimeDeps =
      if splitDarwinRuntime
      then [ncurses libxcrypt]
      else [
        ncurses
        libxcrypt
        bash
        python3
      ];
    propagatedDeps = [];
    ${
      if splitDarwinRuntime
      then "nukeRefsKeep"
      else null
    } = [bash python3];
    ${
      if splitDarwinRuntime
      then "outputChecks"
      else null
    } = {
      out.disallowedReferences = [
        buildPackages.bash
        buildPackages.python3
        buildPackages.llvm
      ];
      lib.disallowedReferences = [
        bash
        python3
        buildPackages.bash
        buildPackages.python3
        buildPackages.llvm
      ];
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gettext-${version}

          # Release scripts are executed while building, then shipped as part
          # of the target tool suite.  Use native interpreters during the
          # Linux build and retarget their installed copies afterward.
          nativePython=$(command -v python3)
          grep -rlZ \
            -e '^#! */usr/bin/env \(sh\|bash\)' \
            -e '^#! */bin/\(sh\|bash\)' \
            -e '^#! */usr/bin/\(sh\|bash\)' \
            . 2>/dev/null \
            | while IFS= read -r -d "" f; do
              refTime=$(stat -c %Y "$f")
              sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$f"
              touch -d "@$refTime" "$f"
            done
          grep -rlZ \
            -e '^#! */usr/bin/env python3' \
            -e '^#! */usr/bin/python3' \
            . 2>/dev/null \
            | while IFS= read -r -d "" f; do
              refTime=$(stat -c %Y "$f")
              sed -i "1s|^#!.*|#!$nativePython|" "$f"
              touch -d "@$refTime" "$f"
            done
        '';
      }
      {
        name = "configure";
        script =
          if splitDarwinRuntime
          then ''
            # The preferred-language consumer uses either the modern CFLocale
            # API or the legacy CFPreferences API, but upstream guards its pure
            # locale-name canonicalizer with only the legacy probe.  Keep the
            # definition available when the modern API is the selected path.
            sed -i \
              '/^#if HAVE_CFPREFERENCESCOPYAPPVALUE$/ { N; /\/\* Mac OS X 10\.4 or newer \*\// s/^#if HAVE_CFPREFERENCESCOPYAPPVALUE/#if HAVE_CFPREFERENCESCOPYAPPVALUE || HAVE_CFLOCALECOPYPREFERREDLANGUAGES/; }' \
              gettext-runtime/intl/gnulib-lib/localename-unsafe.c

            # Darwin's language-preference implementation calls the locale-name
            # canonicalizer from libintl.  Gnulib makes that symbol external only
            # when compiling as part of libintl; without the define it is static
            # in localename-unsafe.c and the final libintl link fails.
            sed -i \
              's|^libgnu_la_CFLAGS = |libgnu_la_CFLAGS = -DIN_LIBINTL |' \
              gettext-runtime/intl/gnulib-lib/Makefile.in

            ./configure \
              $configureFlags \
              --prefix=$out \
              --localedir=$lib/share/locale \
              --disable-static \
              --disable-java \
              --disable-csharp \
              --with-included-libxml \
              --with-included-libunistring \
              --without-emacs \
              --without-git
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --disable-java \
              --disable-csharp \
              --with-included-libxml \
              --with-included-libunistring \
              --without-emacs \
              --without-git
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
        script =
          ''
            make install

            nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
            nativePythonRoot=$(dirname "$(dirname "$(command -v python3)")")
            grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null \
              | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"
            grep -IrlZ -F "$nativePythonRoot" "$out" 2>/dev/null \
              | xargs -0 -r sed -i "s|$nativePythonRoot|${python3}|g"
          ''
          + (
            if splitDarwinRuntime
            then ''

              # Keep the complete target tool suite in the default output, but
              # give library consumers a closure-clean libintl output. Libtool
              # records the original prefix in Mach-O install names, so repair
              # the moved library and every target tool that loads it.
              mkdir -p "$lib/lib" "$lib/include"
              mv "$out/lib/libintl.8.dylib" "$lib/lib/libintl.8.dylib"
              mv "$out/lib/libintl.dylib" "$lib/lib/libintl.dylib"
              mv "$out/lib/libintl.la" "$lib/lib/libintl.la"
              mv "$out/include/libintl.h" "$lib/include/libintl.h"

              oldLibintl="$out/lib/libintl.8.dylib"
              newLibintl="$lib/lib/libintl.8.dylib"
              ${buildPackages.llvm}/bin/llvm-install-name-tool \
                -id "$newLibintl" \
                -delete_rpath "$out/lib" \
                "$newLibintl"

              find "$out" -type f | while read file; do
                if ${buildPackages.llvm}/bin/llvm-objdump --macho --dylibs-used \
                  "$file" 2>/dev/null | grep -q -F "$oldLibintl"; then
                  ${buildPackages.llvm}/bin/llvm-install-name-tool \
                    -change "$oldLibintl" "$newLibintl" "$file"
                fi
              done
              grep -IrlZ -F "$out/lib/libintl" "$out" 2>/dev/null \
                | xargs -0 -r sed -i "s|$out/lib/libintl|$lib/lib/libintl|g"
              sed -i "s|$out/lib|$lib/lib|g" "$lib/lib/libintl.la"

              # Preserve the traditional default-output development surface
              # for existing consumers. The compatibility links make the
              # complete tool output retain libintl, never the inverse.
              ln -s "$lib/lib/libintl.8.dylib" "$out/lib/libintl.8.dylib"
              ln -s "$lib/lib/libintl.dylib" "$out/lib/libintl.dylib"
              ln -s "$lib/lib/libintl.la" "$out/lib/libintl.la"
              ln -s "$lib/include/libintl.h" "$out/include/libintl.h"

              if grep -R -a -F "$out" "$lib" >/dev/null; then
                echo "gettext lib output retains the interpreter-backed tools output" >&2
                exit 1
              fi
            ''
            else ""
          );
      }
    ];

    meta = {
      description = "gettext — GNU internationalization and localization tools";
      homepage = "https://www.gnu.org/software/gettext/";
      license = "GPL-3.0-or-later";
    };
  }
