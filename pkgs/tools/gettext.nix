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
in
  mkDerivation {
    pname = "gettext";
    inherit version;

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
    runtimeDeps = [
      ncurses
      libxcrypt
      bash
      python3
    ];
    propagatedDeps = [];

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
        script = ''
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
        script = ''
          make install

          nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
          nativePythonRoot=$(dirname "$(dirname "$(command -v python3)")")
          grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null \
            | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"
          grep -IrlZ -F "$nativePythonRoot" "$out" 2>/dev/null \
            | xargs -0 -r sed -i "s|$nativePythonRoot|${python3}|g"
        '';
      }
    ];

    meta = {
      description = "gettext — GNU internationalization and localization tools";
      homepage = "https://www.gnu.org/software/gettext/";
      license = "GPL-3.0-or-later";
    };
  }
