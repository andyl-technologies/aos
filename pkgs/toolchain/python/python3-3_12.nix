##! python3-3_12 — Python 3.12 interpreter (bootstrap for 3.14)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  openssl,
  xz,
}: let
  version = "3.12.9";

  markupsafeSrc = fetchurl {
    urls = [
      "https://github.com/pallets/markupsafe/releases/download/2.1.5/MarkupSafe-2.1.5.tar.gz"
    ];
    hash = "sha256-0oPTeokLpMGuc/+t+ARkNcdue8Ike7tjwAvRpwnGVEs=";
  };

  jinja2Src = fetchurl {
    urls = [
      "https://github.com/pallets/jinja/releases/download/3.1.4/jinja2-3.1.4.tar.gz"
    ];
    hash = "sha256-Sjruesu+cwOu3o6WSNE7i/iKQpKCqmEiqZPwrIAMs2k=";
  };
in
  mkDerivation {
    pname = "python3-3_12";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.python.org/ftp/python/${version}/Python-${version}.tar.xz"
      ];
      hash = "sha256-ciCDXZ+Qs3wAbphCqN/0WAqspDGGdPlHMCuNKPP4ERI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      zlib
      openssl
      xz
    ];
    propagatedDeps = [];

    # CPython models PyTupleObject's variable-length ob_item storage as a
    # trailing one-element array. GCC 14's strictest flexible-array mode treats
    # that declaration as a fixed-size object, so _FORTIFY_SOURCE aborts the
    # freshly built _freeze_module when it writes tuples with multiple items.
    # Level 1 preserves the upstream trailing-array convention while retaining
    # fortify3 and the remaining hardening flags.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd Python-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          LDFLAGS="''${LDFLAGS:-} -Wl,-rpath,$out/lib" \
          ./configure \
            --prefix=$out \
            --enable-shared \
            --with-system-ffi=no \
            --with-system-expat=no \
            --with-ensurepip=no \
            --without-static-libpython \
            --disable-test-modules \
            --with-openssl=${openssl}
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
          # Ensure 'python' symlink exists alongside 'python3'
          if [ ! -e $out/bin/python ]; then
            ln -sf python3 $out/bin/python
          fi

          # Install jinja2 + markupsafe (needed by systemd's meson build)
          # Manual install: copy pure-Python packages to site-packages
          # (setup.py requires distutils which was removed in Python 3.12)
          SITE=$out/lib/python3.12/site-packages
          mkdir -p $SITE

          # MarkupSafe (jinja2 dependency) — pure Python fallback is sufficient
          tar xf ${markupsafeSrc}
          cp -r MarkupSafe-2.1.5/src/markupsafe $SITE/

          # Jinja2 — pure Python
          tar xf ${jinja2Src}
          cp -r jinja2-3.1.4/src/jinja2 $SITE/
        '';
      }
    ];

    meta = {
      description = "Python 3.12 interpreter (bootstrap for 3.14)";
      homepage = "https://www.python.org/";
      license = "PSF-2.0";
    };
  }
