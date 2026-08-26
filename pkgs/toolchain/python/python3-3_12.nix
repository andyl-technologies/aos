##! python3-3_12 — Python 3.12 interpreter (bootstrap for 3.14)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  bzip2,
  ncurses,
  readline,
  sqlite,
  zstd,
  zlib,
  openssl,
  xz,
  libffi,
  stdenv,
  buildPackages,
}: let
  version = "3.12.9";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;

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

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if isDarwinCross
        then [buildPackages.python3-3_12]
        else []
      );
    runtimeDeps =
      [
        zlib
        openssl
        xz
      ]
      ++ (
        if isDarwinCross
        then [
          bzip2
          ncurses
          readline
          sqlite
          zstd
          # CPython 3.12 uses system libffi for _ctypes. Its historical
          # --with-system-ffi switch is no longer recognized by configure.
          libffi
        ]
        else []
      );
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
          ${
            if isDarwinCross
            then ''
              # Python 3.12 predates upstream's Darwin cross cases. Teach its
              # generated configure script the same platform facts carried by
              # current CPython without regenerating release artifacts.
              sed -i '/^[[:space:]]*\*-\*-vxworks\*)$/i\
              \    *-*-darwin*)\
              \        ac_sys_system=Darwin\
              \        ac_sys_release=20.0.0\
              \        _host_cpu=$host_cpu\
              \        ;;' configure
              # The first cross-platform switch initializes the release after
              # selecting ac_sys_system. Preserve Darwin's kernel release at
              # that later assignment as current CPython does.
              sed -i 's/^[[:space:]]*ac_sys_release=$/  ac_sys_release=20.0.0/' configure
              # Target-runtime probes cannot execute on the Linux builder.
              # Cache Darwin's documented results so IPv6, pthreads, PTYs,
              # libffi complex values, and timezone support stay enabled.
              export ac_cv_buggy_getaddrinfo=no
              export ac_cv_file__dev_ptmx=yes
              export ac_cv_file__dev_ptc=no
              export ac_cv_pthread_is_default=yes
              export ac_cv_kthread=no
              export ac_cv_pthread=no
              export ac_cv_ffi_complex_double_supported=yes
              export ac_cv_pthread_system_supported=yes
              export ac_cv_working_tzset=yes
            ''
            else ""
          }
          LDFLAGS="''${LDFLAGS:-} -Wl,-rpath,$out/lib" ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            ${
            if isDarwinCross
            then ""
            else "--with-system-ffi=no"
          } \
            --with-system-expat=no \
            --with-ensurepip=no \
            --without-static-libpython \
            --disable-test-modules \
            --with-openssl=${openssl} \
            ${
            if isDarwinCross
            then ''--with-build-python=${buildPackages.python3-3_12}/bin/python3''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          ${
            if isDarwinCross
            then ''
              # Configure embeds _PYTHON_HOST_PLATFORM and target sysconfig
              # paths in PYTHON_FOR_BUILD. Keep that complete command so
              # native Python validates files without importing Darwin modules.
              make -j$NIX_BUILD_CORES
            ''
            else "make -j$NIX_BUILD_CORES"
          }
        '';
      }
      {
        name = "install";
        script = ''
          ${
            if isDarwinCross
            then ''
              make install
              sed -i "s|$PWD|.|g" \
                "$out/lib/python3.12/_sysconfigdata__darwin_darwin.py" \
                "$out/lib/python3.12/config-3.12-darwin/Makefile"
              find "$out/lib/python3.12/__pycache__" \
                -name '_sysconfigdata__darwin_darwin.*.pyc' -delete
            ''
            else "make install"
          }
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
