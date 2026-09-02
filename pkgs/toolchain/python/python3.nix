##! python3 — Python 3.14 interpreter
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
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
  version = "3.14.3";
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
    pname = "python3";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.python.org/ftp/python/${version}/Python-${version}.tar.xz"
      ];
      hash = "sha256-qX1VSemtgf4XFZ7QLGh3StXSZscvjZoLWpw3H+hdkCs=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if isDarwinCross
        then [buildPackages.python3]
        else []
      );
    runtimeDeps =
      [
        zlib
        openssl
        xz
        # libffi is required for the _ctypes extension module — Python 3.13
        # removed the bundled libffi and always uses the system one now.
        # Without it `import ctypes` fails at runtime, breaking ukify and
        # other systemd build-time scripts (elf2efi.py, generate-hwids-
        # section.py) that need it.
        libffi
        sqlite
        readline
      ]
      ++ (
        if isDarwinCross
        then [
          bzip2
          ncurses
          zstd
        ]
        else []
      );
    propagatedDeps = [];

    # CPython models PyTupleObject's variable-length ob_item storage as a
    # trailing one-element array. GCC 14's strictest flexible-array mode treats
    # that declaration as a fixed-size object, so _FORTIFY_SOURCE can abort
    # interpreter bootstrap and ordinary tuple-heavy operations. Level 1
    # preserves the upstream convention while retaining fortify3 and the
    # remaining hardening flags.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    # Guard: scrubPhase's nuke-refs pass should keep these out of the
    # closure. Fails the build if a future regression re-introduces a
    # _sysconfigdata*.py(c) or Makefile reference to the build toolchain.
    disallowedReferences =
      if isDarwinCross
      then [
        buildPackages.gnumake
        buildPackages.pkg-config
        buildPackages.patch
        buildPackages.patchelf
      ]
      else [
        gnumake
        pkg-config
        patch
        patchelf
      ];

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
              # CPython maps the Darwin kernel release to its platform feature
              # policy. Cross configure leaves the release empty, which makes
              # it incorrectly define strict POSIX feature macros and hide
              # Darwin APIs such as sendfile and getpagesize.
              sed -i 's/^[[:space:]]*ac_sys_release=$/  ac_sys_release=20.0.0/' configure
              # Configure finds the Darwin getaddrinfo declaration and link,
              # then tries to execute its target-only behavioral probe on the
              # Linux builder. Darwin's implementation is not the historical
              # buggy glibc variant, so cache the target fact without dropping
              # Python's IPv6 support.
              export ac_cv_buggy_getaddrinfo=no
              # Filesystem probes cannot run against the Darwin target from a
              # Linux builder. Modern Darwin provides the Unix98 PTY master
              # and does not use the legacy BSD /dev/ptc device.
              export ac_cv_file__dev_ptmx=yes
              export ac_cv_file__dev_ptc=no
              # CPython's generic cross path deliberately assumes pthreads
              # are unavailable unless a target program can be executed.
              # Darwin provides pthreads directly from libSystem with no
              # compiler or linker option, so preserve its native result.
              export ac_cv_pthread_is_default=yes
              export ac_cv_kthread=no
              export ac_cv_pthread=no
              # These are target-runtime probes. AOS libffi is newer than the
              # first release with real complex support, and Darwin's pthread
              # scope and tzset implementations satisfy CPython's native tests.
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
            --with-system-expat=no \
            --with-ensurepip=no \
            --without-static-libpython \
            --disable-test-modules \
            --with-openssl=${openssl} \
            ${
            if isDarwinCross
            then ''--with-build-python=${buildPackages.python3}/bin/python3''
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
              # CPython records its configure directory in target sysconfig
              # metadata. Downstream extension builds need the flags, not the
              # ephemeral sandbox path from the Linux builder.
              sed -i "s|$PWD|.|g" \
                "$out/lib/python3.14/_sysconfig_vars__darwin_darwin.json" \
                "$out/lib/python3.14/_sysconfigdata__darwin_darwin.py" \
                "$out/lib/python3.14/config-3.14-darwin/Makefile"
              find "$out/lib/python3.14/__pycache__" \
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
          SITE=$out/lib/python3.14/site-packages
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      import = testing.mkVMTest {
        name = "cross-cutting-python-import";
        rootfsDeps = [self];
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:$LD_LIBRARY_PATH"

          echo "==> Testing python3 version"
          python3 -c "import sys; print('Python', sys.version)"

          echo "==> Testing python3 basic imports"
          python3 -c "
          import os
          import json
          import math
          print('os.name:', os.name)
          print('json works:', json.dumps({'test': True}))
          print('math.pi:', math.pi)
          print('Python imports: PASS')
          "
        '';
      };

      chain = testing.mkVMTest {
        name = "cross-cutting-python-chain";
        rootfsDeps = [
          self
          pkgs.sqlite
          pkgs.zlib
          pkgs.readline
        ];
        memory = 512;
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.sqlite}/lib:${pkgs.zlib}/lib:${pkgs.readline}/lib:$LD_LIBRARY_PATH"

          echo "==> Testing python3 C extension modules"

          python3 -c "
          import sqlite3
          import zlib
          import readline
          print('sqlite3: connected to', sqlite3.sqlite_version)
          db = sqlite3.connect(':memory:')
          db.execute('CREATE TABLE t(x)')
          db.execute('INSERT INTO t VALUES(42)')
          row = db.execute('SELECT x FROM t').fetchone()
          assert row[0] == 42, 'sqlite query failed'
          print('sqlite3: in-memory query OK')

          data = b'test data for compression'
          compressed = zlib.compress(data)
          assert zlib.decompress(compressed) == data, 'zlib round-trip failed'
          print('zlib: compress/decompress OK')

          print('readline: module loaded, version', readline.__doc__)

          print('all imports ok')
          "
          echo "Python chain: PASS"
        '';
      };
    };

    meta = {
      description = "Python 3.14 interpreter";
      homepage = "https://www.python.org/";
      license = "PSF-2.0";
    };
  }
