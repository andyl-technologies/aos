##! classpath-0_93 — GNU Classpath 0.93 Java standard library (last Jikes-buildable release)
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  jikes,
  fastjar,
  pkg-config,
  zip,
}: let
  version = "0.93";
  configurePlatformFlags = lib.optionalString (
    stdenv.isCross && stdenv.hostPlatform.isDarwin
  ) " \\\n            --build=${stdenv.buildPlatform.config} \\\n            --host=${stdenv.hostPlatform.config}";
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
  jikesForBuild =
    if stdenv.isCross
    then buildPackages.jikes
    else jikes;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "classpath-0_93";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The archive is valid ZIP data containing Object, String, and ArrayList classes.";
        "files" = {};
        "input" = "The GNU Classpath standard-library archive.";
        "operation" = "Open the archive and inspect core Java class entries.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, zipfile\narchive = next(pathlib.Path(\"@out@\").rglob(\"glibj.zip\"))\nwith zipfile.ZipFile(archive) as jar:\n    names = set(jar.namelist())\nassert {\"java/lang/Object.class\", \"java/lang/String.class\", \"java/util/ArrayList.class\"} <= names\nprint(\"classpath-0_93 data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "classpath-0_93 data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The archive lookup rejects the unknown class.";
        "files" = {};
        "input" = "A request for a Java core class absent from the standard-library archive.";
        "operation" = "Resolve the nonexistent class entry in the archive index.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys, zipfile\narchive = next(pathlib.Path(\"@out@\").rglob(\"glibj.zip\"))\nwith zipfile.ZipFile(archive) as jar:\n    if \"java/lang/AosNonexistent.class\" in jar.namelist():\n        raise SystemExit(2)\nsys.stderr.write(\"classpath-0_93 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "classpath-0_93 rejected invalid input\n";
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
        "https://mirrors.kernel.org/gnu/classpath/classpath-${version}.tar.gz"
      ];
      hash = "sha256-3y0JNhKr0j/mfpQJ2JuyqOebFmT+Ky2kDhyO1pPjKUU=";
    };

    buildDeps =
      [
        gnumake
        jikesForBuild
        fastjarForBuild
        pkg-config
        zip
      ]
      ++ lib.optionals (stdenv.isCross && stdenv.hostPlatform.isDarwin) [
        buildPackages.automake
      ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd classpath-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # Fix implicit function declarations for GCC 14 (C23 default)
          sed -i '1i #include <stdlib.h>' native/fdlibm/dtoa.c

          # Disable -Werror — old code triggers many new GCC 14 warnings
          find . -name Makefile.in -exec sed -i 's/-Werror//g' {} +
          find . -name configure -exec sed -i 's/-Werror//g' {} +${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isDarwin) ''

            # This 2006 release predates AArch64. Refresh only config.sub; the
            # generated configure logic remains upstream and cross-aware.
            cp ${buildPackages.automake}/share/automake-*/config.sub config.sub

            # GNU Classpath's fdlibm predates AArch64 but uses the standard
            # little-endian IEEE-754 word layout on that architecture.
            sed -i '/#ifdef __alpha__/i #ifdef __aarch64__\n#define __IEEE_LITTLE_ENDIAN\n#endif\n' \
              native/fdlibm/ieeefp.h''}
        '';
      }
      {
        name = "configure";
        script = ''
          CFLAGS="-O2 -Wno-error" \
          ./configure \
            --prefix=$out \
            --disable-gtk-peer \
            --disable-gconf-peer \
            --disable-alsa \
            --disable-dssi \
            --disable-gjdoc \
            --disable-plugin \
            --disable-examples \
            --with-jikes \
            --with-fastjar=${fastjarForBuild}/bin/fastjar${configurePlatformFlags}
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
      description = "GNU Classpath 0.93 — Java standard library implementation";
      homepage = "https://www.gnu.org/software/classpath/";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
