##! composefs — Composite-filesystem builder (mkcomposefs)
##!
##! Builds the EROFS-formatted metadata image that AOS uses as the
##! bottom lower of the `/etc` overlay. The runtime mount is plain
##! `mount -t erofs ... -o ro,nodev,nosuid`; the `composefs.ko` /
##! `mount.composefs` runtime is not used. We therefore disable fuse
##! support and ship only the build-time tools (`mkcomposefs`,
##! `composefs-info`, `composefs-dump`).
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  meson,
  ninja,
  pkg-config,
  openssl,
}: let
  version = "1.0.8";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "composefs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Mkcomposefs creates a nonempty image that composefs-info accepts.";
        "files" = {
          "source/answer.txt" = "qualified\n";
        };
        "input" = "A source directory containing one fixed regular file.";
        "operation" = "Build a composefs image and inspect its metadata with composefs-info.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nbuild = subprocess.run([\"@out@/bin/mkcomposefs\", \"source\", \"image.cfs\"], capture_output=True)\nassert build.returncode == 0, build.stderr\nassert pathlib.Path(\"image.cfs\").stat().st_size > 0\ninspect = subprocess.run([\"@out@/bin/composefs-info\", \"image.cfs\"], capture_output=True)\nassert inspect.returncode == 0, inspect.stderr\nprint(\"composefs operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "composefs operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mkcomposefs rejects the missing source path.";
        "files" = {};
        "input" = "A source-directory path that does not exist.";
        "operation" = "Attempt to build a composefs image from the missing tree.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/mkcomposefs\", \"absent\", \"invalid.cfs\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"composefs rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "composefs rejected invalid input\n";
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
        "https://github.com/composefs/composefs/releases/download/v${version}/composefs-${version}.tar.xz"
      ];
      hash = "sha256-IHOE3rGWGYrEdkxbQrtVj3xmFJQwKzgK/AlEdnhTg4Y=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
    ];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd composefs-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          ${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Meson's installed library must retain the target OpenSSL path;
            # its temporary build-tree search paths are removed on install.
            export PKG_CONFIG_PATH="${openssl}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            export LDFLAGS="''${LDFLAGS:-} -Wl,-rpath,${openssl}/lib"
          ''}meson setup build \
            $mesonFlags \
            --prefix=$out \
            -Dfuse=disabled \
            -Dman=disabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          ninja -C build install
        '';
      }
    ];

    meta = {
      description = "composefs — composite filesystem image builder";
      homepage = "https://github.com/composefs/composefs";
      # COPYING in the v1.0.8 release tarball:
      # `GPL-2.0-or-later OR Apache-2.0`. Parts derived from EROFS are
      # effectively `GPL-2.0-only OR Apache-2.0`; small `LGPL-2.1-or-later`
      # components live in libcomposefs.
      license = "GPL-2.0-or-later OR Apache-2.0";
    };
  }
