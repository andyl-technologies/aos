##! Shared MIME type database and its cache compiler.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  callPackage,
  util-linux,
  libxml2,
}: let
  version = "2.4";
  src = fetchurl {
    urls = ["https://gitlab.freedesktop.org/xdg/shared-mime-info/-/archive/${version}/shared-mime-info-${version}.tar.gz"];
    hash = "1pm2ns9paa0mddmsrllcvlpjnvfhi0vygmvmwwb4xfby738924jk";
  };
  xdgmimeRevision = "1debecbfe5a643dd7bd1a70f40cf86b007edbd43";
  xdgmimeSource = fetchurl {
    urls = ["https://gitlab.freedesktop.org/xdg/xdgmime/-/archive/${xdgmimeRevision}/xdgmime-${xdgmimeRevision}.tar.gz"];
    hash = "0rrapkrryg0k79jyzc881fzqgsjr7lr70r32jvr6pfbclyaw4lwg";
  };
  glib = callPackage ./_image-glib.nix {};
  cacheCompiler =
    if stdenv.isCross
    then "${buildPackages.shared-mime-info}/bin/update-mime-database"
    else "$out/bin/update-mime-database";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "shared-mime-info";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A MIME declaration for the .aosq file extension.";
        operation = "Compile the declaration into the shared MIME database.";
        expected = "The generated type and glob indexes contain the declared mapping.";
        files."mime/packages/aos.xml" = ''
          <?xml version="1.0" encoding="UTF-8"?>
          <mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
            <mime-type type="application/x-aos-qualification">
              <comment>AOS qualification fixture</comment>
              <glob pattern="*.aosq"/>
            </mime-type>
          </mime-info>
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import os
                from pathlib import Path
                import subprocess

                environment = dict(os.environ, XDG_DATA_HOME=str(Path.cwd()))
                subprocess.run(
                    ["@out@/bin/update-mime-database", "mime"],
                    check=True,
                    capture_output=True,
                    env=environment,
                )
                assert "application/x-aos-qualification" in Path("mime/types").read_text().splitlines()
                assert "50:application/x-aos-qualification:*.aosq" in Path("mime/globs2").read_text().splitlines()
                print("shared MIME database compilation passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "shared MIME database compilation passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An incomplete MIME XML declaration.";
        operation = "Compile the malformed declaration.";
        expected = "The parser reports the bad file and omits its MIME type.";
        files."mime/packages/bad.xml" = ''
          <mime-info><mime-type type="application/x-aos-bad">
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import os
                from pathlib import Path
                import subprocess

                environment = dict(os.environ, XDG_DATA_HOME=str(Path.cwd()))
                result = subprocess.run(
                    ["@out@/bin/update-mime-database", "mime"],
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                assert "Failed to parse" in result.stdout
                assert "application/x-aos-bad" not in Path("mime/types").read_text()
                print("shared MIME database rejected malformed XML")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "shared MIME database rejected malformed XML\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    inherit src;
    passthru.evidenceSources = [src xdgmimeSource];

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.libxml2 buildPackages.gettext];
    runtimeDeps =
      [glib libxml2]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [util-linux]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd shared-mime-info-${version}
            find tests po -maxdepth 1 -type f -name '*.sh' -exec \
              sed -i '1s|^#!.*$|#!${buildPackages.bash}/bin/bash|' {} +
            find tests po -maxdepth 1 -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            ${
              if stdenv.isCross
              then ""
              else ''
                tar xf ${xdgmimeSource}
                meson setup xdgmime-build "xdgmime-${xdgmimeRevision}" --buildtype=release
                PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
                  ninja -C xdgmime-build -j"$NIX_BUILD_CORES"
              ''
            }
            meson setup build $mesonFlags -Dxdgmime-path="$PWD/xdgmime-build" --prefix="$out" --libdir=lib --buildtype=release
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            # AOS discovers propagated package metadata through lib/pkgconfig.
            # Keep the upstream architecture-independent location available too.
            mkdir -p "$out/lib/pkgconfig"
            ln -s ../../share/pkgconfig/shared-mime-info.pc "$out/lib/pkgconfig/shared-mime-info.pc"
            ${cacheCompiler} "$out/share/mime"
            test -s "$out/share/mime/mime.cache"
            mkdir -p "$out/share/licenses/shared-mime-info"
            cp COPYING "$out/share/licenses/shared-mime-info/"
          '';
        }
      ];

    meta = {
      description = "Shared MIME type definitions and cache compiler";
      homepage = "https://gitlab.freedesktop.org/xdg/shared-mime-info";
      license = "GPL-2.0-or-later";
    };
  }
