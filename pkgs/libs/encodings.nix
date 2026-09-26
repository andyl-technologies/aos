##! X font encodings and generated lookup indexes.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.1.0";
  # The indexer reads the source encodings explicitly, so it can bootstrap
  # without an installed encoding database. Only the final library is published.
  bootstrapFontenc = import ./_libfontenc.nix {
    inherit (buildPackages) fetchurl stdenv xorgproto zlib;
    mkDerivation = args: buildPackages.mkDerivation (args // {pname = "fontenc-indexer-bootstrap";});
    inherit buildPackages;
  };
  indexer = import ../tools/mkfontscale.nix {
    inherit (buildPackages) fetchurl stdenv freetype zlib bzip2 xorgproto;
    mkDerivation = args: buildPackages.mkDerivation (args // {pname = "font-encoding-indexer";});
    inherit buildPackages;
    libfontenc = bootstrapFontenc;
  };
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
    pname = "encodings";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed X font encoding indexes and compressed encoding files.";
        operation = "Resolve every index entry and decompress its referenced encoding.";
        expected = "Both indexes are complete and the ISO-8859-11 mapping contains U+0E01.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import gzip
                from pathlib import Path

                root = Path("@out@/share/fonts/X11/encodings")
                for directory in (root, root / "large"):
                    lines = (directory / "encodings.dir").read_text().splitlines()
                    assert len(lines) == int(lines[0]) + 1
                    for entry in lines[1:]:
                        name, relative_path = entry.split()
                        contents = gzip.decompress((directory / relative_path).read_bytes())
                        assert name and b"STARTENCODING " in contents

                thai = gzip.decompress((root / "iso8859-11.enc.gz").read_bytes())
                assert b"STARTENCODING iso8859-11" in thai
                assert b"0xA1\t0x0E01" in thai
                print("X font encoding indexes passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "X font encoding indexes passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A truncated copy of an installed compressed encoding.";
        operation = "Attempt to decompress it.";
        expected = "The encoding format decoder rejects the truncated stream.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import gzip
                from pathlib import Path

                source = Path("@out@/share/fonts/X11/encodings/iso8859-11.enc.gz")
                truncated = source.read_bytes()[:8]
                try:
                    gzip.decompress(truncated)
                except EOFError:
                    print("X font encoding rejected truncated stream")
                    raise SystemExit(7)
                raise AssertionError("truncated encoding was accepted")
              ''
            ];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "X font encoding rejected truncated stream\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/font/encodings-${version}.tar.xz"];
      hash = "0xg99nmpvik6vaz4h03xay7rx0r3bf5a8azkjlpa3ksn2xi3rwcz";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.gzip indexer];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd encodings-${version}
          sed -i '1s|^#!.*|#!${buildPackages.bash}/bin/bash|' mkencodingsdir.in
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dencodingsdir="$out/share/fonts/X11/encodings"
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          meson install -C build
          mkdir -p "$out/share/licenses/encodings"
          cp COPYING "$out/share/licenses/encodings/"
          test -s "$out/share/fonts/X11/encodings/encodings.dir"
          test -s "$out/share/fonts/X11/encodings/large/encodings.dir"
        '';
      }
    ];
    meta = {
      description = "X font encodings and lookup indexes";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
