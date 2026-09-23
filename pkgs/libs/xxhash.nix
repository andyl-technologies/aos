##! xxHash libraries and checksum command-line tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "0.8.4";
in
  mkDerivation {
    pname = "xxhash";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/Cyan4973/xxHash/archive/refs/tags/v${version}.tar.gz"];
      hash = "0cnd998anlmd8gg6fpx2jmwcwri5d74zgbdkg65d7hz76l4jff2p";
    };
    buildDeps = [buildPackages.gnumake buildPackages.python3];
    runtimeDeps = [];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd xxHash-${version}
            # GNU make directly execs this recipe line; select AOS bash so
            # its time keyword can measure the complete collision tests.
            ${buildPackages.python3}/bin/python3 - <<'PY'
            from pathlib import Path
            path = Path('tests/collisions/Makefile')
            contents = path.read_text()
            assert '@time ' in contents
            path.write_text(contents.replace('@time ', '@${buildPackages.bash}/bin/bash -c \'time "$$@"\' -- '))
            PY
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" CC="$CC" AR="$AR" SHELL="$CONFIG_SHELL"
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
              make test -j"$NIX_BUILD_CORES" CC="$CC" AR="$AR" SHELL="$CONFIG_SHELL"
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install PREFIX="$out" CC="$CC" AR="$AR" SHELL="$CONFIG_SHELL"
            mkdir -p "$out/share/licenses/xxhash"
            cp LICENSE cli/COPYING "$out/share/licenses/xxhash/"
          '';
        }
      ];
    meta = {
      description = "xxHash libraries and checksum command-line tools";
      homepage = "https://xxhash.com/";
      license = "BSD-2-Clause AND GPL-2.0-or-later";
    };
  }
