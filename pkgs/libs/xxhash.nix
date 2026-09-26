##! xxHash libraries and checksum command-line tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
}: let
  version = "0.8.4";
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
    pname = "xxhash";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The three-byte message abc.";
        operation = "Hash the message from standard input with XXH64.";
        expected = "The installed checksum command returns the XXH64 test vector.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/xxhsum" "-H1" "-"];
            stdin = "abc";
            exit_code = 0;
            stdout.exact = "44bc2cf5ad770999  stdin\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A line that is not a checksum record.";
        operation = "Ask the installed command to verify that malformed record.";
        expected = "Checksum verification rejects the malformed input.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/xxhsum" "--check" "-"];
            stdin = "bad\n";
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "stdin: no properly formatted xxHash checksum lines found\n";
          }
        ];
      };
    };
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
          script =
            if stdenv.hostPlatform.isDarwin
            then ''
              # Upstream asks uname on the Linux builder for the link mode.
              make -j"$NIX_BUILD_CORES" UNAME=Darwin PREFIX="$out" \
                CC="$CC" AR="$AR" SHELL="$CONFIG_SHELL"
            ''
            else ''
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
          script =
            if stdenv.hostPlatform.isDarwin
            then ''
              make install PREFIX="$out" UNAME=Darwin CC="$CC" AR="$AR" SHELL="$CONFIG_SHELL"
              mkdir -p "$out/share/licenses/xxhash"
              cp LICENSE cli/COPYING "$out/share/licenses/xxhash/"
            ''
            else ''
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
