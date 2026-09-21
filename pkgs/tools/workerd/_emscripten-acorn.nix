##! Source-built Acorn parser used by Emscripten's JavaScript optimizer.
{
  mkDerivation,
  fetchurl,
  callPackage,
  buildPackages,
  nodejs,
}: let
  esbuild = callPackage ./_esbuild.nix {};
in
  mkDerivation {
    pname = "emscripten-acorn";
    version = "8.15.0";
    src = fetchurl {
      urls = ["https://github.com/acornjs/acorn/archive/refs/tags/8.15.0.tar.gz"];
      hash = "1i8k43bkfvpdlmiiv6dcif2xli7pl9s0mv1h42gq1yjw6js8pnk0";
    };
    buildDeps = [esbuild buildPackages.nodejs];
    runtimeDeps = [nodejs];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd acorn-8.15.0
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p node_modules
          ln -s ../acorn node_modules/acorn
          # The upstream suite also exercises its recovery parser.
          for package in acorn acorn-loose; do
            esbuild "$package/src/index.js" --bundle --platform=node --format=cjs \
              --external:acorn --outfile="$package/dist/$package.js"
            esbuild "$package/src/index.js" --bundle --platform=node --format=esm \
              --external:acorn --outfile="$package/dist/$package.mjs"
          done
        '';
      }
      {
        name = "check";
        script = ''${buildPackages.nodejs}/bin/node test/run.js'';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/node_modules" "$out/share/licenses/emscripten-acorn"
          cp -R acorn "$out/lib/node_modules/"
          sed -i '1c#!${nodejs}/bin/node' "$out/lib/node_modules/acorn/bin/acorn"
          cp acorn/LICENSE "$out/share/licenses/emscripten-acorn/"
        '';
      }
    ];
    meta = {
      description = "JavaScript parser for Emscripten's optimizer";
      homepage = "https://github.com/acornjs/acorn";
      license = "MIT";
    };
  }
