##! Source-built esbuild JavaScript API and matching binary for Pyodide.
{
  mkDerivation,
  fetchurl,
  callPackage,
  buildPackages,
  nodejs,
}: let
  version = "0.25.0";
  srcHash = "0b1vxqgk0k02nsvc7y9nfn0292avkfhgky0ahcxm2djss9cga062";
  binary = callPackage ./_esbuild.nix {inherit version srcHash;};
in
  mkDerivation {
    pname = "pyodide-esbuild-api";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/evanw/esbuild/archive/refs/tags/v${version}.tar.gz"];
      hash = srcHash;
    };
    buildDeps = [binary buildPackages.nodejs buildPackages.python3];
    runtimeDeps = [binary nodejs];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd esbuild-${version}
        '';
      }
      {
        name = "build";
        script = ''
          ${buildPackages.python3}/bin/python3 <<'PY'
          from pathlib import Path
          p = Path('lib/npm/node-platform.ts')
          source = p.read_text()
          old = 'process.env.ESBUILD_BINARY_PATH || ESBUILD_BINARY_PATH'
          assert source.count(old) == 1
          p.write_text(source.replace(old, 'process.env.ESBUILD_BINARY_PATH || "${binary}/bin/esbuild"'))
          PY
          ${buildPackages.nodejs}/bin/node scripts/esbuild.js ${binary}/bin/esbuild --neutral
          sed -i '1c#!${nodejs}/bin/node' npm/esbuild/bin/esbuild
        '';
      }
      {
        name = "check";
        script = ''
          ${buildPackages.nodejs}/bin/node <<'JS'
          const assert = require('node:assert/strict');
          const vm = require('node:vm');
          const esbuild = require('./npm/esbuild');
          assert.equal(esbuild.version, '0.25.0');
          const compiled = esbuild.transformSync('const answer: number = 6 * 7; answer;', {loader: 'ts'});
          assert.equal(vm.runInNewContext(compiled.code), 42);
          esbuild.build({
            stdin: {contents: 'export const answer: number = 42;', loader: 'ts'},
            bundle: true, format: 'cjs', write: false,
          }).then(result => {
            const context = {module: {exports: {}}};
            vm.runInNewContext(result.outputFiles[0].text, context);
            assert.equal(context.module.exports.answer, 42);
          }).catch(error => {console.error(error); process.exitCode = 1;});
          JS
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/node_modules" "$out/share/licenses/pyodide-esbuild-api"
          cp -R npm/esbuild "$out/lib/node_modules/"
          cp LICENSE.md "$out/share/licenses/pyodide-esbuild-api/"
        '';
      }
    ];
    meta = {
      description = "esbuild JavaScript API for the Pyodide source build";
      homepage = "https://esbuild.github.io/";
      license = "MIT";
    };
  }
