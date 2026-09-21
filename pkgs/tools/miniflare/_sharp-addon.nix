##! Builds Sharp's native addon against AOS image libraries.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  nodejs,
  nodeModules,
  vips,
}: let
  version = "0.35.4";
  nodeAddonApi = fetchurl {
    urls = ["https://github.com/nodejs/node-addon-api/archive/refs/tags/v8.9.2.tar.gz"];
    hash = "0sg244s6vshzcfnicxra6dv4466aicdq3l5dfrvh28avw187nbkn";
  };
  targetArch =
    if stdenv.hostPlatform.isAarch64
    then "arm64"
    else "x64";
in
  mkDerivation {
    pname = "sharp-addon";
    inherit version;
    src = null;
    buildDeps = [buildPackages.nodejs buildPackages.python3 buildPackages.gnumake buildPackages.pkg-config buildPackages.binutils];
    runtimeDeps = [nodejs vips];
    passthru.evidenceSources = [nodeAddonApi nodeModules];
    phases =
      [
        {
          name = "unpack";
          script = ''
            cp -R ${nodeModules} node_modules
            chmod -R u+w node_modules
            # The addon must use AOS libvips, never optional npm binaries.
            rm -rf node_modules/@img/sharp-*
            mkdir -p node_modules/node-addon-api
            tar xf ${nodeAddonApi} --strip-components=1 -C node_modules/node-addon-api
          '';
        }
        {
          name = "build";
          script = ''
            export SHARP_FORCE_GLOBAL_LIBVIPS=1
            export npm_config_arch=${targetArch}
            cd node_modules/sharp/src
            ${buildPackages.nodejs}/bin/node \
              ${buildPackages.nodejs}/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js \
              rebuild --release --arch=${targetArch} --nodedir=${nodejs} \
              --python=${buildPackages.python3}/bin/python3
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
              ${buildPackages.nodejs}/bin/node <<'JS'
              const assert = require('node:assert/strict');
              const sharp = require('../');

              async function checkFormats() {
                for (const format of ['png', 'jpeg', 'webp', 'avif', 'tiff', 'gif']) {
                  const encoded = await sharp({
                    create: {
                      width: 32, height: 24, channels: 3,
                      background: { r: 180, g: 70, b: 30 }
                    }
                  }).toFormat(format).toBuffer();
                  const decoded = await sharp(encoded).raw().toBuffer({ resolveWithObject: true });
                  assert.equal(decoded.info.width, 32);
                  assert.equal(decoded.info.height, 24);
                  assert.ok(decoded.data[0] > decoded.data[2], format);
                }
                const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="12" height="9"><rect width="12" height="9" fill="red"/></svg>');
                const rendered = await sharp(svg).raw().toBuffer({ resolveWithObject: true });
                assert.equal(rendered.info.width, 12);
                assert.equal(rendered.info.height, 9);
                assert.equal(rendered.data[0], 255);
                console.log('Sharp source addon: six format round trips and SVG rendering passed');
              }
              checkFormats().catch(error => { console.error(error); process.exitCode = 1; });
              JS
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            mkdir -p "$out/lib" "$out/share/licenses/sharp-addon"
            cp build/Release/sharp-*.node "$out/lib/"
            # Native addons need the same compiler-reference cleanup as shared
            # libraries, while retaining every linked runtime search path.
            for addon in "$out"/lib/*.node; do
              set --
              for runtime_path in $(patchelf --print-rpath "$addon" | tr ':' ' '); do
                case "$runtime_path" in
                  /nix/store/*) set -- "$@" -e "$runtime_path" ;;
                esac
              done
              nuke-refs "$@" "$addon"
            done
            cp ../LICENSE "$out/share/licenses/sharp-addon/"
            cp ../../node-addon-api/LICENSE.md "$out/share/licenses/sharp-addon/node-addon-api-LICENSE.md"
          '';
        }
      ];
    meta = {
      description = "Sharp native image-processing addon built from source";
      homepage = "https://sharp.pixelplumbing.com/";
      license = "Apache-2.0 AND MIT";
    };
  }
