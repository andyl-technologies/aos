##! Bazel esbuild repository using the source-built executable and pinned launcher.
{
  mkDerivation,
  fetchurl,
  callPackage,
  buildPackages,
}: let
  esbuild = callPackage ./_esbuild.nix {};
  esbuildSource = fetchurl {
    urls = ["https://github.com/evanw/esbuild/archive/refs/tags/v${esbuild.version}.tar.gz"];
    hash = "1pw8yhpmbacp5gfb2872isxdsfw4w6sgc1g942ipjdfrfcdpb3lr";
  };
in
  mkDerivation {
    pname = "workerd-esbuild-repository";
    inherit (esbuild) version;
    src = fetchurl {
      urls = ["https://github.com/aspect-build/rules_esbuild/releases/download/v0.26.0/rules_esbuild-v0.26.0.tar.gz"];
      hash = "sha256-KIyhNG1vWqSksSTtg44N53plSV87LHo1A2/PTiluPXs=";
    };
    buildDeps = [buildPackages.nodejs buildPackages.python3];
    runtimeDeps = [esbuild];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd rules_esbuild-0.26.0
        '';
      }
      {
        name = "build";
        script = ''
          tar xf ${esbuildSource} -C ..

          # The JS API is generated from upstream TypeScript. Point its
          # fallback at the matching AOS-built Go executable.
          ${buildPackages.python3}/bin/python3 - ../esbuild-${esbuild.version}/lib/npm/node-platform.ts <<'PY'
          from pathlib import Path
          import sys

          source = Path(sys.argv[1])
          text = source.read_text()
          original = 'process.env.ESBUILD_BINARY_PATH || ESBUILD_BINARY_PATH'
          if text.count(original) != 1:
              raise SystemExit('Unexpected esbuild binary selector')
          source.write_text(text.replace(original, 'process.env.ESBUILD_BINARY_PATH || "${esbuild}/bin/esbuild"'))
          PY

          (
            cd ../esbuild-${esbuild.version}
            ${buildPackages.nodejs}/bin/node scripts/esbuild.js ${esbuild}/bin/esbuild --neutral
            sed -i '1c#!${buildPackages.nodejs}/bin/node' npm/esbuild/bin/esbuild
          )
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/package/bin" "$out/plugins" "$out/node_modules" \
            "$out/share/licenses/workerd-esbuild-repository"
          cp esbuild/private/launcher.js "$out/launcher.js"
          cp esbuild/private/plugins/bazel-sandbox.js "$out/plugins/"
          cp -R ../esbuild-${esbuild.version}/npm/esbuild "$out/node_modules/"
          cp LICENSE "$out/share/licenses/workerd-esbuild-repository/"
          cp ../esbuild-${esbuild.version}/LICENSE.md \
            "$out/share/licenses/workerd-esbuild-repository/esbuild-LICENSE.md"
          ln -s ${esbuild}/bin/esbuild "$out/package/bin/esbuild"

          # The generated JS API is source-built and lives next to the launcher
          # in Bazel runfiles, where Node resolves require('esbuild').
          cat > "$out/BUILD.bazel" <<'BUILD'
          load("@aspect_rules_esbuild//esbuild:toolchain.bzl", "esbuild_toolchain")
          load("@aspect_rules_js//js:defs.bzl", "js_binary")

          filegroup(
              name = "esbuild_api",
              srcs = glob(["node_modules/esbuild/**"]),
          )

          js_binary(
              name = "launcher",
              entry_point = "launcher.js",
              data = [":plugins/bazel-sandbox.js", ":esbuild_api"],
          )

          esbuild_toolchain(
              name = "esbuild_toolchain",
              launcher = ":launcher",
              target_tool = "package/bin/esbuild",
          )
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
      {
        name = "check";
        script = ''
          test "$($out/package/bin/esbuild --version)" = '${esbuild.version}'
          node --check "$out/launcher.js"
          node --check "$out/plugins/bazel-sandbox.js"
          test "$(head -n 1 "$out/node_modules/esbuild/bin/esbuild")" = '#!${buildPackages.nodejs}/bin/node'
          ESBUILD_BINARY_PATH="${esbuild}/bin/esbuild" node - <<'JS'
          const assert = require('node:assert/strict');
          const esbuild = require(process.env.out + '/node_modules/esbuild');
          assert.equal(esbuild.version, '${esbuild.version}');
          const result = esbuild.transformSync('const value: number = 42', { loader: 'ts' });
          assert.match(result.code, /value = 42/);
          JS
        '';
      }
    ];
    meta = {
      description = "Source-built esbuild toolchain repository for workerd";
      license = ["Apache-2.0" "MIT"];
    };
  }
