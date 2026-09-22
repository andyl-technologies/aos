##! Bazel esbuild repository using the source-built executable and pinned launcher.
{
  mkDerivation,
  fetchurl,
  callPackage,
  buildPackages,
}: let
  esbuild = callPackage ./_esbuild.nix {};
in
  mkDerivation {
    pname = "workerd-esbuild-repository";
    inherit (esbuild) version;
    src = fetchurl {
      urls = ["https://github.com/aspect-build/rules_esbuild/releases/download/v0.26.0/rules_esbuild-v0.26.0.tar.gz"];
      hash = "sha256-KIyhNG1vWqSksSTtg44N53plSV87LHo1A2/PTiluPXs=";
    };
    buildDeps = [buildPackages.nodejs];
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
        name = "install";
        script = ''
          mkdir -p "$out/package/bin" "$out/plugins" "$out/share/licenses/workerd-esbuild-repository"
          cp esbuild/private/launcher.js "$out/launcher.js"
          cp esbuild/private/plugins/bazel-sandbox.js "$out/plugins/"
          cp LICENSE "$out/share/licenses/workerd-esbuild-repository/"
          ln -s ${esbuild}/bin/esbuild "$out/package/bin/esbuild"

          # Match the upstream repository rule's interface without its binary download.
          cat > "$out/BUILD.bazel" <<'BUILD'
          load("@aspect_rules_esbuild//esbuild:toolchain.bzl", "esbuild_toolchain")
          load("@aspect_rules_js//js:defs.bzl", "js_binary")
          load("@aspect_rules_js//npm:defs.bzl", "npm_link_package")

          npm_link_package(
              name = "node_modules/esbuild",
              src = "@npm__esbuild_${esbuild.version}//:pkg",
          )

          js_binary(
              name = "launcher",
              entry_point = "launcher.js",
              data = [":plugins/bazel-sandbox.js", ":node_modules/esbuild"],
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
        '';
      }
    ];
    meta = {
      description = "Source-built esbuild toolchain repository for workerd";
      license = "Apache-2.0";
    };
  }
