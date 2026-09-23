##! Source-built esbuild matching workerd's Bazel JavaScript launcher.
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  stdenv,
  version ? "0.19.9",
  srcHash ? "1pw8yhpmbacp5gfb2872isxdsfw4w6sgc1g942ipjdfrfcdpb3lr",
}: let
  src = fetchurl {
    urls = ["https://github.com/evanw/esbuild/archive/refs/tags/v${version}.tar.gz"];
    hash = srcHash;
  };
in
  mkGoPackage {
    pname = "workerd-esbuild";
    inherit version src;
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-S2uhvYBwdLq6KEv59RmLqLgosbGxK1A6hMaVu6qnnfI=";
    };
    goPackage = "./cmd/esbuild";
    goOutput = "esbuild";
    doCheck = !stdenv.isCross;
    runtimeDeps = [];
    postInstall = ''
      mkdir -p "$out/share/licenses/workerd-esbuild"
      cp LICENSE.md "$out/share/licenses/workerd-esbuild/"
    '';
    meta = {
      description = "JavaScript and CSS bundler for workerd's build";
      homepage = "https://esbuild.github.io/";
      license = "MIT";
      mainProgram = "esbuild";
    };
  }
