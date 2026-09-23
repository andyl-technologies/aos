##! Source-built build tool for the Workers runtime.
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  lib,
}: let
  version = "3.4.0";
  src = fetchurl {
    urls = ["https://github.com/bazel-contrib/bazel-lib/archive/refs/tags/v${version}.tar.gz"];
    hash = "1njs14jzf2i34qc3icmjp59g58wwg8zfph4f19nvgdfq6zpjrwwc";
  };
in
  mkGoPackage {
    pname = "workerd-bazel-copy-directory";
    inherit version src;
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-0iJxSBFPPfK9/vZxnPWvqm+cMt/+cD5+56x2u4Z/Ex4=";
    };
    goPackage = "./tools/copy_directory";
    goOutput = "copy_directory";
    doCheck = true;
    runtimeDeps = [];
    postInstall = ''
      mkdir -p "$out/share/licenses/workerd-bazel-copy-directory"
      cp LICENSE "$out/share/licenses/workerd-bazel-copy-directory/"
    '';
  }
