##! esbuild — JavaScript and CSS bundler built from upstream Go sources.
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.28.1";
  src = fetchurl {
    urls = [
      "https://github.com/evanw/esbuild/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-ZcdW+ofUMXisSlJCRUwr0P3jJfjs93mX+PpLiPlNXNI=";
  };
in
  mkGoPackage {
    pname = "esbuild";
    inherit version src;
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-S2uhvYBwdLq6KEv59RmLqLgosbGxK1A6hMaVu6qnnfI=";
    };
    goPackage = "./cmd/esbuild";
    goOutput = "esbuild";
    doCheck = false;
    runtimeDeps = [];
    meta = {
      description = "JavaScript and CSS bundler built from source";
      homepage = "https://esbuild.github.io/";
      license = "MIT";
    };
  }
