##! ripgrep — Recursive regular-expression search
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  pcre2,
}: let
  version = "15.1.0";
  src = fetchurl {
    urls = ["https://github.com/BurntSushi/ripgrep/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-BG+gGiFnk7i9J1D51o1K1DmG65wNYSJgD5k5BgEpcug=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-IS/LSRQjLWf66xqxnI71Shku9XHMXHhC9S3VfA9YSYM=";
  };
in
  mkCargoPackage {
    pname = "ripgrep";
    inherit version src cargoDeps;

    buildDeps = [pkg-config];
    runtimeDeps = [pcre2];
    buildFeatures = ["pcre2"];
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-ripgrep";
        tool = self;
        command = "printf 'alpha\\nbeta\\n' | rg --pcre2 '^beta$' >/dev/null";
      };
    };

    meta = {
      description = "Fast recursive regular-expression search tool";
      homepage = "https://github.com/BurntSushi/ripgrep";
      license = "Unlicense OR MIT";
      mainProgram = "rg";
    };
  }
