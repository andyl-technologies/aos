##! ripgrep — Recursive regular-expression search
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  pcre2,
}: let
  version = "15.2.0";
  src = fetchurl {
    urls = ["https://github.com/BurntSushi/ripgrep/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-dgUknT6w1fFw40FEmOM0Tiax56FHrsUYtXCQuAA2pWI=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Dn+cJ9eqr5HfMsMqtSyOF1PwBVabKrDqTBNu4NA6HO0=";
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
