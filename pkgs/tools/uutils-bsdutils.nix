##! uutils bsdutils — Rust BSD utility implementations.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.0.1";
  revision = "3ba11da4ddf49141b2266cec1f956f79db84d3b3";
  src = fetchurl {
    urls = ["https://github.com/uutils/bsdutils/archive/${revision}.tar.gz"];
    hash = "sha256-5P4YvGgZIOnjO69hl3Mxfub3FEjlOm7f4Kl9UFOx9A0=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-k/BZ8NZJAF4dgowBHGP54hbytCBQUFTeI88pA4CI/Cg=";
  };
in
  mkCargoPackage {
    pname = "uutils-bsdutils";
    inherit version src cargoDeps;

    cargoFlags = "--bin bsdutils";
    doCheck = false;

    postInstall = ''
      # This upstream revision currently provides renice.
      ln -s bsdutils "$out/bin/renice"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-bsdutils";
        tool = self;
        command = "${self}/bin/renice --help >/dev/null";
      };
    };

    meta = {
      description = "Rust BSD utilities (currently renice)";
      homepage = "https://github.com/uutils/bsdutils";
      license = "MIT";
      mainProgram = "renice";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
