##! uutils findutils — Rust find, xargs, locate, and updatedb.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  oniguruma,
}: let
  version = "0.10.0";
  src = fetchurl {
    urls = ["https://github.com/uutils/findutils/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-42rjk3+Im8Wc+9ZYIKZCuqaVxY1/oeOH5BhX5xD0BBk=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-8CVZNB0pRHP+7bBSnxza1G/rffGrOXt3A3HtXwVluGg=";
  };
in
  mkCargoPackage {
    pname = "uutils-findutils";
    inherit version src cargoDeps;

    cargoFlags = "--bin find --bin xargs --bin locate --bin updatedb";
    buildDeps = [pkg-config];
    runtimeDeps = [oniguruma];
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-findutils";
        tool = self;
        command = ''
          printf 'probe' > /tmp/uutils-find-probe
          ${self}/bin/find /tmp -maxdepth 1 -name uutils-find-probe -print
        '';
        expectedOutput = "/tmp/uutils-find-probe";
      };
    };

    meta = {
      description = "Rust find, xargs, locate, and updatedb utilities";
      homepage = "https://github.com/uutils/findutils";
      license = "MIT";
      mainProgram = "find";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
