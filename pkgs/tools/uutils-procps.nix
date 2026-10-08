##! uutils procps — Rust process utilities.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  systemd,
}: let
  version = "0.0.1";
  revision = "b536810e8746385e1862aa8e344821854e2fea79";
  src = fetchurl {
    urls = ["https://github.com/uutils/procps/archive/${revision}.tar.gz"];
    hash = "sha256-6euvqz5cqAWmPjj2fp/Dhp4Fgwz0nXge1wSs5CviuSA=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-p+aG606aDoNP8OxFKCCc7qEN9H5k1Q5YlPHRl6i00sc=";
  };
in
  mkCargoPackage {
    pname = "uutils-procps";
    inherit version src cargoDeps;

    cargoFlags = "--bin procps";
    buildDeps = [pkg-config];
    runtimeDeps = [systemd];
    doCheck = false;

    postInstall = ''
      cargo tree --offline --depth 1 --edges normal,build --format '{p}' --prefix none \
        | sed -n 's/^uu_\([^ ]*\) .*/\1/p' \
        | while read -r utility; do
            ln -s procps "$out/bin/$utility"
          done

      test -L "$out/bin/ps"
      test -L "$out/bin/free"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-procps";
        tool = self;
        command = "${self}/bin/ps --help >/dev/null";
      };
    };

    meta = {
      description = "Rust process utilities";
      homepage = "https://github.com/uutils/procps";
      license = "MIT";
      mainProgram = "ps";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
