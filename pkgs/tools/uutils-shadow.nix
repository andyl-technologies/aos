##! uutils shadow — Rust account and group management tools.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  linux-pam,
  libxcrypt,
}: let
  version = "0.5.1";
  src = fetchurl {
    urls = ["https://github.com/uutils/shadow/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-D6hi+4xCXLznR8hueD/9B+x4cHgSBCB+QhJaGCVNkWE=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-hDwHivfVulgXhh1dvteuAxlONadgolZ2MbJUF8BtA7Y=";
  };
in
  mkCargoPackage {
    pname = "uutils-shadow";
    inherit version src cargoDeps;

    cargoFlags = "--bin shadow-rs";
    buildFeatures = ["pam"];
    runtimeDeps = [linux-pam libxcrypt];
    doCheck = false;

    postInstall = ''
      cargo tree --offline --depth 1 --edges normal,build --features pam \
        --format '{p}' --prefix none \
        | sed -n '1d; s/^uu_\([^ ]*\) .*/\1/p' \
        | while read -r utility; do
            ln -s shadow-rs "$out/bin/$utility"
          done

      test -L "$out/bin/passwd"
      test -L "$out/bin/useradd"
      test -L "$out/bin/groupadd"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-shadow";
        tool = self;
        command = ''
          applets=$(${self}/bin/shadow-rs --list)
          case "$applets" in
            *passwd*useradd*userdel*) printf 'shadow-applets\n' ;;
            *) exit 1 ;;
          esac
        '';
        expectedOutput = "shadow-applets";
      };
    };

    meta = {
      description = "Rust account and group management tools";
      homepage = "https://github.com/uutils/shadow";
      license = "MIT";
      mainProgram = "shadow-rs";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
