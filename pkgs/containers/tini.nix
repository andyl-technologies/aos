##! tini — Minimal container init process
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "0.19.0";
in
  mkDerivation {
    pname = "tini";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/krallin/tini/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-D9NacDAFKs2fWJSNHZAP4eQy7jcQPFVhVUQIvaxrvw0=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];
    cmakeFlags = "-DMINIMAL=ON";

    postInstall = ''
      test -x "$out/bin/tini"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tini";
        tool = self;
        command = "tini --version";
      };
    };

    meta = {
      description = "Minimal init process for containers";
      homepage = "https://github.com/krallin/tini";
      license = "MIT";
      mainProgram = "tini";
    };
  }
