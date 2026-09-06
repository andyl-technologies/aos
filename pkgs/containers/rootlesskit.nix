##! rootlesskit — User namespaces for rootless container engines
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "2.3.6";
  src = fetchurl {
    urls = ["https://github.com/rootless-containers/rootlesskit/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-tJGumkRPX0y5JZE9+hKteivNiqFJEU33r7L6khNZtuE=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-chcWxIVr/glCSroY6JL8pth2alWoA7mEgmRt5G0dpMU=";
  };
in
  mkGoPackage {
    pname = "rootlesskit";
    inherit version src goModules;
    goPackage = "./cmd/rootlesskit";
    goOutput = "rootlesskit";
    doCheck = false;

    postInstall = ''
      go build -trimpath -mod=readonly -ldflags "-s -w"         -o "$out/bin/rootlessctl" ./cmd/rootlessctl
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-rootlesskit";
        tool = self;
        command = "rootlesskit --version && rootlessctl --help >/dev/null";
      };
    };

    meta = {
      description = "Linux-native user namespaces for rootless containers";
      homepage = "https://github.com/rootless-containers/rootlesskit";
      license = "Apache-2.0";
      mainProgram = "rootlesskit";
    };
  }
