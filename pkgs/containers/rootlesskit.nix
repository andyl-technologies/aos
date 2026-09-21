##! rootlesskit — User namespaces for rootless container engines
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "3.1.0";
  src = fetchurl {
    urls = ["https://github.com/rootless-containers/rootlesskit/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-cSE86oB3aBy0wYlJKbmZQsEcUl0JvZD2JGtdM0P/Fkg=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-9yZOBDwi763P9oE/6QIK3RnET4llT51Ec0ts4oM/mb0=";
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
