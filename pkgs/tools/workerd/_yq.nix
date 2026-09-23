##! Source-built build tool for the Workers runtime.
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  lib,
}: let
  version = "4.45.1";
  src = fetchurl {
    urls = ["https://github.com/mikefarah/yq/archive/refs/tags/v${version}.tar.gz"];
    hash = "09v4v5gnrsngvqm11j2ig41ks210qhgssr00hnrisan30ah22jh7";
  };
in
  mkGoPackage {
    pname = "workerd-yq";
    inherit version src;
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-kwP6sAu2WTBwfOWekQIqtZtyaci5KQIlB4rQdGgfmKk=";
    };
    goPackage = ".";
    goOutput = "yq";
    # Date operators must work without a host timezone database.
    tags = ["timetzdata"];
    doCheck = true;
    runtimeDeps = [];
    postInstall = ''
      mkdir -p "$out/share/licenses/workerd-yq"
      cp LICENSE "$out/share/licenses/workerd-yq/"
    '';
  }
