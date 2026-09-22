##! Markdown book renderer with search, live serving, and file watching.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
  stdenv,
}: let
  version = "0.5.4";
  src = fetchurl {
    urls = ["https://github.com/rust-lang/mdBook/archive/refs/tags/v${version}.tar.gz"];
    hash = "0jslymmwl5ha9mm69rgga1v0iv8fqlk7ikpnnr9pvirm1hri8xhh";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "mdbook";
    inherit version src;
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "mdbook-${version}-vendor";
      hash = "sha256-OmlcPZuQ1RbyFrF5tuztucgtCA544UHJxEaXh/mfSHQ=";
    };
    cargoFlags = "-p mdbook";
    cargoTestFlags = "--workspace";
    doCheck = !stdenv.isCross;
    postInstall = ''
      mkdir -p "$out/share/licenses/mdbook"
      cp LICENSE "$out/share/licenses/mdbook/"
    '';
    meta = {
      description = "Create searchable HTML books from Markdown";
      homepage = "https://rust-lang.github.io/mdBook/";
      license = "MPL-2.0";
      mainProgram = "mdbook";
    };
  }
