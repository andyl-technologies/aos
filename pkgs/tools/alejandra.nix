##! alejandra — The uncompromising Nix code formatter
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}:
let
  version = "4.0.0";
  src = fetchurl {
    urls = [
      "https://github.com/kamadorueda/alejandra/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-8/mYnD+2pW4gUL9TKWkvrjKitUvnwGUqo5Sv5GYOu3Q=";
  };
in
mkCargoPackage {
  pname = "alejandra";
  inherit version src;

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-CXZMZ5PIyJt7AKabAMbMVAnwZ1eFA/3fvyOtCizAaaQ=";
  };

  doCheck = false;

  meta = {
    description = "alejandra — the uncompromising Nix code formatter";
    homepage = "https://github.com/kamadorueda/alejandra";
    license = "Unlicense";
    mainProgram = "alejandra";
  };
}
