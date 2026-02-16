##! alejandra — The uncompromising Nix code formatter
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}:

let
  version = "3.1.0";
  src = fetchurl {
    urls = [
      "https://github.com/kamadorueda/alejandra/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-YpFMBsLiPBkgPSOmWMiU8sXHDUMFJJClgEsCxrHhFjo=";
  };
in
mkCargoPackage {
  pname = "alejandra";
  inherit version src;

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  doCheck = false;

  meta = {
    description = "alejandra — the uncompromising Nix code formatter";
    homepage = "https://github.com/kamadorueda/alejandra";
    license = "Unlicense";
    mainProgram = "alejandra";
  };
}
