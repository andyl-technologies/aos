##! just — A handy way to save and run project-specific commands
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}:
let
  version = "1.46.0";
  src = fetchurl {
    urls = [
      "https://github.com/casey/just/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-9gpXhQLQsp6qKnLFsNkTkLIGTf2NGhKRw7JSXVh/05U=";
  };
in
mkCargoPackage {
  pname = "just";
  inherit version src;

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-NDqWrsIBL+fWS0cLrf2iZuKfyXC5xSj4JfD/QLlsdgA=";
  };

  doCheck = false;

  meta = {
    description = "just — a handy way to save and run project-specific commands";
    homepage = "https://github.com/casey/just";
    license = "CC0-1.0";
    mainProgram = "just";
  };
}
