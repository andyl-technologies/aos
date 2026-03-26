##! aos — AOS build tool
{
  mkCargoPackage,
  fetchCargoDeps,
  git,
  nix,
}:
let
  version = "0.1.0";
  src = builtins.path {
    path = ../../crates;
    name = "aos-crates-src";
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      base != "target" && base != ".git";
  };
in
mkCargoPackage {
  pname = "aos";
  inherit version src;

  cargoFlags = "-p aos";

  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  doCheck = false;

  postInstall = ''
        mv $out/bin/aos $out/bin/.aos-unwrapped
        cat > $out/bin/aos << 'WRAPPER'
    #!/bin/sh
    export PATH="${git}/bin:${nix}/bin''${PATH:+:$PATH}"
    exec "$(dirname "$0")/.aos-unwrapped" "$@"
    WRAPPER
        chmod +x $out/bin/aos
  '';

  meta = {
    description = "aos — AOS build tool";
    homepage = "https://github.com/andyl/andyl-os";
    license = "MIT";
  };
}
