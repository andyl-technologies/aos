##! aos — AOS build tool
{
  mkCargoPackage,
  fetchCargoDeps,
  git,
  nix,
}: let
  version = "0.1.0";
  src = builtins.path {
    path = ../../cli;
    name = "aos-cli-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-gMnRobrTtGEeOlR/ewCeeqE0zXuAJcxkl/HTaMT3jx4=";
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
