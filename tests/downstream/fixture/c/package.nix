# A package function for `callPackage`. The AOS package set fills
# `mkDerivation`; the caller passes the phase helpers as overrides, which
# edit an explicit phase list.
{
  mkDerivation,
  replacePhase,
  addPhaseAfter,
  removePhase,
}: let
  basePhases = [
    {
      name = "build";
      script = ''cc -O2 -o hello "$src/hello.c"'';
    }
    {
      name = "install";
      script = "exit 1";
    }
    {
      name = "unused";
      script = "exit 1";
    }
  ];

  withInstall = replacePhase basePhases "install" {
    name = "install";
    script = ''
      mkdir -p "$out/bin"
      cp hello "$out/bin/c-hello"
    '';
  };

  withSmokeTest = addPhaseAfter withInstall "build" {
    name = "smoke-test";
    script = ''test "$(./hello)" = "c: hello"'';
  };
in
  mkDerivation {
    pname = "c-hello";
    version = "1.0.0";
    src = ./.;
    phases = removePhase withSmokeTest "unused";
  }
