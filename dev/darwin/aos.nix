{system}: let
  rust = import ./rust-toolchain.nix {inherit system;};
  lib = import ../../lib {inherit system;};
  phases = import ../../stdenv/phases.nix;
  src = builtins.path {
    path = ../../cli;
    name = "aos-cli-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
  cargoDeps = lib.fetchCargoDeps {
    cargo = rust;
    bootstrapTools = null;
    inherit src;
    hash = "sha256-+BFoZk6FNUvkOSnwiy/ErD09Kx34ZRno3yw6qV/FmbQ=";
    inherit system;
  };

  # On Darwin we use the system cc and coreutils — inject them into PATH
  darwinPathSetup = ''
    export PATH="$PATH:/usr/bin:/bin:/usr/sbin:/sbin"
  '';

  basePhases = phases.cargoPhases {
    inherit cargoDeps;
    doCheck = false;
  };

  # Patch phases for Darwin:
  # 1. Prepend system PATH to unpack phase
  # 2. Replace install phase (macOS find lacks -executable)
  # 3. Drop fixup phase (strip/patchelf are Linux-only)
  phasesWithDarwinFixes =
    builtins.map (
      phase:
        if phase.name == "unpack"
        then phase // {script = darwinPathSetup + phase.script;}
        else if phase.name == "install"
        then
          phase
          // {
            script = ''
              mkdir -p "$out/bin"
              install -m 755 target/release/aos "$out/bin/"
            '';
          }
        else phase
    )
    (builtins.filter (phase: phase.name != "fixup") basePhases);
in
  lib.mkDerivation {
    pname = "aos";
    version = "0.1.0";
    inherit src system;
    buildDeps = [rust];
    phases = phasesWithDarwinFixes;
    meta.description = "aos — AOS build tool";
  }
