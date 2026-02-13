# pkgs/tools/aos.nix — AOS build tool (crane-built)
#
# Built with the host Rust toolchain via crane, not the AOS
# self-bootstrapping stdenv. This is a dev tool, not an OS component.
#
# Build: nix build .#aos
{ craneLib, pkgs }:

let
  src = craneLib.cleanCargoSource ../../cli;
  commonArgs = {
    inherit src;
    pname = "aos";
    version = "0.1.0";
    strictDeps = true;
  };
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  runtimeDeps = [
    pkgs.git
    pkgs.nix
    pkgs.nixfmt
  ];
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    nativeBuildInputs = [ pkgs.makeWrapper ];

    postInstall = ''
      wrapProgram $out/bin/aos \
        --prefix PATH : ${pkgs.lib.makeBinPath runtimeDeps}
    '';

    meta.description = "AOS build tool";
    meta.mainProgram = "aos";
  }
)
