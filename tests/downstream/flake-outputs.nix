##! Evaluation of every per-system flake output for the cross-built systems.
##!
##! The `aarch64-linux` outputs come from a package set cross-built on the
##! `x86_64-linux` coordinator, and no other gate evaluates them. This check
##! instantiates each `packages`, `devShells`, `checks`, and `formatter`
##! derivation, each app program, each `lib` toolchain, and each `aosSystems`
##! top level for those systems: what `nix flake check --all-systems
##! --no-build` instantiates for them. Like `fixture-eval`, it keeps only the
##! `.drv` files as inputs, so building it never builds an output.
{
  pkgs,
  lib,
  # `(import ./flake.nix).outputs {}` of the repository.
  flakeOutputs,
  coordinatorSystem ? "x86_64-linux",
}: let
  systems = builtins.filter (system: system != coordinatorSystem) (builtins.attrNames flakeOutputs.lib);

  drvFile = drv: builtins.unsafeDiscardOutputDependency drv.drvPath;

  # App programs are store paths whose context names the program's
  # derivation; the derivation's outputs still need not be realized.
  programFiles = app:
    map builtins.unsafeDiscardOutputDependency
    (builtins.attrNames (builtins.getContext app.program));

  forSystem = system: let
    attrsDrvs = attrs: map drvFile (builtins.attrValues attrs);
    packages = flakeOutputs.packages.${system};
    variants = flakeOutputs.aosSystems.${system};
  in
    attrsDrvs packages
    ++ attrsDrvs flakeOutputs.devShells.${system}
    ++ attrsDrvs flakeOutputs.checks.${system}
    ++ [(drvFile flakeOutputs.formatter.${system})]
    ++ builtins.concatMap programFiles (builtins.attrValues flakeOutputs.apps.${system})
    ++ attrsDrvs flakeOutputs.lib.${system}.toolchains
    ++ map (variant: drvFile variant.build.toplevel) (builtins.attrValues variants);

  derivations = lib.unique (builtins.concatMap forSystem systems);
in
  pkgs.mkDerivation {
    pname = "aos-downstream-flake-outputs-check";
    version = "0";
    src = null;
    flakeOutputDerivations = derivations;
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
