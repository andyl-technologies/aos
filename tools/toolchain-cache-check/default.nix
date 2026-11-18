##! `toolchain-cache-check`: a command downstream CI runs to prove that the AOS
##! toolchain set downloads from the binary cache instead of building.
##!
##! The script embeds the derivation paths of each system's toolchain set.
##! Discarding their output dependency keeps the `.drv` files, not the
##! toolchains themselves, in the script's closure, so building the script
##! never builds a toolchain. One script can check both Linux platforms from
##! either machine because substitution does not depend on the host system.
{
  pkgs,
  lib,
  # { <system> = { <name> = derivation; }; } for every system to embed.
  toolchainSets,
  # Tests substitute a stub that replays recorded Nix output.
  nixExecutable ? "${pkgs.nix}/bin/nix",
}: let
  systems = builtins.attrNames toolchainSets;

  derivationPaths = toolchains:
    map (name: builtins.unsafeDiscardOutputDependency toolchains.${name}.drvPath)
    (builtins.attrNames toolchains);

  systemVariable = system: "toolchains_${builtins.replaceStrings ["-"] ["_"] system}";

  definitions =
    lib.concatMapStrings (system: ''
      ${systemVariable system}=${lib.escapeShellArg (toString (derivationPaths toolchainSets.${system}))}
    '')
    systems;
in
  pkgs.writeShellScriptBin "toolchain-cache-check" (
    ''
      nix_bin=${nixExecutable}
      toolchain_systems=${lib.escapeShellArg (toString systems)}
    ''
    + definitions
    + builtins.readFile ./toolchain-cache-check.bash
  )
