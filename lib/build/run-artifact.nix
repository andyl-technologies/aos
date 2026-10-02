##! Builds immutable documents with only their explicitly selected tools.
{pkgs}: let
  buildPackages = pkgs.buildPackages or pkgs;
in
  name: attrs: script:
    builtins.derivation (attrs
      // {
        inherit name script;
        inherit (buildPackages.stdenv.buildPlatform) system;
        builder = "${buildPackages.bash}/bin/bash";
        args = ["--noprofile" "--norc" "-euc" ''source "$scriptPath"''];
        PATH = "${buildPackages.coreutils}/bin";
        passAsFile = ["script"] ++ (attrs.passAsFile or []);
        # A compiler closure can turn inert catalog locators into output
        # references. Script contexts retain the actual tools and payloads.
        preferLocalBuild = true;
        allowSubstitutes = false;
      })
