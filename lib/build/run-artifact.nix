##! Builds immutable documents with only their explicitly selected tools.
{pkgs}: name: attrs: script:
builtins.derivation (attrs
  // {
    inherit name script;
    inherit (pkgs.stdenv.buildPlatform) system;
    builder = "${pkgs.bash}/bin/bash";
    args = ["--noprofile" "--norc" "-euc" ''source "$scriptPath"''];
    PATH = "${pkgs.coreutils}/bin";
    passAsFile = ["script"];
    # A compiler closure can turn inert catalog locators into output
    # references. Script contexts retain the actual tools and payloads.
    preferLocalBuild = true;
    allowSubstitutes = false;
  })
