##! Native Perl runner with target ABI metadata for cross-built XS modules.
{
  buildPackages,
  lib,
  perl,
  stdenv,
}: let
  targetConfigPattern =
    if stdenv.hostPlatform.isDarwin
    then "*-darwin/Config.pm"
    else "*-linux/Config.pm";
in {
  buildPerl = buildPackages.perl;

  setup = lib.optionalString stdenv.isCross ''
    # MakeMaker needs target ABI settings, but native Perl must keep its own
    # architecture modules so it never tries to load target XS binaries.
    targetConfig=$(find ${perl}/lib/perl5 -path '${targetConfigPattern}' -print -quit)
    test -n "$targetConfig"
    mkdir -p .target-perl-config
    cp "$targetConfig" "$(dirname "$targetConfig")/Config_heavy.pl" \
      "$(dirname "$targetConfig")/Errno.pm" \
      .target-perl-config/
    export PERL5LIB="$PWD/.target-perl-config"
  '';
}
