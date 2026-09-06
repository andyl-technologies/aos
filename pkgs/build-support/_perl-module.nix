##! Shared builder for pure-Perl CPAN modules.
{
  mkDerivation,
  perl,
}: {
  pname,
  version,
  src,
  sourceRoot,
  module,
  dependencies ? [],
  postInstall ? "",
  description,
  homepage,
  license,
}: let
  dependencyPath = builtins.concatStringsSep ":" (map (dependency: "${dependency}/lib/perl5") dependencies);
in
  mkDerivation {
    inherit pname version src;

    buildDeps = [perl];
    runtimeDeps = [perl] ++ dependencies;
    propagatedDeps = dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ${sourceRoot}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/perl5"
          cp -a lib/. "$out/lib/perl5/"
          ${postInstall}

          PERL5LIB="$out/lib/perl5:${dependencyPath}" \
            ${perl}/bin/perl -M${module} -e 1
        '';
      }
    ];

    meta = {
      inherit description homepage license;
    };
  }
