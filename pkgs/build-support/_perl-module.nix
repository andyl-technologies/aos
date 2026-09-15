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
  runtimeClosure = [perl] ++ dependencies;
  dependencyPath = builtins.concatStringsSep ":" (map (dependency: "${dependency}/lib/perl5") dependencies);
  runtimeClosureManifest = builtins.concatStringsSep "\n" (map builtins.toString runtimeClosure);
in
  mkDerivation {
    inherit pname version src;

    buildDeps = [perl];
    runtimeDeps = runtimeClosure;
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

          # Pure Perl files do not acquire Nix references through linking.
          # Retain the interpreter and module graph required to load them.
          mkdir -p "$out/nix-support"
          cat > "$out/nix-support/runtime-closure" <<'EOF'
          ${runtimeClosureManifest}
          EOF

          PERL5LIB="$out/lib/perl5:${dependencyPath}" \
            ${perl}/bin/perl -M${module} -e 1
        '';
      }
    ];

    meta = {
      inherit description homepage license;
    };
  }
