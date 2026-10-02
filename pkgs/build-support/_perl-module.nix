##! Shared builder for pure-Perl CPAN modules.
{
  mkDerivation,
  buildPackages,
  perl,
}: {
  pname,
  platformSupport,
  version,
  src,
  sourceRoot,
  module,
  dependencies ? [],
  postInstall ? "",
  description,
  homepage,
  license,
  qualification ? null,
}: let
  runtimeClosure = [perl] ++ dependencies;
  # The Linux builder cannot execute target Perl or load target XS extensions.
  # Validate against native counterparts while retaining target dependencies.
  buildPerl = buildPackages.perl;
  validationDependencies = map (dependency: buildPackages.${dependency.pname}) dependencies;
  validationPath = builtins.concatStringsSep ":" (map (dependency: "${dependency}/lib/perl5") validationDependencies);
  runtimeClosureManifest = builtins.concatStringsSep "\n" (map builtins.toString runtimeClosure);
in
  mkDerivation {
    inherit pname version src qualification platformSupport;

    buildDeps = [buildPerl] ++ validationDependencies;
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

          PERL5LIB="$out/lib/perl5:${validationPath}" \
            ${buildPerl}/bin/perl -M${module} -e 1
        '';
      }
    ];

    meta = {
      inherit description homepage license;
    };
  }
