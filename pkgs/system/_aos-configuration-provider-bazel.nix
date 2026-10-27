##! Installs the Bazel configuration provider with its original module contract.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  stdenv,
}: let
  compilation = callPackage ./_aos-configuration-provider-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/activation/aos-activation-config-files:package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport module moduleDeps runtimeDeps meta;
      src = null;
      buildDeps = [programs compilation.tests];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${programs}/bin/aos-configuration-provider ${programs}/bin/aos-account-lookup "$out/bin/"
          '';
        }
      ];
      passthru =
        packageArguments.passthru
        // {
          buildDriver = "bazel";
          inherit cargoFallback;
          bazelBuild = compilation.build;
          bazelTests = compilation.tests;
          bazelWorkspace = compilation.workspace;
          bazelTestWorkspace = compilation.testWorkspace;
        };
    }
