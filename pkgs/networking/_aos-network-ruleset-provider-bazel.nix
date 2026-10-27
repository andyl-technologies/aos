##! Installs the static network-ruleset provider with its original package contract.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-network-ruleset-provider-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/activation/aos-activation-nftables:static_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module moduleDeps checks runtimeDeps postInstall meta;
      src = null;
      buildDeps = [programs compilation.tests patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${programs}/bin/aos-network-ruleset-provider "$out/bin/"
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
          bazelLibraries = compilation.libraries;
        };
    }
