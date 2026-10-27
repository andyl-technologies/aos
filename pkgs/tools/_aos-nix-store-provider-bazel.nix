##! Installs the static Nix database handler with its immutable Nix companion.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  nix,
  stdenv,
}: let
  compilation = callPackage ./_aos-nix-store-provider-bazel-build.nix {};
  program = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/activation/aos-activation-nix-store:static_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module moduleDeps runtimeDeps meta;
      src = null;
      buildDeps = [program compilation.tests];
      disallowedReferences = [program compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/libexec"
            install -m 755 ${program}/bin/aos-nix-store-provider "$out/bin/"
            ln -s ${nix}/bin/nix-store "$out/libexec/nix-store"
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
