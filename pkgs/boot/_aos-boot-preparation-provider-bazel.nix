##! Installs the static preparation provider with its original package contract.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-boot-preparation-provider-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version;
    build = compilation.build;
    packageLabel = "//crates/boot/aos-boot-runtime:preparation_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module runtimeDeps postInstall meta;
      src = null;
      buildDeps = [programs compilation.tests patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${programs}/bin/aos-boot-preparation-provider "$out/bin/"
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
