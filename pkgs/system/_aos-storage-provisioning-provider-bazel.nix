##! Installs the static provisioning commands and their original shell helpers.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-storage-provisioning-provider-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version;
    build = compilation.build;
    packageLabel = "//crates/activation/aos-activation-storage:static_provisioning_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module moduleDeps runtimeDeps postInstall meta;
      src = null;
      buildDeps = [programs compilation.tests patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            for command in aos-storage-provisioning-provider aos-storage-provisioning-marker-observer; do
              install -m 755 "${programs}/bin/$command" "$out/bin/"
            done
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
