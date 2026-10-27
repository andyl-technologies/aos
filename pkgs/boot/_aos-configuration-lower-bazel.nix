##! Preserves configuration installation while Bazel owns static compilation.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-configuration-lower-bazel-build.nix {};
  programs = mkAosBazelPackage {
    # These tools are embedded as immutable paths in the command binaries.
    # Declaring them here prevents intermediate package fixup scrubbing them.
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/boot/aos-configuration-image:static_package";
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
            for command in aos-certificate-bundle aos-configuration-boot aos-configuration-lower aos-configuration-mount; do
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
          bazelTools = compilation.tools;
        };
    }
