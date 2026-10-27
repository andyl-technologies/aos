##! Installs the Bazel metadata providers with its original module contract.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
  nix,
}: let
  compilation = callPackage ./_aos-metadata-provider-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/boot/aos-platform-metadata:package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module runtimeDeps meta;
      src = null;
      buildDeps = [programs compilation.tests patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${programs}/bin/aos-metadata-acquisition-provider ${programs}/bin/aos-metadata-policy-provider "$out/bin/"

            # Bazel's solib tree belongs to the build workspace. Installed
            # programs resolve the same libraries through immutable store paths.
            for program in "$out/bin/"*; do
              original_rpath="$(${patchelf}/bin/patchelf --print-rpath "$program")"
              installed_rpath=
              original_ifs="$IFS"
              IFS=:
              for directory in $original_rpath; do
                case "$directory" in
                  /nix/store/*) installed_rpath="''${installed_rpath:+$installed_rpath:}$directory" ;;
                  '$ORIGIN/'*'_solib_'*) ;;
                  *) echo "Unexpected metadata provider search path: $directory" >&2; exit 1 ;;
                esac
              done
              IFS="$original_ifs"
              ${patchelf}/bin/patchelf --set-rpath "$installed_rpath" "$program"
            done
            mkdir -p "$out/libexec"
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
        };
    }
