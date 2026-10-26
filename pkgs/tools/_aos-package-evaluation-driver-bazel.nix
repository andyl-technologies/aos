##! Installs the native evaluation fixture driver without Cargo build inputs.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-package-evaluation-driver-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/packages/aos-package-manager:package_evaluation_driver_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport runtimeDeps meta;
      src = null;
      buildDeps = [programs patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            program="$out/bin/package_deployment_check"
            install -m 755 ${programs}/bin/package_deployment_check "$program"

            original_rpath="$(${patchelf}/bin/patchelf --print-rpath "$program")"
            installed_rpath=
            original_ifs="$IFS"
            IFS=:
            for directory in $original_rpath; do
              case "$directory" in
                /nix/store/*) installed_rpath="''${installed_rpath:+$installed_rpath:}$directory" ;;
                '$ORIGIN/'*'_solib_'*) ;;
                *) echo "Unexpected evaluation driver search path: $directory" >&2; exit 1 ;;
              esac
            done
            IFS="$original_ifs"
            ${patchelf}/bin/patchelf --set-rpath "$installed_rpath" "$program"
          '';
        }
      ];
      passthru =
        packageArguments.passthru
        // {
          buildDriver = "bazel";
          inherit cargoFallback;
          bazelBuild = compilation.build;
          bazelWorkspace = compilation.workspace;
        };
    }
