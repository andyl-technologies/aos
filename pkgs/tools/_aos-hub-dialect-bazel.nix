##! Installs the native required-live SQL dialect test driver without Cargo build inputs.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-hub-dialect-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/hub/aos-hub-native:dialect_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification runtimeDeps meta checks;
      src = null;
      buildDeps = [programs patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            program="$out/bin/aos-hub-dialect-contract"
            install -m 755 ${programs}/bin/aos-hub-dialect-contract "$program"

            original_rpath="$(${patchelf}/bin/patchelf --print-rpath "$program")"
            installed_rpath=
            original_ifs="$IFS"
            IFS=:
            for directory in $original_rpath; do
              case "$directory" in
                /nix/store/*) installed_rpath="''${installed_rpath:+$installed_rpath:}$directory" ;;
                '$ORIGIN/'*'_solib_'*) ;;
                *) echo "Unexpected dialect driver search path: $directory" >&2; exit 1 ;;
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
