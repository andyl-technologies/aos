##! Installs the original six-command systemd package from Bazel declarations.
{
  packageArguments,
  cargoFallback,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-systemd-provider-bazel-build.nix {};
  programsFor = pname: packageLabel:
    mkAosBazelPackage {
      inherit pname packageLabel;
      inherit (packageArguments) version runtimeDeps;
      build = compilation.build;
    };
  activationPrograms = programsFor "aos-systemd-provider" "//crates/activation/aos-activation-systemd:production_package";
  bootPrograms = programsFor "aos-systemd-provider-boot-tools" "//crates/boot/aos-boot-runtime:systemd_production_package";
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification runtimeDeps meta;
      src = null;
      buildDeps = [activationPrograms bootPrograms compilation.tests patchelf];
      disallowedReferences = [activationPrograms bootPrograms compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${activationPrograms}/bin/* ${bootPrograms}/bin/* "$out/bin/"

            # Solib directories belong to Bazel's execution tree. Keep only
            # the immutable paths that resolve the installed runtime libraries.
            for program in "$out/bin/"*; do
              original_rpath="$(${patchelf}/bin/patchelf --print-rpath "$program")"
              installed_rpath=
              original_ifs="$IFS"
              IFS=:
              for directory in $original_rpath; do
                case "$directory" in
                  /nix/store/*) installed_rpath="''${installed_rpath:+$installed_rpath:}$directory" ;;
                  '$ORIGIN/'*'_solib_'*) ;;
                  *) echo "Unexpected systemd provider search path: $directory" >&2; exit 1 ;;
                esac
              done
              IFS="$original_ifs"
              ${patchelf}/bin/patchelf --set-rpath "$installed_rpath" "$program"
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
        };
    }
