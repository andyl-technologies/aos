##! Installs a static Rust BPF provider and its Bazel-built native artifacts.
{
  packageArguments,
  cargoFallback,
  providerPackage,
  callPackage,
  mkDerivation,
  mkAosBazelPackage,
  patchelf,
  stdenv,
}: let
  compilation = callPackage ./_aos-bpf-policy-bazel-build.nix {};
  programs = mkAosBazelPackage {
    inherit (packageArguments) pname version runtimeDeps;
    build = compilation.build;
    packageLabel = "//crates/activation/${providerPackage}:static_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit (packageArguments) pname version platformSupport qualification module checks runtimeDeps meta;
      moduleDeps = packageArguments.moduleDeps or [];
      src = null;
      buildDeps = [programs compilation.tests patchelf];
      disallowedReferences = [programs compilation.build compilation.workspace.source];
      phases = [
        {
          name = "install";
          script = ''
            cp -a ${programs}/. "$out/"
            chmod -R u+w "$out"
            rm "$out/nix-support/bazel-package.json"
            for loader in "$out/libexec/"*; do
              original_rpath="$(${patchelf}/bin/patchelf --print-rpath "$loader")"
              installed_rpath=
              original_ifs="$IFS"
              IFS=:
              for directory in $original_rpath; do
                case "$directory" in
                  /nix/store/*) installed_rpath="''${installed_rpath:+$installed_rpath:}$directory" ;;
                  '$ORIGIN/'*'_solib_'*) ;;
                  *) echo "Unexpected BPF loader search path: $directory" >&2; exit 1 ;;
                esac
              done
              IFS="$original_ifs"
              ${patchelf}/bin/patchelf --set-rpath "$installed_rpath" "$loader"
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
