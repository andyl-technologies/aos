##! Bazel 8 source tree with source-built JaCoCo release inputs.
{
  mkDerivation,
  bazelSource8,
  bazelJacoco,
}: let
  version = "8.6.0";
in
  mkDerivation {
    pname = "bazel-source-prepared";
    inherit version;
    src = bazelSource8;

    buildDeps = [];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a "$src"/. "$out"/
          chmod -R u+w "$out"

          destination="$out/third_party/java/jacoco"
          for archive in ${bazelJacoco}/share/java/*.jar; do
            cp "$archive" "$destination/"
          done
        '';
      }
    ];
  }
