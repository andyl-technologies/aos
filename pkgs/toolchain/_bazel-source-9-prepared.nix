##! Bazel 9 source tree populated with source-built Java distribution inputs.
{
  mkDerivation,
  bazelSource9,
  bazelJacoco,
  buildPackages,
  fetchurl,
}: let
  asm = import ./_bazel-asm.nix {
    inherit mkDerivation fetchurl buildPackages;
    includeBazel9 = true;
  };
  asmSourceInstall = builtins.concatStringsSep "\n" (builtins.map (
    archive: ''
      cp ${archive.src} "$out/third_party/asm/${archive.component}-${archive.version}-sources.jar"
    ''
  ) (builtins.filter (archive: archive.version == "9.9") asm.passthru.sourceArchives));
in
  mkDerivation {
    pname = "bazel-source-prepared";
    version = "9.2.0";
    src = bazelSource9;
    buildDeps = [];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a "$src"/. "$out"/
          chmod -R u+w "$out"

          cp ${bazelJacoco}/share/java/*.jar "$out/third_party/java/jacoco/"
          cp ${asm}/share/java/*-9.9.jar "$out/third_party/asm/"
          ${asmSourceInstall}
        '';
      }
    ];
  }
