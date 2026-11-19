##! Coalesces identical files in private immutable-image staging trees.
{
  mkDerivation,
  writeShellScriptBin,
  bash,
  coreutils,
  findutils,
  util-linux,
}: let
  helper = writeShellScriptBin "aos-image-hardlink-tree" ''
    export PATH="${coreutils}/bin:${findutils}/bin:${util-linux}/bin"
    ${builtins.readFile ./_image-hardlink-tree.sh}
  '';
in
  mkDerivation {
    pname = "image-hardlink-tree";
    version = "1.0.0";
    platformSupport = {
      inherit (util-linux.platformSupport) build host;
      target = [];
      role = "build-input";
    };
    src = null;
    # The install phase only copies the helper. Listing it as a build
    # dependency would require running it on the builder, which a cross
    # build of this package cannot do.
    runtimeDeps = [bash coreutils findutils util-linux];
    propagatedDeps = [];
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp ${helper}/bin/aos-image-hardlink-tree "$out/bin/"
        '';
      }
    ];

    meta = {
      description = "Shares identical immutable-image files without changing their metadata";
      license = "Apache-2.0";
      mainProgram = "aos-image-hardlink-tree";
    };
  }
