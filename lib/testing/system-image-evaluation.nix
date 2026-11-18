##! Instantiates every discovered system's image without building it.
##!
##! Fixture systems that layer authored policy onto a golden image can enable
##! services whose packages the image never admits, and nothing on the eval
##! path notices until an image or fleet build resolves them. Forcing each
##! image derivation path runs the complete stage and package-module
##! evaluation for every standalone system while scheduling no image builds:
##! the recorded paths carry no string context, so the check depends on none
##! of them.
{
  pkgs,
  lib,
  systems,
}: let
  # Release variants defer signing to an external finalizer and expose their
  # unsigned assembly instead of a final image; that assembly evaluates the
  # same host and initrd stages.
  imageFor = system:
    if system.config.aos.boot.secureBoot.externalFinalization.enable
    then system.build.unsignedImageAssembly
    else system.build.image.raw;

  imageDrvPaths =
    lib.mapAttrs (_: system: builtins.unsafeDiscardStringContext (imageFor system).drvPath) systems;
in
  pkgs.mkDerivation {
    pname = "aos-system-image-evaluation";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          cat > "$out/images.json" <<'EOF'
          ${builtins.toJSON imageDrvPaths}
          EOF
          echo PASS > "$out/result"
        '';
      }
    ];
  }
