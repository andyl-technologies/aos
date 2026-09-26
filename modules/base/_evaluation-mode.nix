##! Distinguishes image construction from on-host configuration evaluation.
{lib, ...}: {
  options.aos.config.evaluationMode = lib.mkOption {
    type = lib.types.enum ["image-build" "activation"];
    default = "image-build";
    internal = true;
    description = ''
      Selects whether the fixed point may construct image artifacts or only
      evaluate configuration against the already-built image.
    '';
  };
}
