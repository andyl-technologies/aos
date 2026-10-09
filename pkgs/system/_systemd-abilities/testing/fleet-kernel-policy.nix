##! Matches direct-kernel image policy across both authenticated boot scopes.
{
  lib,
  options,
  ...
}: {
  # Partial contract fixtures may omit the optional verification schema.
  # Direct-kernel boots supply no root hash; image boots omit this fragment.
  config = lib.mkMerge [
    (lib.optionalAttrs (options.aos.security or {} ? verity) {
      aos.security.verity.enable = lib.mkForce false;
    })
  ];
}
