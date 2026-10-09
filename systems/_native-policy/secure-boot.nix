##! Authored native policy for the Secure Boot server fixture.
{
  config,
  lib,
  options,
  ...
}: {
  # Server services belong to the host scope; initrd retains only boot policy.
  config = lib.mkMerge [
    {aos.boot.secureBoot.enable = true;}
    (lib.optionalAttrs (options.aos.roles or {} ? server) {
      aos.roles.server.enable = lib.mkIf ((config.aos.boot.stage or "host") == "host") true;
    })
  ];
}
