##! Keeps the image-baked fleet control channel as its only agent owner.
{
  lib,
  options,
  ...
}: {
  config = lib.mkIf ((options.aos-test-agent.enable or null) != null) {
    aos-test-agent.enable = false;
  };
}
