##! Builds the public compiler against this tier's installed kernel headers.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
import ./gcc.nix {
  inherit prev buildPlatform hostPlatform targetPlatform;
  # The completed Linux 5.14 package installs header directories at its root.
  linuxHeadersInclude = toString prev.linuxHeaders;
}
