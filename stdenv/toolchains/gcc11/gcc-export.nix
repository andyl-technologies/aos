##! Builds the public compiler against this tier's installed kernel headers.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  isRiscv = hostPlatform.constraints.cpu == "riscv64";
in
  import ./gcc.nix {
    inherit prev buildPlatform hostPlatform targetPlatform;
    # The completed Linux 5.14 package installs header directories at its root.
    linuxHeadersInclude = toString prev.linuxHeaders;
    # Reuse the completed construction compiler without changing its outputs.
    buildCxxRuntime =
      if isRiscv
      then prev.gcc.passthru.constructionCompiler
      else null;
    installRuntimeLibraryLink = isRiscv;
  }
