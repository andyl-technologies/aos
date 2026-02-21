# lib/platform.nix — Structured platform description
#
# Converts a Nix system string (e.g. "x86_64-linux") into a rich record
# with GNU triple, architecture flags, dynamic linker path, etc.
#
# Supports: x86_64-linux, aarch64-linux, i686-linux
#
# Three-platform model:
#   buildPlatform  — where the builder runs (Nix scheduling)
#   hostPlatform   — where the output binary runs
#   targetPlatform — what code a compiler generates (compilers only)
#
# For native builds all three are identical. Cross-compilation decouples them.
{
  mkPlatform = system: let
    parts = builtins.match "([a-z0-9_]+)-([a-z]+)" system;
    cpuName =
      if parts != null
      then builtins.elemAt parts 0
      else throw "platform: cannot parse system '${system}'";
    kernelName =
      if parts != null
      then builtins.elemAt parts 1
      else throw "platform: cannot parse system '${system}'";
  in
    if kernelName != "linux"
    then throw "platform: unsupported kernel '${kernelName}' (only linux)"
    else if cpuName == "x86_64"
    then {
      inherit system;
      config = "x86_64-unknown-linux-gnu";
      isx86_64 = true;
      isAarch64 = false;
      isi686 = false;
      is32bit = false;
      is64bit = true;
      isLinux = true;
      linuxArch = "x86_64";
      dynamicLinker = "ld-linux-x86-64.so.2";
      parsed = {
        cpu = {
          name = "x86_64";
          bits = 64;
        };
        vendor = "unknown";
        kernel = {
          name = "linux";
        };
        abi = {
          name = "gnu";
        };
      };
    }
    else if cpuName == "aarch64"
    then {
      inherit system;
      config = "aarch64-unknown-linux-gnu";
      isx86_64 = false;
      isAarch64 = true;
      isi686 = false;
      is32bit = false;
      is64bit = true;
      isLinux = true;
      linuxArch = "arm64";
      dynamicLinker = "ld-linux-aarch64.so.1";
      parsed = {
        cpu = {
          name = "aarch64";
          bits = 64;
        };
        vendor = "unknown";
        kernel = {
          name = "linux";
        };
        abi = {
          name = "gnu";
        };
      };
    }
    else if cpuName == "i686"
    then {
      inherit system;
      config = "i686-unknown-linux-gnu";
      isx86_64 = false;
      isAarch64 = false;
      isi686 = true;
      is32bit = true;
      is64bit = false;
      isLinux = true;
      linuxArch = "x86";
      dynamicLinker = "ld-linux.so.2";
      parsed = {
        cpu = {
          name = "i686";
          bits = 32;
        };
        vendor = "unknown";
        kernel = {
          name = "linux";
        };
        abi = {
          name = "gnu";
        };
      };
    }
    else throw "platform: unsupported CPU '${cpuName}'";
}
