##! Shared Linux kernel source — used by linux and linux-headers
{
  fetchurl,
  mkManualUpstream,
}: let
  version = "7.2.3";
  upstream = mkManualUpstream {
    unitId = "linux-7.2";
    family = "linux";
    stream = "7.2";
    owner = "pkgs/kernel/_source.nix";
    member = "linux";
    inherit version;
    upstreamId = "v7.2.3";
    reason = "Kernel updates require config, ABI, module, boot, and all-target maintainer review.";
    riskFloor = "critical";
  };
in {
  inherit version;
  inherit (upstream) updateFor;
  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${version}.tar.xz"
      # Independent full kernel.org mirror as a fallback for flaky
      # CDN edges. Must be one that retains the full v7.x history:
      # csclub.uwaterloo.ca pruned older releases and began
      # returning 404 for pinned tarballs.
      "https://mirror.math.princeton.edu/pub/kernel/linux/kernel/v7.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-i6JZ6OexPsbvCUHIo5rZCyS9Sk1sABC6a6+3lFUOzQM=";
  };
}
