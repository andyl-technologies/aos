##! Shared Linux kernel source — used by linux and linux-headers
{
  fetchurl,
  mkManualUpstream,
}: let
  version = "6.18.33";
  upstream = mkManualUpstream {
    unitId = "linux-6.18";
    family = "linux";
    stream = "6.18";
    owner = "pkgs/kernel/_source.nix";
    member = "linux";
    inherit version;
    upstreamId = "v6.18.33";
    reason = "Kernel updates require config, ABI, module, boot, and all-target maintainer review.";
    riskFloor = "critical";
  };
in {
  inherit version;
  inherit (upstream) updateFor;
  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz"
      # Independent full kernel.org mirror as a fallback for flaky
      # CDN edges. Must be one that retains the full v6.x history:
      # csclub.uwaterloo.ca pruned older releases and began
      # returning 404 for pinned tarballs.
      "https://mirror.math.princeton.edu/pub/kernel/linux/kernel/v6.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-bxb/MCWZ9v40dCiQMizwd1cDEF+9h2dEloL8pq8Pt4I=";
  };
}
