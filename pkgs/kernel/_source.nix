##! Shared Linux kernel source — used by linux and linux-headers
{fetchurl}: let
  version = "6.18.33";
in {
  inherit version;
  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-bxb/MCWZ9v40dCiQMizwd1cDEF+9h2dEloL8pq8Pt4I=";
  };
}
