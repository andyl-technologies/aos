##! Shared Linux kernel source — used by linux and linux-headers
{ fetchurl }:
let
  version = "6.18.12";
in
{
  inherit version;
  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-4AMpStTCwqxbt3+7gllRETT1HZh7MhJRaDLcSwyD8eo=";
  };
}
