##! Pinned librsvg source and locked Rust dependencies.
{
  fetchurl,
  fetchCargoVendor,
}: let
  version = "2.62.91";
  src = fetchurl {
    urls = ["https://download.gnome.org/sources/librsvg/2.62/librsvg-${version}.tar.xz"];
    hash = "0l5jl358zvqdzakqfl8jd9qxljpykgc6yhs9xkw8ipa0kl9axbkc";
  };
in {
  inherit version src;
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "librsvg-${version}-vendor";
    hash = "sha256-2lET93Su+6Ib/vA7eVRBB1rJt2GyFtdm6rueCrnf5c0=";
  };
}
