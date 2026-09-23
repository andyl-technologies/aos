##! Shared source and locked Rust dependencies for Glycin components.
{
  fetchurl,
  fetchCargoVendor,
}: let
  version = "2.2.1";
  src = fetchurl {
    urls = ["https://download.gnome.org/sources/glycin/2.2/glycin-${version}.tar.xz"];
    hash = "1zpavlb3ig41jxr7ay79gvihndl194cx2i5rkpjya3bcsxqyaylk";
  };
in {
  inherit version src;
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "glycin-${version}-vendor";
    hash = "sha256-juN2dr0zknZIXIQNgxsJHhnR2kn4bDtlyc6P6AwNKOU=";
  };
}
