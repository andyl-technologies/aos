##! Cargo C source archive combined with its upstream release lockfile.
{
  mkDerivation,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.10.25";
  archive = fetchurl {
    urls = ["https://github.com/lu-zero/cargo-c/archive/refs/tags/v${version}.tar.gz"];
    hash = "1pm52vccaqdkaa0naayrsl86asyx0s23ch1ynvkmjhmnx0mb2m40";
  };
  lockfile = fetchurl {
    urls = ["https://github.com/lu-zero/cargo-c/releases/download/v${version}/Cargo.lock"];
    hash = "0dmyia682zxv52gafb9kk91kz5vn8ggsjhi8aigwc459canrnpca";
  };
  prepared = mkDerivation {
    pname = "cargo-c-locked-source";
    inherit version;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "prepare";
        script = ''
          tar xf ${archive}
          cp ${lockfile} cargo-c-${version}/Cargo.lock
          mkdir -p "$out"
          tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
            -cf "$out/source.tar" cargo-c-${version}
        '';
      }
    ];
  };
  src = "${prepared}/source.tar";
in {
  inherit version src archive lockfile;
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "cargo-c-${version}-vendor";
    hash = "sha256-NWpOUNrYPHqyudHKNtL3W4+zHTW9kZ/dCvh74pOQZDA=";
  };
}
