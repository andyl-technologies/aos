##! Garage — S3-compatible distributed object store
##!
##! Pure-Rust, single-binary, embedded storage (LMDB/sqlite via
##! bundled-libs) — which is what makes it the right S3 fixture for AOS
##! tests: `aos`/`apr`'s s3:// cache backend (crates/aos-net/src/
##! protocol/s3.rs) needs a real SigV4 endpoint to be exercised against,
##! and garage provides one with no external services. See the
##! origin-upload-s3 test in pkgs/tools/aos/_tests.nix.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  version = "2.3.0";
  src = fetchurl {
    urls = [
      "https://git.deuxfleurs.fr/Deuxfleurs/garage/archive/v${version}.tar.gz"
    ];
    hash = "sha256-uDqYFndnazVAC7uvIJdMOW8y2jHHx2MM5V/D5iwOLgE=";
  };
in
  mkCargoPackage {
    pname = "garage";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-EzUMASYQl7/W3cnfYTbwEazNnhZUtdIALfztWk3Qvb8=";
    };

    # Build only the garage binary from the workspace. The default
    # features bundle the sqlite and LMDB C sources, so no system
    # libraries are needed beyond the stdenv C compiler.
    cargoFlags = "-p garage";
    doCheck = false;

    meta = {
      description = "Garage — S3-compatible distributed object storage service";
      homepage = "https://garagehq.deuxfleurs.fr";
      license = "AGPL-3.0";
    };
  }
