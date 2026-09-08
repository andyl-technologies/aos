##! sccache — Shared compilation cache
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  openssl,
}: let
  version = "0.17.0";
  src = fetchurl {
    urls = ["https://github.com/mozilla/sccache/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-SZSa0c8XXEnaEm27DC5qVr2dH2JujMC+F7lmi5FBRcY=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    # sccache 0.17 predates rust-openssl's OpenSSL 4 support.
    cargoPatches = [./sccache-openssl-4.patch];
    hash = "sha256-lnfGDjnTLI4YU2qm5a26ardulbGTIlcfWzk2R9ajg5w=";
  };
in
  mkCargoPackage {
    pname = "sccache";
    inherit version src cargoDeps;
    # Keep the build lockfile aligned with the vendored dependency set.
    patches = [./sccache-openssl-4.patch];

    buildDeps = [pkg-config];
    runtimeDeps = [openssl];
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-sccache";
        tool = self;
        command = "sccache --version";
      };
    };
    meta = {
      description = "Compiler cache with local and remote storage support";
      homepage = "https://github.com/mozilla/sccache";
      license = "Apache-2.0";
      mainProgram = "sccache";
    };
  }
