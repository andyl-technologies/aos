##! uutils hostname — Rust hostname utility.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.0.1";
  revision = "f92ca23956382e6a2d29e241a235ad6559687a5c";
  src = fetchurl {
    urls = ["https://github.com/uutils/hostname/archive/${revision}.tar.gz"];
    hash = "sha256-0KasoiI8tZYeCm+LSd0IJQW24JefUyDlrPnnouxVJfk=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-KukXPO1EfajAz0bqAW1U1huT8mrm1e0CB82fjKPEjOI=";
  };
in
  mkCargoPackage {
    pname = "uutils-hostname";
    inherit version src cargoDeps;

    cargoFlags = "--bin hostname";
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-hostname";
        tool = self;
        command = ''
          name=$(${self}/bin/hostname)
          test -n "$name"
          printf 'hostname-read\n'
        '';
        expectedOutput = "hostname-read";
      };
    };

    meta = {
      description = "Rust hostname utility";
      homepage = "https://github.com/uutils/hostname";
      license = "MIT";
      mainProgram = "hostname";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
