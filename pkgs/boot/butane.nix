{ mkGoPackage, fetchurl }:

let
  version = "0.21.0";
in
mkGoPackage {
  pname = "butane";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/coreos/butane/archive/v${version}/butane-${version}.tar.gz"
    ];
    hash = "sha256-RMH/E8AbTdirgxD9RwPD5+xBGxWSXOy0NK1fWV+dF9Y=";
  };

  goPackage = "./internal";
  goOutput = "butane";
  ldflags = "-s -w -X github.com/coreos/butane/internal/version.Raw=v${version}";
  doCheck = false;

  meta = {
    description = "Butane — human-readable config transpiler for Ignition";
    homepage = "https://github.com/coreos/butane";
    license = "Apache-2.0";
  };
}
