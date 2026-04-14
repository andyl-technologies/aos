##! Ignition — first-boot machine provisioning utility
{
  mkDerivation,
  fetchurl,
  go,
  util-linux,
}:
let
  version = "2.25.1";
  modPath = "github.com/coreos/ignition/v2";
in
mkDerivation {
  pname = "ignition";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/coreos/ignition/archive/v${version}/ignition-${version}.tar.gz"
    ];
    hash = "sha256-dPvBvkFjXrf6QTGn1WzUowPvZxcSphujUc2MCWHoAYE=";
  };

  buildDeps = [ go ];
  runtimeDeps = [ util-linux ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd ignition-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        export HOME=$TMPDIR
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export GOFLAGS="-mod=vendor"
        export GOPROXY=off
        export CGO_ENABLED=1
        export CGO_CFLAGS="-I${util-linux}/include"
        export CGO_LDFLAGS="-L${util-linux}/lib"
        mkdir -p "$GOPATH" "$GOCACHE"
      '';
    }
    {
      name = "build";
      script = ''
        ldflags="-s -w -X ${modPath}/internal/version.Raw=v${version}"

        echo "==> Building ignition"
        go build -buildmode=pie -ldflags "$ldflags" \
          -o ignition ./internal

        echo "==> Building ignition-validate"
        go build -ldflags "$ldflags" \
          -o ignition-validate ./validate
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 0755 ignition $out/bin/ignition
        install -m 0755 ignition-validate $out/bin/ignition-validate
      '';
    }
  ];

  meta = {
    description = "Ignition — machine provisioning utility";
    homepage = "https://github.com/coreos/ignition";
    license = "Apache-2.0";
  };
}
