##! Longhorn Manager — Longhorn orchestration controller
{
  mkDerivation,
  fetchurl,
  go,
}:
let
  version = "1.8.1";
in
mkDerivation {
  pname = "longhorn-manager";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/longhorn/longhorn-manager/archive/v${version}/longhorn-manager-${version}.tar.gz"
    ];
    hash = "sha256-dZLMYwijkUDyxKh8wVoHIrCvVkuzHnOYgakF012u3Tc=";
  };

  buildDeps = [ go ];
  runtimeDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd longhorn-manager-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=0
        export GOPROXY=off
        export GOFLAGS="-trimpath -mod=vendor"
        mkdir -p "$GOPATH" "$GOCACHE"

        go build -ldflags "-s -w -X main.Version=${version}" \
          -o longhorn-manager .
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 longhorn-manager $out/bin/
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-manager";
        tool = self;
        command = "longhorn-manager version";
      };
    };

  meta = {
    description = "Longhorn Manager — distributed block storage orchestrator";
    homepage = "https://longhorn.io";
    license = "Apache-2.0";
  };
}
