##! CloudCore — KubeEdge cloud-side component
{
  mkDerivation,
  fetchurl,
  buildPackages,
  kubeedgeSource,
}:
let
  inherit (kubeedgeSource) version src;
in
mkDerivation {
  pname = "cloudcore";
  inherit version;
  inherit src;

  buildDeps = [ buildPackages.go ];
  runtimeDeps = [ ];

  abilities = ./_cloudcore-config/module.nix;

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd kubeedge-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=0
        export GOPROXY=off
        if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
          export GOOS="$AOS_GOOS"
          export GOARCH="$AOS_GOARCH"
        fi
        # KubeEdge uses a Go workspace (go.work) but the vendor dir was
        # created from go.mod replace directives. Disable workspace mode
        # so -mod=vendor uses go.mod consistently with vendor/modules.txt.
        export GOWORK=off
        export GOFLAGS="-trimpath -mod=vendor"
        mkdir -p "$GOPATH" "$GOCACHE"

        go build -ldflags "-s -w \
          -X github.com/kubeedge/kubeedge/pkg/version.Version=v${version}" \
          -o cloudcore ./cloud/cmd/cloudcore
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 cloudcore $out/bin/
      '';
    }
  ];

  checks = {
    testing,
    self,
    ...
  }: {
    version = testing.mkToolCheck {
      pname = "tool-cloudcore";
      tool = self;
      command = "cloudcore --help";
    };
  };

  meta = {
    description = "CloudCore — KubeEdge cloud-side component";
    homepage = "https://kubeedge.io";
    license = "Apache-2.0";
  };
}
