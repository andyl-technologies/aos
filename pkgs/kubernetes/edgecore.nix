##! EdgeCore — KubeEdge edge-side agent
{
  mkDerivation,
  fetchurl,
  go,
  kubeedgeSource,
}: let
  inherit (kubeedgeSource) version src;
in
  mkDerivation {
    pname = "edgecore";
    inherit version;
    inherit src;

    buildDeps = [go];
    runtimeDeps = [];

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
          # KubeEdge uses a Go workspace (go.work) but the vendor dir was
          # created from go.mod replace directives. Disable workspace mode
          # so -mod=vendor uses go.mod consistently with vendor/modules.txt.
          export GOWORK=off
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w \
            -X github.com/kubeedge/kubeedge/pkg/version.Version=v${version}" \
            -o edgecore ./edge/cmd/edgecore
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 edgecore $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-edgecore";
        tool = self;
        command = "edgecore --help";
      };
    };

    meta = {
      description = "EdgeCore — KubeEdge edge-side agent";
      homepage = "https://kubeedge.io";
      license = "Apache-2.0";
    };
  }
