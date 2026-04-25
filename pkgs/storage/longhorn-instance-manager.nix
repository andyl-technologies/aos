##! Longhorn Instance Manager — Engine and replica process manager
{
  mkDerivation,
  fetchurl,
  go,
  zlib,
  libqcow,
}: let
  version = "1.8.1";
in
  mkDerivation {
    pname = "longhorn-instance-manager";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/longhorn/longhorn-instance-manager/archive/v${version}/longhorn-instance-manager-${version}.tar.gz"
      ];
      hash = "sha256-DA/MwHcPNtWrySn2ZaWbWmKc/MspHsZxrAAuUPqmYpA=";
    };

    buildDeps = [go];
    runtimeDeps = [zlib libqcow];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd longhorn-instance-manager-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=1
          export GOPROXY=off
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w -X main.Version=${version}" \
            -o longhorn-instance-manager .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 longhorn-instance-manager $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-instance-manager";
        tool = self;
        command = "longhorn-instance-manager version";
      };
    };

    meta = {
      description = "Longhorn Instance Manager — engine and replica process manager";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
