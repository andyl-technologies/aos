##! Hubble — Cilium observability CLI
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.17.3";
in
  mkDerivation {
    pname = "hubble";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/cilium/hubble/archive/v${version}/hubble-${version}.tar.gz"
      ];
      hash = "sha256-ea/dd7K5QGu2zdkMClmQ/f6UV8CIN69Finu3cXtY1WA=";
    };

    # Use the Linux-hosted compiler when producing Darwin commands.  The
    # target Go distribution is a Mach-O runtime artifact and cannot execute
    # during this build.
    buildDeps = [buildPackages.go];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd hubble-${version}
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
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w \
            -X github.com/cilium/hubble/pkg/version.Version=v${version}" \
            -o hubble .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 hubble $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-hubble";
        tool = self;
        command = "hubble version";
      };
    };

    meta = {
      description = "Hubble — Cilium network observability CLI";
      homepage = "https://github.com/cilium/hubble";
      license = "Apache-2.0";
    };
  }
