##! Longhorn Manager — Longhorn orchestration controller
{
  mkDerivation,
  fetchurl,
  buildPackages,
  longhorn-engine,
  longhorn-instance-manager,
}: let
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

    buildDeps = [buildPackages.go];
    # The signed add-on resource bundle refers to these payloads as its
    # authenticated runtime companions. Keep them in the package closure so
    # publication, installation, rollback, and GC retain one complete add-on.
    runtimeDeps = [longhorn-engine longhorn-instance-manager];
    abilities = ./_longhorn-config/module.nix;

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
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-manager";
        tool = self;
        command = "longhorn-manager --help";
      };
    };

    meta = {
      description = "Longhorn Manager — distributed block storage orchestrator";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
