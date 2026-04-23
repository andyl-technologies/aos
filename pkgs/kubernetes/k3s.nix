##! k3s — Lightweight Kubernetes distribution
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  gnumake,
  go,
}: let
  version = "1.35.1-k3s1";
  srcVersion = "1.35.1+k3s1";
  src = fetchurl {
    urls = [
      "https://github.com/k3s-io/k3s/archive/v${srcVersion}/k3s-${version}.tar.gz"
    ];
    hash = "sha256-DopUJRV2vMGG174kAH0BSF/tXZD15X14YXSvLrTYCNc=";
  };

  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-IgBM6UOEzIAssm2/LPKfWFpgkzN5nC3/lvDH42PsZrQ=";
  };
in
  mkDerivation {
    pname = "k3s";
    inherit version;
    inherit src;

    buildDeps = [
      gnumake
      go
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd k3s-*
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH="${goModules}"
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=1
          export GOPROXY=off
          export GOFLAGS="-mod=readonly"
          mkdir -p "$GOCACHE"

          go build -trimpath \
            -tags "ctrd,no_btrfs" \
            -ldflags "-s -w \
              -X github.com/k3s-io/k3s/pkg/version.Version=v${srcVersion} \
              -X github.com/k3s-io/k3s/pkg/version.GitCommit=v${srcVersion}" \
            -o k3s .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 k3s $out/bin/

          # Symlinks for embedded commands
          for cmd in kubectl crictl ctr; do
            ln -s k3s "$out/bin/$cmd"
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-k3s";
        tool = self;
        command = "k3s --version";
      };
    };

    meta = {
      description = "k3s — lightweight Kubernetes distribution";
      homepage = "https://k3s.io";
      license = "Apache-2.0";
    };
  }
