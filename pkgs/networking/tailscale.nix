##! tailscale — Mesh VPN client and coordination daemon
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  go,
  getent,
  iproute2,
  iptables,
  procps-ng,
}: let
  # Newer releases require a Go patch release newer than the self-hosted AOS
  # compiler. Keep the newest release whose declared toolchain floor is met.
  version = "1.94.2";
  src = fetchurl {
    urls = ["https://github.com/tailscale/tailscale/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-xFl1vrTLe6uAR8+6d+yLFwVw0YTzyAYliETz5Jxg16o=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-rIJP7coRNy0as/KaQPI98f60w59+nNkpjARArGll+Y0=";
  };
in
  mkDerivation {
    pname = "tailscale";
    inherit version src;

    buildDeps = [go];
    runtimeDeps = [getent iproute2 iptables procps-ng];
    propagatedDeps = [];
    disallowedReferences = [go goModules];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd tailscale-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export GOPATH="${goModules}"
          export GOCACHE="$TMPDIR/go-cache"
          export GOFLAGS="-trimpath -mod=readonly"
          export GOPROXY=off
          export CGO_ENABLED=0
          mkdir -p "$GOCACHE"
        '';
      }
      {
        name = "build";
        script = ''
          versionFlags="-s -w -X tailscale.com/version.longStamp=${version} -X tailscale.com/version.shortStamp=${version}"
          go build -tags ts_include_cli -ldflags "$versionFlags" -o tailscaled ./cmd/tailscaled
          go build -ldflags "$versionFlags" -o derper ./cmd/derper
          go build -ldflags "$versionFlags" -o derpprobe ./cmd/derpprobe
          go build -ldflags "$versionFlags" -o get-authkey ./cmd/get-authkey
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 755 tailscaled derper derpprobe get-authkey "$out/bin/"
          ln -s tailscaled "$out/bin/tailscale"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tailscale";
        tool = self;
        command = "tailscale version && tailscaled --version && derper --help >/dev/null";
      };
    };

    meta = {
      description = "Mesh VPN client, daemon, and DERP relay";
      homepage = "https://tailscale.com/";
      license = "BSD-3-Clause";
      mainProgram = "tailscale";
    };
  }
