##! Builds K3s's Traefik release, including its complete embedded dashboard.
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
}: let
  version = "3.7.13";
  src = fetchurl {
    name = "traefik-v${version}.tar.gz";
    urls = ["https://github.com/traefik/traefik/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-wc/1kmF0De86OT6ixNfH0BhOuOs5yIQCsm6zs+RzW5Y=";
  };
  modules = fetchGoModules {
    inherit src;
    name = "k3s-traefik-go-modules";
    hash = "sha256-iGtGGy3jsM5KnoWK097xcsBd1GhxuhseytW/bjeyy7w=";
  };
  dashboard = import ./_k3s-dashboard.nix {
    inherit src version buildPackages;
  };
in
  mkDerivation {
    pname = "k3s-traefik";
    inherit version src;
    buildDeps = [buildPackages.go];
    runtimeDeps = [];
    passthru.evidenceSources = [src modules] ++ dashboard.passthru.evidenceSources;
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd traefik-${version}
          mkdir -p webui/static
          cp -r ${dashboard}/. webui/static/
          test -s webui/static/index.html
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH="${modules}"
          if [ -n "''${AOS_SHARED_BUILD_CACHE:-}" ]; then export GOCACHE=/aos-build-cache/go; else export GOCACHE="$TMPDIR/go-cache"; fi
          export GOPROXY=off
          export GOTOOLCHAIN=local
          export CGO_ENABLED=0
          export GOMAXPROCS="$NIX_BUILD_CORES"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          go build -mod=readonly -p "$NIX_BUILD_CORES" -trimpath \
            -ldflags "-s -w -X github.com/traefik/traefik/v3/pkg/version.Version=${version}" \
            -o traefik ./cmd/traefik
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/licenses/traefik"
          install -m 0755 traefik "$out/bin/traefik"
          cp LICENSE.md "$out/share/licenses/traefik/"
        '';
      }
    ];
    meta = {
      description = "Traefik ingress proxy and dashboard for K3s";
      homepage = "https://traefik.io/traefik/";
      license = "MIT";
    };
  }
