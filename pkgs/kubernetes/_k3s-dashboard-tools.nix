##! Native source-built tools used to compile the Traefik dashboard.
{buildPackages}: let
  # Dashboard assets are architecture-independent. Its compilers execute on
  # the build scheduler, even when Traefik itself targets another machine.
  inherit (buildPackages) mkDerivation fetchurl fetchGoModules fetchCargoVendor;

  esbuild = version: hash: let
    src = fetchurl {
      name = "esbuild-${version}.tar.gz";
      urls = ["https://github.com/evanw/esbuild/archive/refs/tags/v${version}.tar.gz"];
      inherit hash;
    };
    modules = fetchGoModules {
      inherit src;
      hash = "sha256-S2uhvYBwdLq6KEv59RmLqLgosbGxK1A6hMaVu6qnnfI=";
    };
  in
    mkDerivation {
      pname = "k3s-dashboard-esbuild";
      inherit version src;
      buildDeps = [buildPackages.go];
      runtimeDeps = [];
      phases = [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd esbuild-${version}
          '';
        }
        {
          name = "build";
          script = ''
            export GOPATH="${modules}"
            export GOCACHE="$TMPDIR/go-cache"
            export GOPROXY=off
            export GOTOOLCHAIN=local
            export CGO_ENABLED=0
            export GOMAXPROCS="$NIX_BUILD_CORES"
            go build -mod=readonly -p "$NIX_BUILD_CORES" -trimpath \
              -ldflags "-s -w" -o esbuild ./cmd/esbuild
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/licenses/esbuild"
            install -m 0755 esbuild "$out/bin/esbuild"
            cp LICENSE.md "$out/share/licenses/esbuild/"
          '';
        }
      ];
      meta = {
        description = "Source-built esbuild compiler for the K3s dashboard";
        license = "MIT";
      };
    };

  rollupSource = fetchurl {
    name = "rollup-4.52.5.tar.gz";
    urls = ["https://github.com/rollup/rollup/archive/refs/tags/v4.52.5.tar.gz"];
    hash = "sha256-gV6pX1AzFteGJ+r7VcplpJ+JqBXlvrwtq32Lqq2y0lg=";
  };
  rollupModules = fetchCargoVendor {
    src = rollupSource;
    sourceRoot = "rollup-4.52.5/rust";
    hash = "sha256-aVrXX4sxOoo9TLca+yYucVV83WPjMK2MYKu4Uz1ox+4=";
  };
in {
  esbuild_0_21 = esbuild "0.21.5" "sha256-tPg6JTooV1q5vA6EIBE49ik9xlXudCGfZw18+iDiaic=";
  esbuild_0_25 = esbuild "0.25.8" "sha256-0qILJkQmEVSBmEb0Ks/icNJsqne+BUMaOwChEilBpmI=";

  rollup = mkDerivation {
    pname = "k3s-dashboard-rollup-native";
    version = "4.52.5";
    src = rollupSource;
    buildDeps = [
      buildPackages.rust
      buildPackages.cmake
      buildPackages.gnumake
    ];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd rollup-4.52.5/rust
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo-home"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${rollupModules}|g" \
            ${rollupModules}/.cargo/config.toml > .cargo/config.toml
        '';
      }
      {
        name = "build";
        script = ''
          cargo build --frozen --offline --release \
            --jobs "$NIX_BUILD_CORES" --package bindings_napi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib" "$out/share/licenses/rollup"
          install -m 0755 target/release/libbindings_napi.so "$out/lib/rollup.node"
          cp ../LICENSE.md "$out/share/licenses/rollup/"
        '';
      }
    ];
    meta = {
      description = "Source-built Rollup Node API parser for the K3s dashboard";
      license = "MIT";
    };
  };
}
