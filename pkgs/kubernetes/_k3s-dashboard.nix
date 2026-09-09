##! Builds Traefik's complete static dashboard with source-built native tools.
{
  buildPackages,
  src,
  version,
}: let
  inherit (buildPackages) mkDerivation;
  tools = import ./_k3s-dashboard-tools.nix {inherit buildPackages;};

  # The imported lock is retained separately from upstream's Yarn lock. It
  # freezes pnpm's peer resolution and is never regenerated during a build.
  nodeSources = mkDerivation {
    pname = "k3s-traefik-node-sources";
    inherit version src;
    buildDeps = [
      buildPackages.pnpm
      buildPackages.nodejs
      buildPackages.python3
      buildPackages.ca-certificates
    ];
    runtimeDeps = [];
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-d6m9n6mxZaol5ZS62JsuyztZDTKG7tJriTmMaWe+R+o=";
    phases = [
      {
        name = "fetch";
        script = ''
          export SSL_CERT_FILE="${buildPackages.ca-certificates}/etc/ssl/certs/ca-certificates.crt"
          mkdir project
          cd project
          tar xOf "$src" traefik-${version}/webui/package.json > package.json
          cp ${./_k3s-dashboard/pnpm-lock.yaml} pnpm-lock.yaml
          pnpm --pm-on-fail=ignore --store-dir "$TMPDIR/pnpm-store" \
            --state-dir "$TMPDIR/pnpm-state" install --ignore-scripts \
            --ignore-pnpmfile --frozen-lockfile

          mkdir -p "$out"
          cp -a node_modules "$out/"
          python3 ${./_k3s-dashboard/remove-precompiled.py} "$out/node_modules"
          rm -f "$out/node_modules/.modules.yaml"
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "k3s-traefik-dashboard";
    inherit version src;
    buildDeps = [buildPackages.nodejs];
    runtimeDeps = [];
    passthru.evidenceSources = [src nodeSources ./_k3s-dashboard];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd traefik-${version}/webui
          cp -a ${nodeSources}/node_modules .
          chmod -R u+w node_modules
        '';
      }
      {
        name = "configure";
        script = ''
          # Yarn's flat layout exposed this transitive dependency to the app.
          # Match that visibility without changing its locked router version.
          ln -s .pnpm/react-router@6.22.1_react@18.3.1/node_modules/react-router \
            node_modules/react-router

          # Bind each esbuild JS interface to its matching source-built binary.
          # An environment override would select only one of the two versions.
          esbuild_old=node_modules/.pnpm/esbuild@0.21.5/node_modules/esbuild/lib/main.js
          esbuild_new=node_modules/.pnpm/esbuild@0.25.8/node_modules/esbuild/lib/main.js
          grep -F 'var ESBUILD_BINARY_PATH =' "$esbuild_old"
          grep -F 'var ESBUILD_BINARY_PATH =' "$esbuild_new"
          sed -i 's|^var ESBUILD_BINARY_PATH =.*|var ESBUILD_BINARY_PATH = "${tools.esbuild_0_21}/bin/esbuild";|' "$esbuild_old"
          sed -i 's|^var ESBUILD_BINARY_PATH =.*|var ESBUILD_BINARY_PATH = "${tools.esbuild_0_25}/bin/esbuild";|' "$esbuild_new"

          # Rollup prefers a parser beside native.js over a platform npm package.
          node_arch="$(node -p process.arch)"
          cp ${tools.rollup}/lib/rollup.node \
            "node_modules/.pnpm/rollup@4.52.5/node_modules/rollup/dist/rollup.linux-$node_arch-gnu.node"
        '';
      }
      {
        name = "build";
        script = ''
          node node_modules/typescript/bin/tsc --noEmit
          node node_modules/vite/bin/vite.js build
          test -s static/index.html
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -r static/. "$out/"
        '';
      }
    ];
    meta = {
      description = "Traefik dashboard compiled from its pinned application and dependency sources";
      license = "MIT";
    };
  }
