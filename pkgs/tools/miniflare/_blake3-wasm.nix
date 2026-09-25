##! Wrangler BLAKE3 WebAssembly generated from the upstream Rust source.
##! The upstream tag has no Cargo workspace lockfile. The checked-in patch adds
##! one generated with AOS Cargo and pins wasm-bindgen to our matching CLI.
{buildPackages}: let
  version = "2.1.5";
  src = buildPackages.fetchurl {
    urls = [
      "https://github.com/connor4312/blake3/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-Wkq0D73eO01Xmufkf9WeuBcZl7l98moOLsXKGJ36x8g=";
  };
  workspacePatch = ./blake3-wasm-workspace.patch;
  cargoDeps = buildPackages.fetchCargoDeps {
    inherit src;
    cargoPatches = [workspacePatch];
    hash = "sha256-Km5xWhP8n6dRlF8TxlmvHSOpGoPwwIjhp3/b6ipQkXY=";
  };
in
  buildPackages.mkCargoPackage {
    pname = "blake3-wasm";
    inherit version src cargoDeps;

    patches = [workspacePatch];
    cargoFlags = "-p blake3-js --target wasm32-unknown-unknown";
    # WASM debug names otherwise retain the fixed-output vendor store path.
    RUSTFLAGS = "--remap-path-prefix=${cargoDeps}=vendor";
    buildDeps = [
      buildPackages.wasm-bindgen-cli
      buildPackages.esbuild
      buildPackages.nodejs
      buildPackages.findutils
      buildPackages.tar
      buildPackages.gzip
    ];
    installBins = false;
    doCheck = false;

    postInstall = ''
      wasm=target/wasm32-unknown-unknown/release/blake3_js.wasm
      test -f "$wasm"

      package="$out/package"
      mkdir -p "$package/dist/wasm" "$package/esm"

      # Keep the generated modules free of build-time store references.
      wasm-bindgen --remove-name-section --target nodejs --out-dir "$package/dist/wasm/nodejs" "$wasm"
      wasm-bindgen --remove-name-section --target bundler --out-dir "$package/dist/wasm/browser" "$wasm"
      wasm-bindgen --remove-name-section --target web --out-dir "$package/dist/wasm/web" "$wasm"

      sources=$(find ts -type f -name '*.ts' ! -name '*.test.ts' ! -name '*.d.ts')
      esbuild $sources --outbase=ts --outdir="$package/dist" --format=cjs --platform=node
      esbuild $sources --outbase=ts --outdir="$package/esm" --format=esm --platform=browser

      cp browser-async.js LICENSE readme.md "$package/"

      cat > "$package/browser.js" <<'JS'
      import { provideWasm } from './esm/browser/wasm.js';
      import * as wasm from './dist/wasm/browser/blake3_js.js';

      provideWasm(wasm);

      export * from './esm/browser/index.js';
      JS

      # esbuild preserves relative imports when transpiling each module. Add
      # extensions for native browser ESM resolution, as upstream's build does.
      node - "$package" <<'JS'
      const fs = require("node:fs");
      const path = require("node:path");
      const root = process.argv[2];

      function rewrite(file) {
        const source = fs.readFileSync(file, "utf8");
        const updated = source.replace(
          /((?:from|import)\s+["'])(\.\.?\/[^"']+)(["'])/g,
          (match, prefix, target, suffix) =>
            target.endsWith(".js") ? match : prefix + target + ".js" + suffix,
        );
        fs.writeFileSync(file, updated);
      }

      function walk(directory) {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
          const child = path.join(directory, entry.name);
          if (entry.isDirectory()) walk(child);
          else if (entry.name.endsWith(".js")) rewrite(child);
        }
      }

      walk(path.join(root, "esm"));
      rewrite(path.join(root, "browser-async.js"));
      JS

      cat > "$package/package.json" <<'JSON'
      {
        "name": "blake3-wasm",
        "version": "2.1.5",
        "main": "dist/index.js",
        "module": "esm/index.js",
        "browser": "browser.js",
        "license": "MIT"
      }
      JSON

      tar -C "$out" --sort=name --mtime='@0' --owner=0 --group=0 \
        --numeric-owner -cf - package | gzip -n > "$out/blake3-wasm-${version}.tgz"
    '';

    meta = {
      description = "BLAKE3 WebAssembly for Wrangler built from Rust sources";
      homepage = "https://github.com/connor4312/blake3";
      license = "MIT";
    };
  }
