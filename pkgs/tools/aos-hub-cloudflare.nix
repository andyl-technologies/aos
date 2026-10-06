##! aos-hub-cloudflare — the hub binary packaged as a self-contained
##! Cloudflare installer.
##!
##! The base `aos-hub` is a lean server binary; its `cloudflare`
##! command group (provision / deploy / install / init) needs two extra runtime
##! assets that this wrapper layers on:
##!
##! - the **prebuilt Worker wasm dist** (`shim.mjs` + `index.wasm` plus the
##!   `assets/` static bundle from `aos-hub-worker-dist`) — the payload
##!   `wrangler deploy` uploads, copied into `$out/share/aos-hub/worker/`;
##! - the **`wrangler` CLI** (from `pkgs.miniflare`, 4.x) + its `node` runtime.
##!
##! The wrapper sets `AOS_HUB_WORKER_DIST` / `AOS_HUB_WRANGLER` (read by
##! `aos_hub::cloudflare::Assets::from_env`) and prepends `node` to
##! `PATH`, then `exec`s the real binary. The result is "self-contained" in the
##! Nix sense: one closure (`nix copy` it and it runs anywhere there is a
##! `/nix/store`), with `wrangler` + `node` + the wasm payload all reachable. For
##! a truly portable single file on a non-Nix host, `nix bundle` this derivation.
##!
##! Operator Cloudflare credentials are not baked in: `wrangler` reads
##! `CLOUDFLARE_API_TOKEN` (or an OAuth login) from the caller's environment.
{
  mkDerivation,
  aos-hub,
  aos-hub-worker-dist,
  miniflare,
  nodejs,
  python3,
  bash,
  observationTools ? null,
}:
assert observationTools == null || observationTools.selectedNativeArtifact == toString aos-hub;
assert observationTools == null || observationTools.selectedWorkerArtifact == toString aos-hub-worker-dist;
  mkDerivation {
    pname = "aos-hub-cloudflare";
    version = "0.1.0";

    # The wrapper bakes these store paths into the launcher and `exec`s/reads them
    # at runtime, so they must survive the scrub phase (which nukes any store ref
    # not reachable from a declared output / runtime / propagated dep). The wasm
    # dist is copied into `$out` itself, so it needs no runtime ref.
    runtimeDeps =
      [aos-hub miniflare nodejs python3 bash]
      ++ (
        if observationTools == null
        then []
        else [observationTools]
      );

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos-hub/worker"
          cp ${aos-hub-worker-dist}/shim.mjs ${aos-hub-worker-dist}/index.wasm \
            "$out/share/aos-hub/worker/"
          cp ${./aos-hub-direct-sdk-conformance.mjs} \
            "$out/share/aos-hub/direct-sdk-conformance.mjs"
          cp ${./aos-hub-direct-qualification.mjs} \
            "$out/share/aos-hub/direct-qualification.mjs"
          cp ${./aos-hub-hosted-workload.py} "$out/share/aos-hub/hosted-workload.py"
          mkdir -p "$out/share/aos-hub/hosted-capture"
          cp ${./aos-hub-hosted-capture/capture.mjs} \
            ${./aos-hub-hosted-capture/sink.mjs} \
            ${./aos-hub-hosted-capture/baseline-proxy.mjs} \
            ${./aos-hub-hosted-capture/origin-capture.mjs} \
            ${./aos-hub-hosted-capture/storage-shim.mjs} \
            ${./aos-hub-hosted-capture/render.py} \
            "$out/share/aos-hub/hosted-capture/"
          # Measure the selected source-built dependency; the renderer also checks
          # its canonical immutable executable and exact hash before validation.
          ${python3}/bin/python3 -B -E - "$out/share/aos-hub/hosted-capture/node-tool.json" <<'PYTHON'
          import hashlib
          import json
          import pathlib
          import sys

          node = pathlib.Path("${nodejs}/bin/node").resolve(strict=True)
          digest = hashlib.sha256()
          with node.open("rb") as executable:
              for chunk in iter(lambda: executable.read(1024 * 1024), b""):
                  digest.update(chunk)
          with open(sys.argv[1], "x") as output:
              json.dump({"file": str(node), "sha256": digest.hexdigest()}, output)
              output.write("\n")
          PYTHON
          mkdir -p "$out/share/aos-hub/hosted-measurements"
          cp ${../../tests/fleet/_hub-direct-publisher.py} \
            ${../../tests/fleet/_hub-direct-sparse-publisher.py} \
            ${../../tests/fleet/_hub-perf.py} \
            ${../../tests/fleet/_hub-direct-runtime-observations.py} \
            ${../../tests/fleet/_hub-direct-observations.py} \
            "$out/share/aos-hub/hosted-measurements/"
          # The static-asset bundle Cloudflare serves from its CDN edge (the
          # `[assets]` directory the generated wrangler.toml points at). Copied
          # writable so `wrangler deploy`'s asset manifest pass can stat it.
          cp -r ${aos-hub-worker-dist}/assets "$out/share/aos-hub/worker/assets"
          chmod -R u+w "$out/share/aos-hub/worker/assets"

          # Hand-rolled wrapper (AOS has no nixpkgs makeWrapper). The unquoted
          # heredoc bakes the literal `$out` store path and the Nix-interpolated
          # tool paths; `\$@`/`\$PATH` stay literal for runtime expansion.
          cat > "$out/bin/aos-hub" <<EOF
          #!${bash}/bin/bash
          export AOS_HUB_WORKER_DIST="$out/share/aos-hub/worker"
          export AOS_HUB_WRANGLER="${miniflare}/bin/wrangler"
          export PATH="${nodejs}/bin:\$PATH"
          exec ${aos-hub}/bin/aos-hub "\$@"
          EOF
          chmod +x "$out/bin/aos-hub"
          ln -s ${aos-hub}/bin/aos-hub-direct-review "$out/bin/aos-hub-direct-review"
          ln -s ${aos-hub}/bin/aos-hub-provider-conformance "$out/bin/aos-hub-provider-conformance"

          ${
            if observationTools == null
            then ""
            else ''
              # Explicit helper selection pins the actual Native and Worker tuple.
              # Linking tools installs no capture, producer flag or acceptance.
              ln -s ${observationTools}/bin/aos-native-body-observer "$out/bin/aos-native-body-observer"
              ln -s ${observationTools}/bin/aos-native-body-auth "$out/bin/aos-native-body-auth"
              ln -s ${observationTools}/bin/aos-hosted-byte-assessment "$out/bin/aos-hosted-byte-assessment"
              ln -s ${observationTools}/bin/aos-observation-private-wrapper "$out/bin/aos-observation-private-wrapper"
            ''
          }

          cat > "$out/bin/aos-hub-direct-sdk-conformance" <<EOF
          #!${bash}/bin/bash
          exec ${nodejs}/bin/node "$out/share/aos-hub/direct-sdk-conformance.mjs" "\$@"
          EOF
          chmod +x "$out/bin/aos-hub-direct-sdk-conformance"
          cat > "$out/bin/aos-hub-direct-qualification" <<EOF
          #!${bash}/bin/bash
          exec ${nodejs}/bin/node "$out/share/aos-hub/direct-qualification.mjs" "\$@"
          EOF
          chmod +x "$out/bin/aos-hub-direct-qualification"
          cat > "$out/bin/aos-hub-hosted-workload" <<EOF
          #!${bash}/bin/bash
          exec ${python3}/bin/python3 "$out/share/aos-hub/hosted-workload.py" "\$@" \
            --library-dir "$out/share/aos-hub/hosted-measurements"
          EOF
          chmod +x "$out/bin/aos-hub-hosted-workload"
          cat > "$out/bin/aos-hub-hosted-capture-render" <<EOF
          #!${bash}/bin/bash
          if [ "\$#" -ne 1 ]; then
            printf '%s\n' 'usage: aos-hub-hosted-capture-render SELECTION.json' >&2
            exit 2
          fi
          exec ${python3}/bin/python3 -B -E "$out/share/aos-hub/hosted-capture/render.py" \
            --selection "\$1" --node-tool-file "$out/share/aos-hub/hosted-capture/node-tool.json"
          EOF
          chmod +x "$out/bin/aos-hub-hosted-capture-render"
        '';
      }
    ];

    passthru.evidenceSources = [
      ./aos-hub-cloudflare.nix
      ./aos-hub-direct-sdk-conformance.mjs
      ./aos-hub-direct-qualification.mjs
      ./aos-hub-hosted-workload.py
      ./aos-hub-hosted-capture/capture.mjs
      ./aos-hub-hosted-capture/sink.mjs
      ./aos-hub-hosted-capture/baseline-proxy.mjs
      ./aos-hub-hosted-capture/origin-capture.mjs
      ./aos-hub-hosted-capture/storage-shim.mjs
      ./aos-hub-hosted-capture/render.py
      ../../tests/fleet/_hub-direct-publisher.py
      ../../tests/fleet/_hub-direct-sparse-publisher.py
      ../../tests/fleet/_hub-perf.py
      ../../tests/fleet/_hub-direct-runtime-observations.py
      ../../tests/fleet/_hub-direct-observations.py
    ];

    meta = {
      description = "aos-hub packaged with wrangler + the Worker wasm dist as a Cloudflare installer";
      homepage = "https://github.com/andyl-technologies/aos";
      license = "MIT";
    };
  }
