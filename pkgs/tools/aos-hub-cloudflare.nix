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
  bash,
}:
mkDerivation {
  pname = "aos-hub-cloudflare";
  version = "0.1.0";

  # The wrapper bakes these store paths into the launcher and `exec`s/reads them
  # at runtime, so they must survive the scrub phase (which nukes any store ref
  # not reachable from a declared output / runtime / propagated dep). The wasm
  # dist is copied into `$out` itself, so it needs no runtime ref.
  runtimeDeps = [aos-hub miniflare nodejs bash];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/share/aos-hub/worker"
        cp ${aos-hub-worker-dist}/shim.mjs ${aos-hub-worker-dist}/index.wasm \
          "$out/share/aos-hub/worker/"
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
      '';
    }
  ];

  meta = {
    description = "aos-hub packaged with wrangler + the Worker wasm dist as a Cloudflare installer";
    homepage = "https://github.com/andyl-technologies/aos";
    license = "MIT";
  };
}
