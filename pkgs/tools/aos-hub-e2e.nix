##! aos-hub-e2e — launcher that exercises the native hub against a real Nix client.
##!
##! The sibling `aos-hub-worker-e2e` boots the deployed *Worker* (wasm) under
##! workerd+miniflare and asserts the cache read surface. This is its **native**
##! counterpart: it runs the from-source `aos-hub` binary as a real HTTP server
##! and drives the unified cache read path with the actual `nix` client —
##! `nix copy --from http://<hub>/<cache>` — so the wire contract a substituter
##! depends on (generated `nix-cache-info`, `<hash>.narinfo`, ranged `nar/<file>`
##! reads, NarHash validation) is proven against the same `cache_serve` /
##! `fetch_stream` path the cargo router tests drive in-process.
##!
##! ```text
##! aos-hub init / org / binding / cache create                  (CLI-driven setup)
##! nix copy --to file://seed <path>                             (real Nix produces a cache)
##! aos-hub serve --listen 127.0.0.1:PORT                        (native server)
##! GET /<cache>/nix-cache-info                  -> 200 StoreDir  (generated)
##! GET /<cache>/<hash>.narinfo                  -> 200           (passthrough)
##! GET /<cache>/nar/<file>  Range: bytes=0-3    -> 206           (native streaming range)
##! nix copy --from http://127.0.0.1:PORT/<cache> <path>         (real Nix round-trips + verifies NarHash)
##! ```
##!
##! ## Why a launcher (not a pure check)
##!
##! Like `aos-hub-worker-e2e` and the fleet VM tests, this drives a real `nix`
##! daemon and binds a TCP port, neither of which the hermetic Nix build sandbox
##! provides. The derivation builds a launcher in-sandbox (every path it `exec`s
##! is a baked store path); the aos test harness / CI runs
##! `$out/bin/aos-hub-e2e` on a real host, outside the sandbox.
{
  mkDerivation,
  aos-hub,
  nix,
  curl,
  coreutils,
  bash,
}:
mkDerivation {
  pname = "aos-hub-e2e";
  version = "0.1.0";

  # The launcher `exec`s these store paths at runtime, so they must survive the
  # scrub phase (which nukes any store ref not reachable from a runtime dep).
  runtimeDeps = [aos-hub nix curl coreutils bash];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        cat > "$out/bin/aos-hub-e2e" <<'EOF'
        #!${bash}/bin/bash
        # Drive the native aos-hub server with a real Nix client. Must run OUTSIDE
        # the Nix sandbox: it needs a nix daemon and a bindable TCP port.
        set -euo pipefail
        export PATH="${coreutils}/bin:${curl}/bin:${nix}/bin:${aos-hub}/bin:$PATH"
        NIXFLAGS="--extra-experimental-features nix-command"
        PORT="18420"
        BASE="http://127.0.0.1:$PORT/e2e-cache"

        work="$(mktemp -d)"
        srv_pid=""
        cleanup() {
          [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
          rm -rf "$work"
        }
        trap cleanup EXIT

        ok=0
        fail=0
        pass() { echo "ok   $1"; ok=$((ok+1)); }
        die()  { echo "FAIL $1"; fail=$((fail+1)); }

        root="$work/hub"
        store="$work/storage"
        mkdir -p "$store"

        # 1. CLI-driven setup: migrate, create org + local_fs binding + public cache.
        aos-hub --root "$root" init >/dev/null
        aos-hub --root "$root" org add acme "Acme" >/dev/null
        aos-hub --root "$root" binding add acme primary --path "$store" >/dev/null
        aos-hub --root "$root" cache create e2e-cache --org acme --binding primary \
          --prefix pc --visibility public --compression none >/dev/null
        pass "CLI setup (init + org + binding + public cache)"

        # 2. Real Nix produces a valid binary cache for a fresh store path.
        printf 'andyl-os hub e2e payload\n' > "$work/payload"
        sp="$(nix-store --add "$work/payload")"
        nix $NIXFLAGS copy --to "file://$work/seed?compression=none" "$sp"
        # Lay the produced cache under the binding's prefix (pc/), the layout the
        # hub serves: pc/<hash>.narinfo + pc/nar/<file>.nar.
        mkdir -p "$store/pc"
        cp -r "$work/seed/." "$store/pc/"
        hash="$(basename "$sp" | cut -d- -f1)"
        narfile="$(ls "$store/pc/nar" | head -1)"
        pass "seeded cache surface from real nix copy ($hash.narinfo + nar/$narfile)"

        # 3. Start the native server and wait for readiness.
        aos-hub --root "$root" serve --listen "127.0.0.1:$PORT" > "$work/serve.log" 2>&1 &
        srv_pid=$!
        ready=0
        for _ in $(seq 1 50); do
          if curl -fsS "$BASE/nix-cache-info" >/dev/null 2>&1; then ready=1; break; fi
          sleep 0.2
        done
        [ "$ready" = 1 ] && pass "aos-hub serve is reachable" || die "server never became ready"

        # 4. nix-cache-info is hub-generated.
        if curl -fsS "$BASE/nix-cache-info" | grep -q "StoreDir: /nix/store"; then
          pass "GET nix-cache-info -> StoreDir"
        else die "nix-cache-info missing StoreDir"; fi

        # 5. narinfo is served (passthrough from the local_fs surface).
        if curl -fsS "$BASE/$hash.narinfo" | grep -q "StorePath: $sp"; then
          pass "GET <hash>.narinfo -> StorePath"
        else die "narinfo missing/incorrect StorePath"; fi

        # 6. Ranged NAR read -> 206 (the native streaming range path).
        hdrs="$(curl -fsS -D - -o /dev/null -r 0-3 "$BASE/nar/$narfile")"
        if printf '%s' "$hdrs" | grep -qi "206 Partial Content" \
           && printf '%s' "$hdrs" | grep -qi "Content-Range: bytes 0-3/"; then
          pass "GET nar/<file> Range bytes=0-3 -> 206 + Content-Range"
        else die "ranged NAR read did not yield 206 + Content-Range"; fi

        # 7. THE round-trip: a real nix client copies the path back out of the hub,
        #    validating the narinfo signature policy (--no-check-sigs) and, crucially,
        #    re-hashing the streamed NAR against the narinfo NarHash. A serve-path
        #    corruption (wrong bytes, bad range framing) fails this.
        if nix $NIXFLAGS copy --no-check-sigs \
             --from "$BASE" --to "file://$work/dest?compression=none" "$sp" \
           && [ -f "$work/dest/$hash.narinfo" ]; then
          pass "nix copy --from http hub -> NAR re-hashed + path materialized"
        else die "nix copy --from the hub failed (serve-path or NarHash mismatch)"; fi

        echo "aos-hub-e2e: $ok ok, $fail fail"
        [ "$fail" = 0 ] || { echo "--- serve.log ---"; tail -20 "$work/serve.log" || true; exit 1; }
        echo "aos-hub e2e: PASS"
        EOF
        chmod +x "$out/bin/aos-hub-e2e"
      '';
    }
  ];

  meta = {
    description = "Launcher: run the native aos-hub server and assert a real nix copy round-trip through the unified cache read path";
    homepage = "https://github.com/andyl/andyl-os";
    license = "MIT";
  };
}
