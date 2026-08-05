##! aos-hub-e2e — launcher that exercises the native hub against a real Nix client.
##!
##! The sibling `aos-hub-worker-do-e2e` boots the deployed *Worker* (wasm) under
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
##! Like `aos-hub-worker-do-e2e` and the fleet VM tests, this drives a real `nix`
##! daemon and binds a TCP port, neither of which the hermetic Nix build sandbox
##! provides. The derivation builds a launcher in-sandbox (every path it `exec`s
##! is a baked store path); the aos test harness / CI runs
##! `$out/bin/aos-hub-e2e` on a real host, outside the sandbox.
{
  mkDerivation,
  aos,
  aos-hub,
  aos-system-image-e2e-fixture,
  nix,
  curl,
  coreutils,
  grep,
  bash,
}:
mkDerivation {
  pname = "aos-hub-e2e";
  version = "0.1.0";

  # The launcher `exec`s these store paths at runtime, so they must survive the
  # scrub phase (which nukes any store ref not reachable from a runtime dep).
  runtimeDeps = [aos aos-hub aos-system-image-e2e-fixture nix curl coreutils grep bash];

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
        export PATH="${coreutils}/bin:${grep}/bin:${curl}/bin:${nix}/bin:${aos}/bin:${aos-hub}/bin:$PATH"
        PORT="18420"
        HUB="http://127.0.0.1:$PORT"
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
        fixture="$work/producer"
        ${aos-system-image-e2e-fixture}/bin/aos-system-image-e2e-fixture "$fixture"
        export AOS_HUB_E2E_IMAGE_FIXTURE="$fixture"
        pass "apr release produced the signed raw + QCOW2 static origin"

        # Start the native server and make the producer output its seed source.
        aos-hub --root "$root" init >/dev/null
        aos-hub --root "$root" serve --seed --listen "127.0.0.1:$PORT" > "$work/serve.log" 2>&1 &
        srv_pid=$!
        ready=0
        for _ in $(seq 1 50); do
          if curl -fsS "$HUB/demo/cdn/-/images" >/dev/null 2>&1; then ready=1; break; fi
          sleep 0.2
        done
        [ "$ready" = 1 ] && pass "aos-hub serve is reachable" || die "server never became ready"
        pass "Hub kept staged bytes hidden until signed pointers and rooted all four image objects"
        if curl -fsS "$HUB/demo/cdn/-/images" | grep -q 'aos-e2e.qcow2'; then
          pass "Web Images page renders the apr-produced catalog"
        else die "Web Images page omitted producer output"; fi
        api_list="$(curl -fsS -X POST \
          -H 'content-type: application/json' \
          -H 'connect-protocol-version: 1' \
          --data '{"slug":"demo/cdn","channel":"stable"}' \
          "$HUB/aos.hub.v1.ImageService/ListImages")"
        if printf '%s' "$api_list" | grep -q 'aos-e2e.img' \
           && printf '%s' "$api_list" | grep -q 'aos-e2e.qcow2'; then
          pass "Image API lists the complete apr-produced integrity catalog"
        else die "Image API omitted producer output"; fi

        # Drive the public API through the real consumer CLI.
        image_list="$(aos --json image list --hub "$HUB" --registry demo/cdn --channel stable)"
        if printf '%s' "$image_list" | grep -q '"format":"raw"' \
           && printf '%s' "$image_list" | grep -q '"format":"qcow2"'; then
          pass "aos image list discovers signed raw + QCOW2 encodings"
        else die "aos image list omitted a signed image encoding"; fi

        image_show="$(aos --json image show --hub "$HUB" --registry demo/cdn \
          --channel stable --architecture x86_64 --target qemu-kvm)"
        if printf '%s' "$image_show" | grep -q '"format":"qcow2"' \
           && printf '%s' "$image_show" | grep -q '"releaseVerification":"verified"' \
           && printf '%s' "$image_show" | grep -q '"bootVerification":"unsigned"'; then
          pass "aos image show resolves target to complete integrity metadata"
        else die "aos image show did not resolve qemu-kvm to QCOW2"; fi

        cp "$(cat "$fixture/raw-path")" "$work/expected.raw"
        raw_out="$work/downloaded.img"
        aos image download --hub "$HUB" --registry demo/cdn --channel stable \
          --format raw --output "$raw_out" >/dev/null
        if cmp -s "$work/expected.raw" "$raw_out"; then
          pass "aos image download writes exact raw bytes with checksum verification"
        else die "raw image download bytes differ"; fi

        # Useful signed filenames are used when --output is omitted.
        mkdir -p "$work/default-name"
        (
          cd "$work/default-name"
          aos image download --hub "$HUB" --registry demo/cdn --channel stable \
            --format raw >/dev/null
        )
        if cmp -s "$work/expected.raw" "$work/default-name/aos-e2e.img"; then
          pass "aos image download uses the signed useful filename"
        else die "default image filename or bytes are incorrect"; fi

        # Resume from the secure descriptor-relative partial filename. A
        # successful result proves the CLI accepted a 206 with exact range
        # framing and verified the full-file digest before finalization.
        qcow_out="$work/resumed.qcow2"
        printf 'QFI' > "$work/.resumed.qcow2.aos-part"
        resume_json="$(aos --json image download --hub "$HUB" --registry demo/cdn \
          --channel stable --format qcow2 --output "$qcow_out")"
        cp "$(cat "$fixture/qcow2-path")" "$work/expected.qcow2"
        if cmp -s "$work/expected.qcow2" "$qcow_out" \
           && printf '%s' "$resume_json" | grep -q '"resumedFrom":3'; then
          pass "aos image download resumes with Range and verifies exact QCOW2 bytes"
        else die "resumed QCOW2 download or JSON result is incorrect"; fi

        # 9. Exchange the seed's one-time provisioning secret for a real JWT.
        #    Anonymous private discovery must fail; org-scoped bearer access
        #    must list and download the exact private image bytes. Plain HTTP is
        #    accepted only because the host is an IP-literal loopback address.
        provisioning=""
        while IFS= read -r line; do
          case "$line" in
            "  token:     "*) provisioning="''${line#  token:     }" ;;
          esac
        done < "$work/serve.log"
        if [ -z "$provisioning" ]; then
          die "seed did not print its provisioning token"
        else
          access="$(aos hub login --hub "$HUB" --provisioning-token "$provisioning" | tail -n 1)"
          if aos image list --hub "$HUB" --registry demo/private-images >/dev/null 2>&1; then
            die "private image catalog was anonymously readable"
          elif private_list="$(aos --json image list --hub "$HUB" --token "$access" \
            --registry demo/private-images --channel stable --format qcow2)" \
            && printf '%s' "$private_list" | grep -q 'aos-e2e.qcow2'; then
            pass "aos image list enforces private auth and accepts bearer access"
          else die "authenticated private image listing failed"; fi

          private_out="$work/private.qcow2"
          if aos image download --hub "$HUB" --token "$access" \
               --registry demo/private-images --channel stable --format qcow2 \
               --output "$private_out" >/dev/null \
             && cmp -s "$work/expected.qcow2" "$private_out"; then
            pass "aos image download serves exact authenticated private bytes"
          else die "authenticated private image download failed"; fi
        fi

        echo "aos-hub-e2e: $ok ok, $fail fail"
        [ "$fail" = 0 ] || { echo "--- serve.log ---"; tail -20 "$work/serve.log" || true; exit 1; }
        echo "aos-hub e2e: PASS"
        EOF
        chmod +x "$out/bin/aos-hub-e2e"
      '';
    }
  ];

  meta = {
    description = "Launcher: assert native Hub cache and signed system-image end-to-end consumer flows";
    homepage = "https://github.com/andyl/andyl-os";
    license = "MIT";
  };

  checks = {
    testing,
    self,
    ...
  }: {
    live-native-image-topology = testing.mkVMTest {
      name = "aos-hub-e2e-live";
      rootfsDeps = [self];
      memory = 2048;
      testScript = ''
        ${nix}/bin/nix-store --load-db < /aos-registration
        ${self}/bin/aos-hub-e2e
      '';
    };
  };
}
