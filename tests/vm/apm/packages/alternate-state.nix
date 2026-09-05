# Packages VM checks for alternate state workflows.
{
  testing,
  pkgs,
  fixtures,
  sourcefulV1,
  sourceVerifyAltDeps,
  gcAltDeps,
  setupAltNixEnv,
  setupEmptyAltNixGcEnv,
}: {
  # -------------------------------------------------------------------------
  # 13. source-verify-alt-nix-state — Source and verify with re-rooted Nix state
  # -------------------------------------------------------------------------
  source-verify-alt-nix-state = testing.mkVMTest {
    name = "apm-source-verify-alt-nix-state";
    rootfsDeps = sourceVerifyAltDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupAltNixEnv}

      echo "==> Test: apm source and verify honor alternate Nix state DB"

      SOURCE_STORE="${sourcefulV1}"
      SOURCE_HASH=$(basename "$SOURCE_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/sourcealt"
      SOURCE_BIN="$PROFILE/current/bin/sourceful"

      assert_store_valid() {
        path="$1"
        label="$2"
        if alt_nix_store --check-validity "$path" > "/tmp/source-alt-valid-$label.out" 2>&1; then
          pass "$label valid in alternate Nix state"
        else
          cat "/tmp/source-alt-valid-$label.out"
          fail "$label should be valid in alternate Nix state"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if alt_nix_store --check-validity "$path" > "/tmp/source-alt-missing-$label.out" 2>&1; then
          cat "/tmp/source-alt-missing-$label.out"
          fail "$label should be missing from alternate Nix state"
        else
          pass "$label missing from alternate Nix state"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if alt_nix_store --delete --ignore-liveness "$path" > "/tmp/source-alt-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/source-alt-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18123/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/source-alt-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/source-alt-$label.out"
          fail "$label should exit 0"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$SOURCE_STORE" "sourceful"

      $APR create source-alt-reg
      REG_DIR="$REG_STORAGE/source-alt-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR publish "$SOURCE_STORE" \
        --name source-alt \
        --version 1.0.0 \
        --description "Alternate-state source verification fixture" \
        --license MIT \
        --maintainer source-alt@example.invalid \
        --source-drv "$SOURCE_STORE" \
        --registry source-alt-reg \
        --no-commit > /tmp/source-alt-publish.out 2>&1 || {
        cat /tmp/source-alt-publish.out
        fail "apr publish source-alt succeeds"
      }
      cat /tmp/source-alt-publish.out
      assert_file_contains /tmp/source-alt-publish.out "$SOURCE_STORE" \
        "apr publish reports explicit source metadata"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        "$SOURCE_HASH" "published metadata records source-alt store hash"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        "$SOURCE_STORE" "published metadata records source drv path"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        'source_nar_hash = "sha256:' "published metadata records source NAR hash"

      $APR cache generate \
        --registry source-alt-reg \
        --output /tmp/source-alt-cache \
        --cache-url http://127.0.0.1:18123 \
        --priority 25 \
        --no-commit > /tmp/source-alt-cache-generate.out 2>&1 || {
        cat /tmp/source-alt-cache-generate.out
        fail "apr cache generate source-alt succeeds"
      }
      cat /tmp/source-alt-cache-generate.out
      assert_file_exists "/tmp/source-alt-cache/$SOURCE_HASH.narinfo" \
        "static cache has source-alt narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: source-alt 1.0.0"
      git init --bare --object-format=sha256 /tmp/source-alt-origin.git
      git -C "$REG_DIR" remote add origin /tmp/source-alt-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18123 --bind 127.0.0.1 \
        --directory /tmp/source-alt-cache > /tmp/source-alt-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/source-alt-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      export HOME=/tmp/source-alt-consumer
      export USER=sourcealt
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/source-alt-origin.git \
        --name source-alt-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/source-alt-registry-add.out 2>&1 || {
        cat /tmp/source-alt-registry-add.out
        fail "apm registry add syncs source-alt registry"
      }
      cat /tmp/source-alt-registry-add.out

      delete_store_path "$SOURCE_STORE" "sourceful"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install source-alt --registry source-alt-reg --yes > /tmp/source-alt-install.out 2>&1 || {
        cat /tmp/source-alt-install.out
        fail "apm install downloads source-alt"
      }
      cat /tmp/source-alt-install.out
      assert_file_contains /tmp/source-alt-install.out "Downloading 1 NAR" \
        "source-alt install downloads the package NAR"
      assert_file_contains /tmp/source-alt-install.out "Installed 1 package" \
        "source-alt install creates profile generation"
      assert_store_valid "$SOURCE_STORE" "sourceful"
      "$SOURCE_BIN" > /tmp/source-alt-run.out
      assert_file_contains /tmp/source-alt-run.out "^sourceful 1.0.0$" \
        "installed source-alt executable runs from profile"

      run_ok source-fetch "$APM" source source-alt --fetch
      assert_file_contains /tmp/source-alt-source-fetch.out "Source realised: $SOURCE_STORE" \
        "apm source --fetch realises source path through alternate Nix state"

      run_ok source-verify "$APM" source source-alt --verify
      assert_file_contains /tmp/source-alt-source-verify.out "$SOURCE_STORE" \
        "apm source --verify uses installed source path"
      assert_file_contains /tmp/source-alt-source-verify.out "matches installed binary" \
        "apm source --verify compares rebuilt source with installed package"

      run_ok verify "$APM" verify source-alt
      assert_file_contains /tmp/source-alt-verify.out "integrity verified" \
        "apm verify validates installed NAR hash through alternate Nix state"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 14. gc-alt-nix-state — GC with re-rooted Nix state
  # -------------------------------------------------------------------------
  gc-alt-nix-state = testing.mkVMTest {
    name = "apm-gc-alt-nix-state";
    rootfsDeps = gcAltDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupEmptyAltNixGcEnv}

      echo "==> Test: apm gc honors alternate Nix state DB"

      $APM --json gc > /tmp/gc-alt.json 2>&1 || {
        cat /tmp/gc-alt.json
        fail "apm gc succeeds using AOS_NIX_STATE_DIR"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg store "$AOS_NIX_STORE_DIR" \
        --arg state "$AOS_NIX_STATE_DIR" \
        '.action == "gc"
          and .status == "completed"
          and .success == true
          and .nix_store_dir == $store
          and .nix_state_dir == $state
          and (.stdout | type == "string")
          and (.stderr | type == "string")' \
        /tmp/gc-alt.json >/dev/null || {
        cat /tmp/gc-alt.json
        fail "apm --json gc reports alternate Nix state"
      }

      check_fail
    '';
  };
}
